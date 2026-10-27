"""Detector-fixture CLI: ``memdiver fixtures {run,add,list,remove}``.

Thin adapters over the ``detector_fixtures.*`` producers in
:mod:`memdiver.app.tools_detector_fixtures` (the same functions behind
``/api/detector-fixtures`` and the MCP ``detector_fixtures_*`` tools). ``run`` exits
non-zero unless the verdict is ``pass`` (``1`` fail, ``2`` indeterminate), so a rule
or finder can gate a script. Output is the producer payload as JSON.
"""

import argparse
import sys
from pathlib import Path
from typing import Callable, Dict, Optional

from ._shared import _write_output, output_parent_parser
from .vol3 import _json_object

# B105: "pass" is a fixture verdict name, not a credential.
_VERDICT_EXIT = {"pass": 0, "fail": 1, "indeterminate": 2}  # nosec B105


def _kind_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--kind", choices=("yara", "keyfinder"), required=True, dest="artifact_kind")


def add_fixtures_parser(sub) -> None:
    """Register the ``fixtures <action>`` group on the top-level subparsers."""
    group = sub.add_parser(
        "fixtures", help="Detector fixtures: positive controls and decoys for YARA rules "
                         "and key finders")
    actions = group.add_subparsers(dest="fixtures_action")
    run = actions.add_parser("run", parents=[output_parent_parser()],
                             help="Run a detector's fixtures (exit 0 pass, 1 fail, 2 indeterminate)")
    _kind_args(run)
    run.add_argument("artifact", help="Key-finder name, or with --kind yara the rule FILE")
    run.add_argument("--case", dest="case_dir", help="Also run (and file verdicts for) stored fixtures")
    run.add_argument("--params", type=_json_object, help="JSON finder params overriding each fixture's")
    add = actions.add_parser("add", parents=[output_parent_parser()], help="Store a fixture in a case")
    add.add_argument("name")
    _kind_args(add)
    add.add_argument("--case", required=True, dest="case_dir")
    add.add_argument("--artifact", required=True, help="Key-finder name, or the YARA rule NAME")
    sample = add.add_mutually_exclusive_group(required=True)
    sample.add_argument("--sample-hex", dest="sample_hex")
    sample.add_argument("--sample-base64", dest="sample_base64")
    sample.add_argument("--sample-dump", dest="sample_dump", metavar="DUMP",
                        help="A capture range: also give --offset and --length")
    add.add_argument("--offset", type=int)
    add.add_argument("--length", type=int)
    add.add_argument("--view", choices=("va", "vas", "raw"))
    add.add_argument("--expect", type=_json_object, required=True,
                     help='{"matches": [{"offset": N, ...}]} or {"no_match": true}')
    add.add_argument("--params", type=_json_object)
    lst = actions.add_parser("list", parents=[output_parent_parser()],
                             help="Bundled and stored fixtures with their last verdict")
    lst.add_argument("--case", dest="case_dir")
    lst.add_argument("--kind", choices=("yara", "keyfinder"), dest="artifact_kind")
    lst.add_argument("--artifact", help="Narrow to one finder / rule name")
    rem = actions.add_parser("remove", parents=[output_parent_parser()],
                             help="Retire a stored fixture (archived under history/)")
    rem.add_argument("name")
    rem.add_argument("--case", required=True, dest="case_dir")


def _sample_of(args: argparse.Namespace) -> dict:
    if args.sample_hex is not None:
        return {"hex": args.sample_hex}
    if args.sample_base64 is not None:
        return {"base64": args.sample_base64}
    sample = {"dump_path": args.sample_dump, "offset": args.offset, "length": args.length}
    return {**sample, **({"view": args.view} if args.view else {})}


def _cmd_fixtures_run(args: argparse.Namespace) -> int:
    from memdiver.app.tools_detector_fixtures import detector_fixtures_run_result
    artifact = (Path(args.artifact).expanduser().read_text(encoding="utf-8")
                if args.artifact_kind == "yara" else args.artifact)
    payload = detector_fixtures_run_result(
        args.artifact_kind, artifact, None, args.params, args.case_dir).payload
    _write_output(payload, args.output)
    return _VERDICT_EXIT.get(payload["verdict"], 2)


def _cmd_fixtures_add(args: argparse.Namespace) -> int:
    from memdiver.app.tools_detector_fixtures import detector_fixtures_add_result
    _write_output(detector_fixtures_add_result(
        args.case_dir, args.name, args.artifact_kind, args.artifact, _sample_of(args),
        args.expect, args.params).payload, args.output)
    return 0


def _cmd_fixtures_list(args: argparse.Namespace) -> int:
    from memdiver.app.tools_detector_fixtures import detector_fixtures_list_result
    _write_output(detector_fixtures_list_result(
        args.case_dir, args.artifact_kind, args.artifact).payload, args.output)
    return 0


def _cmd_fixtures_remove(args: argparse.Namespace) -> int:
    from memdiver.app.tools_detector_fixtures import detector_fixtures_remove_result
    _write_output(detector_fixtures_remove_result(args.case_dir, args.name).payload, args.output)
    return 0


_FIXTURES_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "run": _cmd_fixtures_run, "add": _cmd_fixtures_add,
    "list": _cmd_fixtures_list, "remove": _cmd_fixtures_remove,
}


def _cmd_fixtures(args: argparse.Namespace) -> int:
    """Dispatch a ``fixtures <action>`` subcommand to its handler."""
    handler: Optional[Callable] = _FIXTURES_HANDLERS.get(getattr(args, "fixtures_action", None) or "")
    if handler is None:
        print("memdiver fixtures: pick an action: " + ", ".join(_FIXTURES_HANDLERS), file=sys.stderr)
        return 1
    return handler(args)
