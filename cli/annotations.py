"""Analysis-record CLI: ``memdiver annotations {list,add,supersede,retract}``.

Thin adapters over the ``annotations.*`` producers in
:mod:`memdiver.app.tools_annotations` (the same functions behind the REST
routes and the MCP tools). ``--case`` is REQUIRED until the Case abstraction
with a default directory lands (plan T1.8). Output is the producer payload as
JSON (stdout, or ``-o FILE``); a :class:`CapabilityError` propagates to the CLI
backstop, which prints one line and exits with the category's code.
"""

import argparse
import json
import sys
from typing import Any, Callable, Dict, List, Optional

from ._shared import _write_output


def _json_arg(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not valid JSON: {exc}") from exc


def _support_arg(text: str) -> Dict[str, str]:
    kind, sep, ref = text.partition(":")
    if not sep or not kind or not ref:
        raise argparse.ArgumentTypeError("support must be KIND:REF")
    return {"kind": kind, "ref": ref}


def _auto_int(text: str) -> int:
    return int(text, 0)


def _case_parent_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--case", required=True, help="Case directory (required)")
    p.add_argument("--capture", required=True,
                   help="Capture id (image sha256 or .msl integrity hash)")
    p.add_argument("-o", "--output", help="Write the JSON payload to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _add_content_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--location", action="append", type=_json_arg, dest="locations",
                   help='Location as JSON, e.g. \'{"space":"physical","value":4096}\' '
                        "(repeatable)")
    p.add_argument("--length", type=_auto_int, help="Length in bytes of the span")
    p.add_argument("--label", help="Short human-readable label")
    p.add_argument("--payload", type=_json_arg, help="JSON object payload")
    p.add_argument("--support", action="append", type=_support_arg,
                   help="Evidence as KIND:REF (repeatable)")


def add_annotations_parser(sub) -> None:
    """Register the ``annotations <action>`` group on the top-level subparsers."""
    parents = [_case_parent_parser()]
    group = sub.add_parser(
        "annotations", help="Versioned analysis record (list, add, supersede, retract)")
    actions = group.add_subparsers(dest="annotations_action")
    ls = actions.add_parser("list", parents=parents, help="List current entries")
    ls.add_argument("--kind", help="Only entries of this kind")
    ls.add_argument("--include-superseded", action="store_true",
                    help="Also list superseded entries and retractions")
    add = actions.add_parser("add", parents=parents, help="Append a new entry")
    add.add_argument("--kind", default="annotation", help="Entry kind (default: annotation)")
    add.add_argument("--author", default="human",
                     help="human, agent or tool:<name> (default: human)")
    _add_content_arguments(add)
    sup = actions.add_parser("supersede", parents=parents,
                             help="Replace an entry; unspecified fields are inherited")
    sup.add_argument("--entry", required=True, help="Id of the entry to replace")
    sup.add_argument("--kind", help="New kind")
    sup.add_argument("--author", default="human")
    _add_content_arguments(sup)
    ret = actions.add_parser("retract", parents=parents, help="Withdraw an entry")
    ret.add_argument("--entry", required=True, help="Id of the entry to withdraw")
    ret.add_argument("--author", default="human")
    ret.add_argument("--reason", default="", help="Why it is withdrawn")


def _emit(args: argparse.Namespace, payload: dict) -> int:
    _write_output(payload, args.output)
    return 0


def _cmd_annotations_list(args: argparse.Namespace) -> int:
    from memdiver.app.tools_annotations import annotations_list_result
    return _emit(args, annotations_list_result(
        args.case, args.capture, args.kind, args.include_superseded).payload)


def _cmd_annotations_add(args: argparse.Namespace) -> int:
    from memdiver.app.tools_annotations import annotations_add_result
    return _emit(args, annotations_add_result(
        args.case, args.capture, args.kind, args.author, args.locations,
        args.label or "", args.payload, args.support, args.length).payload)


def _cmd_annotations_supersede(args: argparse.Namespace) -> int:
    from memdiver.app.tools_annotations import annotations_supersede_result
    changes = {"kind": args.kind, "locations": args.locations, "length": args.length,
               "label": args.label, "payload": args.payload, "support": args.support}
    return _emit(args, annotations_supersede_result(
        args.case, args.capture, args.entry, args.author,
        **{k: v for k, v in changes.items() if v is not None}).payload)


def _cmd_annotations_retract(args: argparse.Namespace) -> int:
    from memdiver.app.tools_annotations import annotations_retract_result
    return _emit(args, annotations_retract_result(
        args.case, args.capture, args.entry, args.author, args.reason).payload)


_ANNOTATIONS_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "list": _cmd_annotations_list, "add": _cmd_annotations_add,
    "supersede": _cmd_annotations_supersede, "retract": _cmd_annotations_retract,
}


def _cmd_annotations(args: argparse.Namespace) -> int:
    """Dispatch an ``annotations <action>`` subcommand to its handler."""
    handler: Optional[Callable] = _ANNOTATIONS_HANDLERS.get(
        getattr(args, "annotations_action", None) or "")
    if handler is None:
        print("memdiver annotations: pick an action: " + ", ".join(_ANNOTATIONS_HANDLERS),
              file=sys.stderr)
        return 1
    return handler(args)
