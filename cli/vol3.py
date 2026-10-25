"""Volatility 3 CLI: ``memdiver vol3 {list,describe,run,query,annotate,scaffold,check,import,write-config,source,fixture}``.

Thin adapters over the ``vol3.*`` producers in :mod:`memdiver.app.tools_vol3` and
:mod:`memdiver.app.tools_vol3_dev` (the same functions behind the REST routes and
the MCP tools). Unlike REST, ``run`` always executes inline. A user plugin is given
as a FILE (``--source``) and runs UNSANDBOXED in this process; its SHA-256 is
logged. Output is the producer payload as JSON (stdout, or ``-o FILE``); a
:class:`CapabilityError` propagates to the CLI backstop.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ._shared import _write_output


def _json_or_string(text: str) -> Any:
    """A ``--arg``/``--param`` value: JSON when it parses (``[1,2]``, ``7``), else text."""
    try:
        return json.loads(text)
    except ValueError:
        return text


def _key_value(text: str) -> "tuple[str, Any]":
    key, sep, value = text.partition("=")
    if not sep or not key:
        raise argparse.ArgumentTypeError(f"expected key=value, got {text!r}")
    return key, _json_or_string(value)


def _json_object(text: str) -> Dict[str, Any]:
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise argparse.ArgumentTypeError("expected a JSON object")
    return value


def _common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-o", "--output", help="Write the JSON payload to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _add_source(p: argparse.ArgumentParser) -> None:
    p.add_argument("--source", metavar="FILE",
                   help="Plugin source file (runs UNSANDBOXED in this process; sha256 logged)")
    p.add_argument("--source-name", dest="source_name", metavar="NAME",
                   help="Plugin source stored in --case (see `vol3 source put`)")


def add_vol3_parser(sub) -> None:
    """Register the ``vol3 <action>`` group on the top-level subparsers."""
    group = sub.add_parser(
        "vol3", help="Volatility 3: run plugins over a .mdview into a case, query, scaffold")
    actions = group.add_subparsers(dest="vol3_action")
    _add_list_describe(actions)
    _add_run(actions)
    _add_query_annotate(actions)
    _add_dev(actions)
    _add_source_fixture(actions)


def _add_list_describe(actions) -> None:
    lst = actions.add_parser("list", parents=[_common_parser()],
                             help="Bundled plugins of an OS family")
    lst.add_argument("--os", dest="os_family", default="linux", help="OS family (default: linux)")
    desc = actions.add_parser("describe", parents=[_common_parser()],
                              help="A plugin's user requirements")
    desc.add_argument("--plugin", default="", help="Bundled plugin, e.g. linux.pslist")
    desc.add_argument("--case", dest="case_dir", help="Case holding --source-name")
    _add_source(desc)


def _add_run(actions) -> None:
    run = actions.add_parser("run", parents=[_common_parser()],
                             help="Run a plugin over a .mdview (inline); --case files the table")
    run.add_argument("--view", required=True, help=".mdview descriptor")
    run.add_argument("--plugin", default="", help="Bundled plugin, e.g. linux.pslist")
    _add_source(run)
    run.add_argument("--arg", action="append", type=_key_value, dest="plugin_args",
                     metavar="KEY=VALUE",
                     help="Plugin argument (repeatable; JSON values, e.g. pid=[1,2])")
    run.add_argument("--case", dest="case_dir", help="Case directory or bare name to register into")
    run.add_argument("--limit", type=int, default=100_000, help="Row cap while running")
    run.add_argument("--timeout", type=float, default=300.0, help="Seconds before stopping")
    run.add_argument("--max-rows", type=int, default=1000, help="Rows echoed in the output")
    run.add_argument("--column-map", type=_json_object, dest="column_map",
                     help='JSON {"Column": "space"|null} overriding address-column detection')
    run.add_argument("--out-dir", dest="out_dir", help="Directory for plugin file outputs")


def _add_query_annotate(actions) -> None:
    q = actions.add_parser("query", parents=[_common_parser()],
                           help="SQL or a saved query over a case (neither lists saved queries)")
    q.add_argument("--case", required=True, dest="case_dir", help="Case directory")
    q.add_argument("--sql", help="Read-only SELECT")
    q.add_argument("--saved", help="Built-in saved query name")
    q.add_argument("--param", action="append", type=_json_or_string, dest="params",
                   help="Positional ? binding (repeatable; JSON values)")
    q.add_argument("--limit", type=int, default=1000, help="Row cap (default: 1000)")
    ann = actions.add_parser("annotate", parents=[_common_parser()],
                             help="File plugin_row annotations for a registered run")
    ann.add_argument("--case", required=True, dest="case_dir")
    ann.add_argument("--table", required=True)
    ann.add_argument("--run-id", required=True, dest="run_id")
    ann.add_argument("--column", required=True, help="Location column to annotate")
    ann.add_argument("--rows", type=int, nargs="+", help="Row indexes (default: all)")
    ann.add_argument("--label-column", dest="label_column")
    ann.add_argument("--author", default="tool:vol3")


def _add_dev(actions) -> None:
    sc = actions.add_parser("scaffold", parents=[_common_parser()],
                            help="Source text of a new plugin")
    sc.add_argument("name")
    sc.add_argument("--os", dest="os_family", default="linux")
    sc.add_argument("--description", default="")
    sc.add_argument("--kernel-only", action="store_true", help="No per-process pid filter")
    chk = actions.add_parser("check", parents=[_common_parser()],
                             help="Load a plugin source file; optionally test it against a view")
    _add_source(chk)
    chk.add_argument("--case", dest="case_dir", help="Case holding --source-name")
    chk.add_argument("--view", help=".mdview to test the requirements against")
    imp = actions.add_parser("import", parents=[_common_parser()],
                             help="Register an external vol3 output file as a case table")
    imp.add_argument("file", metavar="FILE", help="Parquet / CSV / JSON output file")
    imp.add_argument("--case", required=True, dest="case_dir")
    imp.add_argument("--table", required=True, help="Table name, vol3__<os>_<plugin>")
    imp.add_argument("--capture-id", required=True, dest="capture_id")
    imp.add_argument("--image-sha256", dest="image_sha256")
    imp.add_argument("--locations", type=_json_object, help='JSON {"Column": "space"}')
    imp.add_argument("--format", default="auto")
    wc = actions.add_parser("write-config", parents=[_common_parser()],
                            help="Write a vol config.json reproducing a view's stack")
    wc.add_argument("--view", required=True)
    wc.add_argument("--out", required=True, dest="out_path")
    wc.add_argument("--plugin", default="linux.pslist.PsList")
    wc.add_argument("--case", dest="case_dir", help="Case holding --source-name")
    _add_source(wc)


def _add_source_fixture(actions) -> None:
    src = actions.add_parser("source", help="Stored plugin sources of a case: put|get|list")
    src_actions = src.add_subparsers(dest="source_action")
    put = src_actions.add_parser("put", parents=[_common_parser()],
                                 help="Store a plugin source file in the case and check it")
    put.add_argument("name")
    put.add_argument("--case", required=True, dest="case_dir")
    put.add_argument("--file", required=True, metavar="FILE", help="Plugin source file")
    put.add_argument("--view", help=".mdview to test the requirements against")
    get = src_actions.add_parser("get", parents=[_common_parser()], help="One stored source")
    get.add_argument("name")
    get.add_argument("--case", required=True, dest="case_dir")
    lst = src_actions.add_parser("list", parents=[_common_parser()], help="Stored sources")
    lst.add_argument("--case", required=True, dest="case_dir")
    fix = actions.add_parser("fixture", help="Plugin fixtures of a case: put|list|run")
    fix_actions = fix.add_subparsers(dest="fixture_action")
    fput = fix_actions.add_parser("put", parents=[_common_parser()],
                                  help="Store a fixture: plugin + view + row predicates")
    fput.add_argument("name")
    fput.add_argument("--case", required=True, dest="case_dir")
    fput.add_argument("--view", required=True, help=".mdview descriptor")
    fput.add_argument("--plugin", default="", help="Bundled plugin, e.g. linux.pslist")
    fput.add_argument("--source-name", dest="source_name", help="Stored plugin source")
    fput.add_argument("--arg", action="append", type=_key_value, dest="plugin_args",
                      metavar="KEY=VALUE", help="Plugin argument (repeatable; JSON values)")
    fput.add_argument("--expect", action="append", type=_json_object, required=True,
                      help='Predicate JSON, e.g. \'{"min_rows": 1}\' (repeatable)')
    flst = fix_actions.add_parser("list", parents=[_common_parser()], help="Stored fixtures")
    flst.add_argument("--case", required=True, dest="case_dir")
    frun = fix_actions.add_parser("run", parents=[_common_parser()],
                                  help="Run a fixture and file its verdict")
    frun.add_argument("name")
    frun.add_argument("--case", required=True, dest="case_dir")
    frun.add_argument("--view", help="Override the stored view")
    frun.add_argument("--limit", type=int, default=100_000)
    frun.add_argument("--timeout", type=float, default=300.0)
    frun.add_argument("--register-run", action="store_true", dest="register_run",
                      help="Also file the plugin table and link the verdict to it")


def _emit(args: argparse.Namespace, payload: dict) -> int:
    _write_output(payload, args.output)
    return 0


def _read_source(path: Optional[str]) -> Optional[str]:
    return Path(path).expanduser().read_text(encoding="utf-8") if path else None


def _cmd_vol3_list(args: argparse.Namespace) -> int:
    from memdiver.app.tools_vol3 import vol3_plugins_result
    return _emit(args, vol3_plugins_result(args.os_family).payload)


def _cmd_vol3_describe(args: argparse.Namespace) -> int:
    from memdiver.app.tools_vol3 import vol3_describe_result
    return _emit(args, vol3_describe_result(
        args.plugin, _read_source(args.source), source_name=args.source_name,
        case_dir=args.case_dir).payload)


def _cmd_vol3_run(args: argparse.Namespace) -> int:
    from memdiver.app.tools_vol3 import vol3_run_result
    return _emit(args, vol3_run_result(
        args.view, args.plugin, dict(args.plugin_args or []), case_dir=args.case_dir,
        limit=args.limit, timeout_s=args.timeout, max_rows=args.max_rows,
        column_map=args.column_map, source=_read_source(args.source),
        out_dir=args.out_dir, source_name=args.source_name).payload)


def _cmd_vol3_query(args: argparse.Namespace) -> int:
    from memdiver.app.tools_vol3 import vol3_query_result
    return _emit(args, vol3_query_result(
        args.case_dir, args.sql, args.saved, args.params, args.limit).payload)


def _cmd_vol3_annotate(args: argparse.Namespace) -> int:
    from memdiver.app.tools_vol3 import vol3_annotate_result
    return _emit(args, vol3_annotate_result(
        args.case_dir, args.table, args.run_id, args.column, rows=args.rows,
        label_column=args.label_column, author=args.author).payload)


def _cmd_vol3_scaffold(args: argparse.Namespace) -> int:
    from memdiver.app.tools_vol3_dev import vol3_scaffold_result
    return _emit(args, vol3_scaffold_result(
        args.name, os_family=args.os_family, description=args.description,
        per_process=not args.kernel_only).payload)


def _cmd_vol3_check(args: argparse.Namespace) -> int:
    from memdiver.app.tools_vol3_dev import vol3_check_result
    return _emit(args, vol3_check_result(
        _read_source(args.source), args.view, source_name=args.source_name,
        case_dir=args.case_dir).payload)


def _cmd_vol3_import(args: argparse.Namespace) -> int:
    from memdiver.app.tools_vol3_dev import vol3_import_parquet_result
    return _emit(args, vol3_import_parquet_result(
        args.case_dir, args.file, table=args.table, capture_id=args.capture_id,
        image_sha256=args.image_sha256, locations=args.locations,
        format=args.format).payload)


def _cmd_vol3_write_config(args: argparse.Namespace) -> int:
    from memdiver.app.tools_vol3_dev import vol3_write_config_result
    return _emit(args, vol3_write_config_result(
        args.view, args.out_path, args.plugin, source=_read_source(args.source),
        source_name=args.source_name, case_dir=args.case_dir).payload)


def _cmd_vol3_source(args: argparse.Namespace) -> int:
    from memdiver.app import tools_vol3_sources as sources
    action = getattr(args, "source_action", None)
    if action == "put":
        return _emit(args, sources.vol3_source_put_result(
            args.case_dir, args.name, _read_source(args.file) or "", args.view).payload)
    if action == "get":
        return _emit(args, sources.vol3_source_get_result(args.case_dir, args.name).payload)
    if action == "list":
        return _emit(args, sources.vol3_source_list_result(args.case_dir).payload)
    print("memdiver vol3 source: pick an action: put, get, list", file=sys.stderr)
    return 1


def _cmd_vol3_fixture(args: argparse.Namespace) -> int:
    from memdiver.app import tools_vol3_fixtures as fixtures
    action = getattr(args, "fixture_action", None)
    if action == "put":
        return _emit(args, fixtures.vol3_fixture_put_result(
            args.case_dir, args.name, view_path=args.view, expect=args.expect,
            plugin=args.plugin, source_name=args.source_name,
            args=dict(args.plugin_args or [])).payload)
    if action == "list":
        return _emit(args, fixtures.vol3_fixture_list_result(args.case_dir).payload)
    if action == "run":
        return _emit(args, fixtures.vol3_fixture_run_result(
            args.case_dir, args.name, view_path=args.view, limit=args.limit,
            timeout_s=args.timeout, register_run=args.register_run).payload)
    print("memdiver vol3 fixture: pick an action: put, list, run", file=sys.stderr)
    return 1


_VOL3_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "list": _cmd_vol3_list, "describe": _cmd_vol3_describe, "run": _cmd_vol3_run,
    "query": _cmd_vol3_query, "annotate": _cmd_vol3_annotate,
    "scaffold": _cmd_vol3_scaffold, "check": _cmd_vol3_check,
    "import": _cmd_vol3_import, "write-config": _cmd_vol3_write_config,
    "source": _cmd_vol3_source, "fixture": _cmd_vol3_fixture,
}


def _cmd_vol3(args: argparse.Namespace) -> int:
    """Dispatch a ``vol3 <action>`` subcommand to its handler."""
    handler: Optional[Callable] = _VOL3_HANDLERS.get(
        getattr(args, "vol3_action", None) or "")
    if handler is None:
        print("memdiver vol3: pick an action: " + ", ".join(_VOL3_HANDLERS),
              file=sys.stderr)
        return 1
    return handler(args)
