"""Case data-lake CLI: ``memdiver case {init,status,schema,query,context-at,export}``.

Thin adapters over the ``case.*`` producers in :mod:`memdiver.app.tools_case`
(the same functions behind the REST routes and the MCP tools). Output is the
producer payload as JSON (stdout, or ``-o FILE``); a :class:`CapabilityError`
propagates to the CLI backstop, which prints one line and exits with the
category's code.
"""

import argparse
import json
import sys
from typing import Any, Callable, Dict, Optional

from ._shared import _write_output


def _auto_int(text: str) -> int:
    return int(text, 0)


def _param_arg(text: str) -> Any:
    """``--param`` value: an integer when it parses as one, else the string."""
    try:
        return int(text, 0)
    except ValueError:
        return text


def _location_arg(text: str) -> Dict[str, Any]:
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise argparse.ArgumentTypeError("location must be a JSON object")
    return value


def _common_parser(with_case: bool = True) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    if with_case:
        p.add_argument("--case", required=True, help="Case directory (required)")
    p.add_argument("-o", "--output", help="Write the JSON payload to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def add_case_parser(sub) -> None:
    """Register the ``case <action>`` group on the top-level subparsers."""
    group = sub.add_parser(
        "case", help="Case data lake: tables, read-only SQL, locate_context")
    actions = group.add_subparsers(dest="case_action")
    init = actions.add_parser(
        "init", parents=[_common_parser(with_case=False)],
        help="Create (or re-open) a case")
    init.add_argument("case", metavar="CASE",
                      help="Directory, or a bare name for ~/.memdiver/cases/<name>")
    actions.add_parser("status", parents=[_common_parser()],
                       help="Manifest, tables (runs, rows) and annotation captures")
    man = actions.add_parser("manifest", parents=[_common_parser()],
                             help="Inventory: views, images, captures, annotations, ISF, plugins")
    man.add_argument("--json", action="store_true", dest="as_json",
                     help="Emit the JSON payload instead of the human table")
    actions.add_parser("schema", parents=[_common_parser()],
                       help="Columns, location mappings and row counts per table")
    q = actions.add_parser("query", parents=[_common_parser()],
                           help="Run one read-only SELECT over the case tables")
    q.add_argument("--sql", default="-",
                   help="SQL text, or '-' (default) to read it from stdin")
    q.add_argument("--param", action="append", type=_param_arg, dest="params",
                   help="Positional ? binding (repeatable; integers parsed as int)")
    q.add_argument("--limit", type=int, default=1000, help="Row cap (default: 1000)")
    ctx = actions.add_parser(
        "context-at", parents=[_common_parser()],
        help="What contains an address: table rows and annotations, outermost first")
    ctx.add_argument("--location", required=True, type=_location_arg,
                     help='Location as JSON, e.g. \'{"space":"physical","value":4096,'
                          '"capture_id":"<id>"}\'')
    ctx.add_argument("--length", type=_auto_int, default=1,
                     help="Span length in bytes for coverage (default: 1)")
    ctx.add_argument("--dump", dest="dump_path",
                     help="Dump to open, for read coverage of the span")
    ctx.add_argument("--table", action="append", dest="tables",
                     help="Restrict to this table (repeatable)")
    _add_export_parser(actions)


def _add_export_parser(actions) -> None:
    exp = actions.add_parser(
        "export", parents=[_common_parser()],
        help="Export a dump's regions / page states / heap chunks into case tables")
    exp.add_argument("dump_path", metavar="DUMP", help=".mdview image view or .msl")
    exp.add_argument("--what", action="append", dest="what",
                     choices=["auto", "view_regions", "msl_regions", "page_states",
                              "heap_chunks"],
                     help="What to export (repeatable; default: auto)")
    exp.add_argument("--run-id", dest="run_id", help="Run id to file the tables under")


def _emit(args: argparse.Namespace, payload: dict) -> int:
    _write_output(payload, args.output)
    return 0


def _cmd_case_init(args: argparse.Namespace) -> int:
    from memdiver.app.tools_case import case_init_result
    return _emit(args, case_init_result(args.case).payload)


def _cmd_case_status(args: argparse.Namespace) -> int:
    from memdiver.app.tools_case import case_status_result
    return _emit(args, case_status_result(args.case).payload)


def _manifest_lines(m: dict) -> list:
    n, isf = m["record_counts"], m["isf"]
    lines = [f"case {m['name']}  ({m['case_dir']})  created {m['created']}  v{m['version']}",
             f"  views {n['views']}  images {n['images']}  captures {n['captures']}  "
             f"annotation-captures {n['annotation_captures']}  isf-drafts {n['isf_drafts']}  "
             f"isf-exports {n['isf_exports']}  plugins {n['plugins']}  tables {n['tables']}"]
    lines += [f"  view    {v['path']}  {v['kind']}  pid={v['pid']}  -> {v['image']}"
              for v in m["views"]]
    lines += [f"  image   {i['path']}  {'exists' if i['exists'] else 'MISSING'}  "
              f"size={i['size']}" for i in m["images"]]
    lines += [f"  capture {c['path']}  size={c['size']}" for c in m["captures"]]
    lines += [f"  annot   {a['capture']}  entries={a['entries']}" for a in m["annotations"]]
    lines += [f"  draft   {d['name']}  capture={d['capture']}  ops={d['ops']}"
              for d in isf["drafts"]]
    lines += [f"  isf     {e['path']}  size={e['size']}" for e in isf["exports"]]
    lines += [f"  plugin  {p['path']}  size={p['size']}" for p in m["plugins"]]
    lines += [f"  table   {t['name']}  runs={t['runs']}  rows={t['rows']}" for t in m["tables"]]
    lines += [f"  truncated: {k}" for k in m["truncated"]]
    lines += [f"  warning: {w}" for w in m["warnings"]]
    return lines


def _cmd_case_manifest(args: argparse.Namespace) -> int:
    from memdiver.app.tools_case import case_manifest_result
    payload = case_manifest_result(args.case).payload
    if args.as_json or args.output:
        return _emit(args, payload)
    print("\n".join(_manifest_lines(payload)))
    return 0


def _cmd_case_schema(args: argparse.Namespace) -> int:
    from memdiver.app.tools_case import case_schema_result
    return _emit(args, case_schema_result(args.case).payload)


def _cmd_case_query(args: argparse.Namespace) -> int:
    from memdiver.app.tools_case import case_query_result
    sql = sys.stdin.read() if args.sql == "-" else args.sql
    return _emit(args, case_query_result(
        args.case, sql, args.limit, args.params).payload)


def _cmd_case_context_at(args: argparse.Namespace) -> int:
    from memdiver.app.tools_case import context_at_result
    return _emit(args, context_at_result(
        args.case, args.location, args.length, args.dump_path, args.tables).payload)


def _cmd_case_export(args: argparse.Namespace) -> int:
    from memdiver.app.tools_case import case_export_result
    return _emit(args, case_export_result(
        args.case, args.dump_path, tuple(args.what or ("auto",)), args.run_id).payload)


_CASE_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "init": _cmd_case_init, "status": _cmd_case_status, "manifest": _cmd_case_manifest,
    "schema": _cmd_case_schema,
    "query": _cmd_case_query, "context-at": _cmd_case_context_at,
    "export": _cmd_case_export,
}


def _cmd_case(args: argparse.Namespace) -> int:
    """Dispatch a ``case <action>`` subcommand to its handler."""
    handler: Optional[Callable] = _CASE_HANDLERS.get(
        getattr(args, "case_action", None) or "")
    if handler is None:
        print("memdiver case: pick an action: " + ", ".join(_CASE_HANDLERS),
              file=sys.stderr)
        return 1
    return handler(args)
