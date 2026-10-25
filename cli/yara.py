"""YARA editor CLI: ``memdiver yara {check,scan}``.

Thin adapters over the ``yara.*`` producers in :mod:`memdiver.app.tools_yara` (the same
functions behind ``/api/yara`` and the MCP ``yara_*`` tools). ``check`` exits 1 when the
rule does not compile; ``scan`` covers the captured bytes of ONE dump (``scan-yara`` is
the N-dump census). ``check`` / ``scan`` take a rule FILE or ``--rule-name`` (a stored rule;
for ``scan`` the dump is then the only positional). ``rules list|get|put|delete`` manage the
stored library / case rules. Output is the producer payload as JSON (stdout, or ``-o FILE``).
"""

import argparse
import sys
from pathlib import Path
from typing import Callable, Dict, Optional

from ._shared import _write_output


def _common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-o", "--output", help="Write the JSON payload to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("rule", nargs="?", help="YARA rule FILE (.yar); omit with --rule-name")
    p.add_argument("--rule-name", help="Use a STORED rule (library, or case with --case)")
    p.add_argument("--case", dest="case_dir", help="Case directory/name for --rule-name lookup")
    return p


def _add_rules_parser(actions) -> None:
    rules = actions.add_parser("rules", help="Stored rules: list, get, put, delete")
    verbs = rules.add_subparsers(dest="rules_action")
    scope = argparse.ArgumentParser(add_help=False)
    scope.add_argument("-o", "--output", help="Write the JSON payload to this file")
    scope.add_argument("--case", dest="case_dir", help="Case directory/name (scope case)")
    scope.add_argument("--scope", choices=("library", "case", "auto"), default=None,
                       help="Scope: put/delete default to case with --case, else library; "
                            "get defaults to auto (case first, then library)")
    verbs.add_parser("list", parents=[scope], help="List library rules (+ the case's with --case)")
    verbs.add_parser("get", parents=[scope], help="Print a stored rule").add_argument("name")
    put = verbs.add_parser("put", parents=[scope], help="Store a rule from FILE or stdin (-)")
    put.add_argument("name")
    put.add_argument("file", nargs="?", default="-", help="Rule file (default: stdin)")
    verbs.add_parser("delete", parents=[scope],
                     help="Remove a rule (its source is kept in history)").add_argument("name")


def add_yara_parser(sub) -> None:
    """Register the ``yara <action>`` group on the top-level subparsers."""
    from memdiver.app.tools_yara import DEFAULT_LIMIT, DEFAULT_TIMEOUT_S

    group = sub.add_parser(
        "yara", help="YARA rule editor backend: compile-check a rule, scan one dump")
    actions = group.add_subparsers(dest="yara_action")
    actions.add_parser("check", parents=[_common_parser()],
                       help="Compile a rule; print its names or the failing line (exit 1)")
    _add_rules_parser(actions)
    scan = actions.add_parser(
        "scan", parents=[_common_parser()],
        help="Scan the captured bytes of one dump (.msl / .mdview / raw) with a rule")
    scan.add_argument("dump", nargs="?", help="Dump file")
    scan.add_argument("--view", choices=("va", "vas", "raw"),
                      help="Coordinates (default: va for .msl/.mdview, raw for a flat file)")
    scan.add_argument("--offset", type=lambda x: int(x, 0),
                      help="Window start, in --view coordinates (decimal or 0x hex)")
    scan.add_argument("--length", type=lambda x: int(x, 0), help="Window length in bytes")
    scan.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                      help=f"Row cap; a cut sets truncated (default: {DEFAULT_LIMIT})")
    scan.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S, dest="timeout_s",
                      help=f"libyara seconds per window (default: {DEFAULT_TIMEOUT_S})")


def _rule_arguments(args: argparse.Namespace) -> "tuple[Optional[str], Optional[str]]":
    """``(rule_source, rule_name)``: the file's text, or the stored name (never both)."""
    if args.rule_name and args.rule:
        print("memdiver yara: give a rule FILE or --rule-name, not both", file=sys.stderr)
        raise SystemExit(1)
    if args.rule_name:
        return None, args.rule_name
    if not args.rule:
        print("memdiver yara: give a rule FILE or --rule-name", file=sys.stderr)
        raise SystemExit(2)
    return Path(args.rule).read_text(encoding="utf-8"), None


def _cmd_yara_check(args: argparse.Namespace) -> int:
    from memdiver.app.tools_yara import yara_check_result
    source, name = _rule_arguments(args)
    payload = yara_check_result(source, name, args.case_dir).payload
    _write_output(payload, args.output)
    return 0 if payload["valid"] else 1


def _cmd_yara_scan(args: argparse.Namespace) -> int:
    from memdiver.app.tools_yara import yara_scan_dump_result
    if args.rule_name and args.dump is None:    # `scan --rule-name N DUMP`: DUMP landed in `rule`
        args.dump, args.rule = args.rule, None
    if not args.dump:
        print("memdiver yara scan: a dump file is required", file=sys.stderr)
        return 2
    source, name = _rule_arguments(args)
    result = yara_scan_dump_result(
        args.dump, source, args.view, args.offset, args.length, args.limit, args.timeout_s,
        name, args.case_dir)
    _write_output(result.payload, args.output)
    return 0


def _cmd_yara_rules(args: argparse.Namespace) -> int:
    from memdiver.app import tools_yara_rules as rules
    action = getattr(args, "rules_action", None)
    case = args.case_dir if action else None
    if action == "list":
        result = rules.yara_rule_list_result(case)
    elif action == "get":
        result = rules.yara_rule_get_result(args.name, case, args.scope)
    elif action == "put":
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8")
        result = rules.yara_rule_put_result(args.name, text, args.scope, case)
    elif action == "delete":
        result = rules.yara_rule_delete_result(args.name, args.scope, case)
    else:
        print("memdiver yara rules: pick an action: list, get, put, delete", file=sys.stderr)
        return 1
    _write_output(result.payload, args.output)
    return 0


_YARA_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "check": _cmd_yara_check, "scan": _cmd_yara_scan, "rules": _cmd_yara_rules,
}


def _cmd_yara(args: argparse.Namespace) -> int:
    """Dispatch a ``yara <action>`` subcommand to its handler."""
    handler: Optional[Callable] = _YARA_HANDLERS.get(getattr(args, "yara_action", None) or "")
    if handler is None:
        print("memdiver yara: pick an action: " + ", ".join(_YARA_HANDLERS), file=sys.stderr)
        return 1
    return handler(args)
