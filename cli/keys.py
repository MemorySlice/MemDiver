"""Key-finder CLI: ``memdiver keys {list,scan}``.

Thin adapters over the ``keyfinders.*`` producers in
:mod:`memdiver.app.tools_keyfinders` (the same functions behind ``/api/keyfinders``
and the MCP ``keyfinders_*`` tools). ``scan`` always executes inline. Output is the
producer payload as JSON (stdout, or ``-o FILE``); a :class:`CapabilityError`
propagates to the CLI backstop.
"""

import argparse
import sys
from typing import Callable, Dict, Optional

from ._shared import _write_output, output_parent_parser
from .vol3 import _json_object


def add_keys_parser(sub) -> None:
    """Register the ``keys <action>`` group on the top-level subparsers."""
    from memdiver.app.tools_keyfinders import DEFAULT_FINDERS, DEFAULT_LIMIT, HEAP_POLICIES

    group = sub.add_parser(
        "keys", help="Key finders: recognise key material by structure in a dump")
    actions = group.add_subparsers(dest="keys_action")
    actions.add_parser("list", parents=[output_parent_parser()],
                       help="The key finders and the params each reads")
    scan = actions.add_parser(
        "scan", parents=[output_parent_parser()],
        help="Scan the captured bytes of a dump (.msl / .mdview / raw) with key finders")
    scan.add_argument("dump", help="Dump file")
    scan.add_argument("--finder", action="append", dest="finders", metavar="NAME",
                      help=f"Finder to run (repeatable; default: {', '.join(DEFAULT_FINDERS)})")
    scan.add_argument("--view", choices=("va", "vas", "raw"),
                      help="Coordinates (default: va for .msl/.mdview, raw for a flat file)")
    scan.add_argument("--offset", type=lambda x: int(x, 0),
                      help="Window start, in --view coordinates (decimal or 0x hex)")
    scan.add_argument("--length", type=lambda x: int(x, 0), help="Window length in bytes")
    scan.add_argument("--heap-policy", dest="heap_policy", choices=HEAP_POLICIES,
                      default="annotate", help="off | annotate | mask (default: annotate)")
    scan.add_argument("--params", type=_json_object, help="JSON finder params, e.g. '{\"stride\": 4}'")
    scan.add_argument("--case", dest="case_dir",
                      help="Case directory: register the key_hits table + key_hit annotations")
    scan.add_argument("--no-annotate", action="store_true", dest="no_annotate",
                      help="With --case, register the table only (no analysis-record entries)")
    scan.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                      help=f"Row cap; a cut sets truncated (default: {DEFAULT_LIMIT})")
    scan.add_argument("--candidates-out", dest="candidates_out", metavar="FILE",
                      help="Write a candidates.json (verify / brute-force input)")


def _cmd_keys_list(args: argparse.Namespace) -> int:
    from memdiver.app.tools_keyfinders import keyfinders_list_result
    _write_output(keyfinders_list_result().payload, args.output)
    return 0


def _cmd_keys_scan(args: argparse.Namespace) -> int:
    from memdiver.app.tools_keyfinders import DEFAULT_FINDERS, keyfinders_scan_result
    result = keyfinders_scan_result(
        args.dump, tuple(args.finders or DEFAULT_FINDERS), args.view, args.offset,
        args.length, args.heap_policy, args.params, args.case_dir, args.limit,
        args.candidates_out, not args.no_annotate)
    _write_output(result.payload, args.output)
    return 0


_KEYS_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "list": _cmd_keys_list, "scan": _cmd_keys_scan,
}


def _cmd_keys(args: argparse.Namespace) -> int:
    """Dispatch a ``keys <action>`` subcommand to its handler."""
    handler: Optional[Callable] = _KEYS_HANDLERS.get(getattr(args, "keys_action", None) or "")
    if handler is None:
        print("memdiver keys: pick an action: " + ", ".join(_KEYS_HANDLERS), file=sys.stderr)
        return 1
    return handler(args)
