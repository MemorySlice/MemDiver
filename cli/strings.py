"""Strings-table CLI: ``memdiver strings table <dump>``.

A thin adapter over :func:`memdiver.app.tools_strings.strings_table_result` (the same
producer behind ``/api/strings/table`` and the MCP ``strings_table`` tool). It always
executes inline. Output is the producer payload as JSON (stdout, or ``-o FILE``); a
:class:`CapabilityError` propagates to the CLI backstop. ``memdiver inspect strings``
(the streaming, cursor-paged extractor) is a different command and is unchanged.
"""

import argparse
import sys
from typing import Callable, Dict, Optional

from ._shared import _write_output


def add_strings_parser(sub) -> None:
    """Register the ``strings <action>`` group on the top-level subparsers."""
    from memdiver.app.tools_strings import (DEFAULT_ENCODINGS, DEFAULT_LIMIT,
                                            DEFAULT_MIN_LEN, ENCODINGS)

    group = sub.add_parser(
        "strings", help="Strings as a table: one row per string with address, "
                        "region and IOC badges")
    actions = group.add_subparsers(dest="strings_action")
    table = actions.add_parser(
        "table", help="Extract the strings of the captured bytes of a dump "
                      "(.msl / .mdview / raw)")
    table.add_argument("dump", help="Dump file")
    table.add_argument("--view", choices=("va", "vas", "raw"),
                       help="Coordinates (default: va for .msl/.mdview, raw for a flat file)")
    table.add_argument("--offset", type=lambda x: int(x, 0),
                      help="Window start, in --view coordinates (decimal or 0x hex)")
    table.add_argument("--length", type=lambda x: int(x, 0), help="Window length in bytes")
    table.add_argument("--min-len", type=int, default=DEFAULT_MIN_LEN, dest="min_len",
                       help=f"Minimum string length (default: {DEFAULT_MIN_LEN})")
    table.add_argument("--encoding", action="append", dest="encodings", choices=ENCODINGS,
                       help=f"Encoding (repeatable; default: {', '.join(DEFAULT_ENCODINGS)})")
    table.add_argument("--case", dest="case_dir",
                       help="Case directory: register the 'strings' table "
                            "(then: case query / vol3 query --saved strings_iocs)")
    table.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                       help=f"Row cap; a cut sets truncated (default: {DEFAULT_LIMIT})")
    table.add_argument("-o", "--output", help="Write the JSON payload to this file")
    table.add_argument("-v", "--verbose", action="store_true")


def _cmd_strings_table(args: argparse.Namespace) -> int:
    from memdiver.app.tools_strings import (DEFAULT_ENCODINGS, _region_of,
                                            strings_table_result)
    result = strings_table_result(
        args.dump, args.view, _region_of(args.offset, args.length), args.min_len,
        tuple(args.encodings or DEFAULT_ENCODINGS), args.limit, args.case_dir)
    _write_output(result.payload, args.output)
    return 0


_STRINGS_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "table": _cmd_strings_table,
}


def _cmd_strings(args: argparse.Namespace) -> int:
    """Dispatch a ``strings <action>`` subcommand to its handler."""
    handler: Optional[Callable] = _STRINGS_HANDLERS.get(
        getattr(args, "strings_action", None) or "")
    if handler is None:
        print("memdiver strings: pick an action: " + ", ".join(_STRINGS_HANDLERS),
              file=sys.stderr)
        return 1
    return handler(args)
