"""Disassembly CLI: ``memdiver disasm DUMP ADDRESS LENGTH``.

A thin adapter over :func:`memdiver.app.tools_disasm.disasm_result` (the same function
behind ``POST /api/disasm`` and the MCP ``disasm`` tool). ``ADDRESS`` is in the dump's own
address space (kernel/process VA for ``.mdview``, MSL VA for ``.msl``, file offset for a
flat file); only captured bytes are decoded. Output is the payload as JSON.
"""

import argparse

from ._shared import _write_output


def add_disasm_parser(sub) -> None:
    """Register the ``disasm`` command on the top-level subparsers."""
    from memdiver.app.tools_disasm import ARCHES, DEFAULT_MAX_INSNS
    p = sub.add_parser("disasm", help="Disassemble the captured bytes at an address")
    p.add_argument("dump", metavar="DUMP", help="Dump file (.msl, .mdview, raw)")
    p.add_argument("address", type=lambda x: int(x, 0), help="Start address (decimal or 0x hex)")
    p.add_argument("length", type=lambda x: int(x, 0), help="Bytes to decode")
    p.add_argument("--arch", default="auto", help="auto or one of: " + ", ".join(ARCHES))
    p.add_argument("--mode", help="thumb selects Thumb for arm")
    p.add_argument("--max-insns", type=int, default=DEFAULT_MAX_INSNS)
    p.add_argument("--case", dest="case_dir", help="Store the rows as the case's disasm table")
    p.add_argument("-o", "--output", help="Write the JSON payload to this file")
    p.add_argument("-v", "--verbose", action="store_true")


def _cmd_disasm(args: argparse.Namespace) -> int:
    from memdiver.app.tools_disasm import disasm_result
    result = disasm_result(args.dump, args.address, args.length, arch=args.arch,
                           mode=args.mode, max_insns=args.max_insns, case_dir=args.case_dir)
    _write_output(result.payload, args.output)
    return 0
