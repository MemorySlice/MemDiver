"""``msl.threads``: the THREAD_CONTEXT blocks of a ``.msl`` capture (spec 5.7, Table 22).

One row per thread with its state, flags and the program counter, stack pointer and frame
pointer picked by the register role bits of Table 23. ``--verbose`` adds every register
as ``name=hex`` in a ``Registers`` column; vector registers are shown as raw bytes, integer
registers as little-endian values (the only byte order the format allows).
"""

import logging
from typing import Any, Iterator, List, Optional, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from .. import msl_slim
from .info import collected, enum_name, format_time, msl_reader_or_report

vollog = logging.getLogger(__name__)

THREAD_FLAGS = ((0x0001, "current"), (0x0002, "crashed"), (0x0004, "suspended"),
                (0x0008, "partial"))
ROLE_PC, ROLE_SP, ROLE_FP = 0x0001, 0x0002, 0x0004
ROLE_NAMES = {ROLE_PC: ("pc", "rip", "eip"), ROLE_SP: ("sp", "rsp", "esp"),
              ROLE_FP: ("fp", "rbp", "ebp", "x29")}
MAX_INTEGER_WIDTH = 8


def register_value(register: Any) -> Any:
    """An int for a register of at most 8 bytes, else the raw bytes."""
    if register.width <= MAX_INTEGER_WIDTH:
        return int.from_bytes(register.value, "little")
    return bytes(register.value)


def role_register(thread: Any, role: int) -> Optional[int]:
    """Value of the register flagged ``role`` (else one of its conventional names)."""
    for register in thread.registers:
        if register.flags & role and register.width <= MAX_INTEGER_WIDTH:
            return register_value(register)
    for name in ROLE_NAMES[role]:
        register = thread.register(name)
        if register is not None and register.width <= MAX_INTEGER_WIDTH:
            return register_value(register)
    return None


def registers_text(thread: Any) -> str:
    parts = []
    for register in thread.registers:
        value = register_value(register)
        text = f"0x{value:x}" if isinstance(value, int) else value.hex()
        parts.append(f"{register.name}={text}")
    return " ".join(parts)


def flags_text(flags: int) -> str:
    return ",".join(name for bit, name in THREAD_FLAGS if flags & bit) or "-"


class Threads(interfaces.plugins.PluginInterface):
    """Lists the threads (state, flags, pc/sp/fp) of a MemDiver .msl capture."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer of the .msl capture"),
            requirements.BooleanRequirement(
                name="verbose", optional=True, default=False,
                description="Add every register as name=value"),
        ]

    @staticmethod
    def _address(value: Optional[int]) -> Any:
        return format_hints.Hex(value) if value is not None else renderers.NotApplicableValue()

    def _row(self, thread: Any, header_arch: str, verbose: bool) -> Tuple:
        arch = enum_name(msl_slim.ArchType, thread.arch) if thread.arch else header_arch
        row = (thread.thread_id if thread.thread_id else renderers.NotApplicableValue(),
               thread.name or renderers.NotApplicableValue(),
               enum_name(msl_slim.ThreadState, thread.state), arch, flags_text(thread.flags),
               self._address(role_register(thread, ROLE_PC)),
               self._address(role_register(thread, ROLE_SP)),
               self._address(role_register(thread, ROLE_FP)), len(thread.registers),
               format_time(thread.start_time_ns))
        return row + (registers_text(thread),) if verbose else row

    def _generator(self, reader: Any, verbose: bool) -> Iterator[Tuple[int, Tuple]]:
        threads = collected(reader, "collect_thread_contexts", "msl.threads")
        header_arch = enum_name(msl_slim.ArchType, reader.file_header.arch_type)
        for thread in threads or []:
            if not hasattr(thread, "registers"):
                vollog.warning("msl.threads: malformed THREAD_CONTEXT at 0x%X skipped",
                               thread.block_header.file_offset)
                continue
            yield 0, self._row(thread, header_arch, verbose)

    def run(self) -> renderers.TreeGrid:
        verbose = bool(self.config.get("verbose"))
        columns = [("TID", int), ("Name", str), ("State", str), ("Arch", str), ("Flags", str),
                   ("PC", format_hints.Hex), ("SP", format_hints.Hex),
                   ("FP", format_hints.Hex), ("Regs", int), ("Started", str)]
        if verbose:
            columns.append(("Registers", str))
        reader = msl_reader_or_report(self.context, self.config["primary"], "msl.threads")
        return renderers.TreeGrid(columns, self._generator(reader, verbose)
                                  if reader is not None else iter(()))
