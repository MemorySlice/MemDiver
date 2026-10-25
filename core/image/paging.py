"""Kernel paging for Linux x86_64 images: 4-level vs LA57, decided by self-test.

Measured on the pakunoda corpus (``docs/dev/semantic_workbench_progress.md``):
10 of 20 x86_64 images run 5-level paging (LA57). Volatility 3 (2.27 and
2.28) has no 5-level Intel layer, so its automagic stacks a 4-level layer over
the right DTB and every plugin silently returns nothing. This module adds the
missing layer class and picks the depth by *reading known kernel bytes back*
(``linux_banner`` and ``init_task.comm``) through each candidate — the two
depths are mutually exclusive on every measured image, and a read-back check
cannot be fooled by a stale hint.

Imports Volatility 3; only :mod:`memdiver.core.image.context` imports this.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Type

from volatility3.framework import exceptions, interfaces
from volatility3.framework.layers import intel

#: ``__START_KERNEL_map`` on x86_64: kernel-image VA minus this = physical (pre-KASLR).
START_KERNEL_MAP = 0xFFFFFFFF80000000
#: Symbols that hold the kernel's top-level page table, newest name first.
PGD_SYMBOLS = ("init_top_pgt", "init_level4_pgt")


class LinuxIntel5Level(intel.LinuxIntel32e):
    """x86_64 LA57: one more 9-bit level above Intel32e, 57-bit virtual addresses."""

    _maxvirtaddr = 57
    _structure = [("page map layer 5", 9, False)] + list(intel.Intel32e._structure)


#: Candidate kernel layer classes by virtual-address width.
LAYER_BY_VA_BITS: Dict[int, Type[intel.Intel]] = {48: intel.LinuxIntel32e, 57: LinuxIntel5Level}


@dataclass(frozen=True)
class KernelPaging:
    """What the self-test established about the kernel's address space."""

    layer_name: str
    va_bits: int
    dtb: int
    kaslr_shift: int     # physical KASLR shift
    aslr_shift: int      # virtual KASLR shift (the kernel module's offset)
    la57_symbol: Optional[int]   # value of __pgtable_l5_enabled, if the ISF has it
    rejected: Tuple[str, ...]    # why the other depth(s) failed

    def to_dict(self) -> Dict[str, Any]:
        return {"layer": self.layer_name, "va_bits": self.va_bits, "dtb": self.dtb,
                "kaslr_shift": self.kaslr_shift, "aslr_shift": self.aslr_shift,
                "la57_symbol": self.la57_symbol, "rejected": list(self.rejected)}


def kernel_dtb(table: Any, kaslr_shift: int) -> int:
    """Physical address of the top-level kernel page table (from the ISF)."""
    for name in PGD_SYMBOLS:
        if name in table.symbols:
            return table.get_symbol(name).address - START_KERNEL_MAP + kaslr_shift
    raise ValueError(f"profile has none of {PGD_SYMBOLS}; not a supported x86_64 kernel")


def read_la57_symbol(ctx: interfaces.context.ContextInterface, physical: str,
                     table: Any, kaslr_shift: int) -> Optional[int]:
    """``__pgtable_l5_enabled`` read straight from physical memory (evidence only)."""
    if "__pgtable_l5_enabled" not in table.symbols:
        return None
    phys = table.get_symbol("__pgtable_l5_enabled").address - START_KERNEL_MAP + kaslr_shift
    try:
        return int.from_bytes(ctx.layers[physical].read(phys, 4), "little")
    except exceptions.InvalidAddressException:
        return None


def choose_kernel_layer(ctx: interfaces.context.ContextInterface, physical: str,
                        table_name: str, kaslr_shift: int, aslr_shift: int,
                        dtb: Optional[int] = None,
                        va_bits_hint: Optional[int] = None) -> KernelPaging:
    """Stack the kernel layer whose depth reads the banner and init_task back.

    ``va_bits_hint`` (e.g. from a ``.mdview`` paging spec) is tried first but
    still has to pass the read-back test. Raises ``ValueError`` when no depth
    passes — never returns a layer that silently translates nothing.
    """
    table = ctx.symbol_space[table_name]
    dtb = kernel_dtb(table, kaslr_shift) if dtb is None else dtb
    rejected: List[str] = []
    for va_bits in _candidate_order(va_bits_hint):
        name = _add_layer(ctx, physical, dtb, va_bits)
        reason = _self_test(ctx, name, table, aslr_shift)
        if reason is None:
            return KernelPaging(name, va_bits, dtb, kaslr_shift, aslr_shift,
                                read_la57_symbol(ctx, physical, table, kaslr_shift),
                                tuple(rejected))
        rejected.append(f"{va_bits}-bit: {reason}")
        ctx.layers.del_layer(name)
    raise ValueError(f"no paging depth reads the kernel back at DTB {dtb:#x}: {rejected}")


def _candidate_order(hint: Optional[int]) -> List[int]:
    order = [57, 48]
    if hint in LAYER_BY_VA_BITS:
        order.remove(hint)
        order.insert(0, hint)
    return order


def _add_layer(ctx: interfaces.context.ContextInterface, physical: str,
               dtb: int, va_bits: int) -> str:
    name = ctx.layers.free_layer_name(f"kernel{va_bits}")
    ctx.config[f"{name}.memory_layer"] = physical
    ctx.config[f"{name}.page_map_offset"] = dtb
    ctx.add_layer(LAYER_BY_VA_BITS[va_bits](ctx, name, name, metadata={"os": "Linux"}))
    return name


def _self_test(ctx: interfaces.context.ContextInterface, layer_name: str,
               table: Any, aslr_shift: int) -> Optional[str]:
    """``None`` when the layer reads known kernel bytes back, else why not."""
    layer = ctx.layers[layer_name]
    checks = [("linux_banner", 0, b"Linux version")]
    if "init_task" in table.symbols and "task_struct" in table.types:
        comm = table.get_type("task_struct").relative_child_offset("comm")
        checks.append(("init_task", comm, b"swapper"))
    for symbol, delta, expected in checks:
        va = table.get_symbol(symbol).address + aslr_shift + delta
        try:
            data = layer.read(va, len(expected), pad=False)
        except exceptions.InvalidAddressException as exc:
            return f"{symbol} untranslatable ({exc.__class__.__name__})"
        if data != expected:
            return f"{symbol} reads {data!r}, expected {expected!r}"
    return None
