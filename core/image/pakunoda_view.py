"""No-ISF kernel view: the kernel address space from a page-table root alone (plan T4.3).

A kernel view normally needs a profile (ISF) so vol3 can find ``_text``/``_end``
and the direct map. This view needs only what the ISF workbench can recover
without one: the physical address of the top-level table (``pgd_phys``, from
``pakunoda.probes.find_page_table_root`` or typed in) and the paging format.

The format is pakunoda's ``PagingFormat`` — from ``arch.paging_format(va_bits,
page_size)`` (x86_64 4/5-level, aarch64 4K granule 48/39-bit, x86_32 non-PAE),
or supplied as a dict for architectures pakunoda only stubs (arm32, mips). One
walker serves every architecture, so the view also covers aarch64 images, for
which vol3 has no page-table layer at all.

The view enumerates the kernel half of the table tree once and keeps the leaves:

* a leaf whose frame is in the image -> CAPTURED;
* a leaf whose frame is not, or a table the walk cannot read -> FAILED (the
  upper levels say it is mapped; its bytes are not here) — never zeros;
* no translation -> outside every run, i.e. unmapped.

Reads go through the recorded leaves, so a read never re-walks and never
pads. Every physical read holds ``ImageContext.lock``.
"""

from __future__ import annotations

import bisect
import threading
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from memdiver.core.image.context import ImageContext, require_pakunoda
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.view_descriptor import PagingSpec
from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Bit 0 is "present" on x86 and "valid" on AArch64 descriptors alike.
VALID_BIT = 1
#: Walk budget: a mistyped ``pgd_phys`` must not hang or build a giant view.
MAX_LEAVES = 2_000_000
MAX_TABLES = 200_000
#: Architectures with more than one paging depth/width: ``va_bits`` cannot be guessed.
AMBIGUOUS_VA_BITS: Dict[str, Tuple[int, ...]] = {
    "x86_64": (48, 57), "amd64": (48, 57), "aarch64": (48, 39), "arm64": (48, 39)}


@dataclass(frozen=True)
class Leaf:
    """One final translation: ``size`` bytes at kernel VA ``va`` -> physical ``phys``."""

    va: int
    size: int
    phys: Optional[int]       # None: the table holding it could not be read
    state: RunState


def require_va_bits(spec: PagingSpec) -> None:
    """Without an explicit ``format``, ``va_bits`` is required where the depth is ambiguous.

    pakunoda would default to 48-bit: on an LA57 image the 5-level table would be
    walked as 4-level and wrong translations labelled CAPTURED.
    """
    choices = AMBIGUOUS_VA_BITS.get((spec.arch or "").lower())
    if not spec.format and choices and not spec.va_bits:
        raise CapabilityError(
            f"paging needs 'va_bits' ({' or '.join(map(str, choices))}) for {spec.arch}: "
            "the paging depth cannot be guessed (a wrong guess mislabels translations)",
            category=ErrorCategory.INVALID_INPUT, code="paging_va_bits_required")


def paging_format_for(spec: PagingSpec) -> Any:
    """The pakunoda ``PagingFormat`` a spec describes (CapabilityError if none)."""
    require_pakunoda()
    from pakunoda.core.pagetable import PagingFormat
    if spec.format:
        try:
            return PagingFormat(**spec.format)
        except (TypeError, ValueError) as exc:
            raise CapabilityError(f"invalid paging format: {exc}",
                                  category=ErrorCategory.INVALID_INPUT) from exc
    if not spec.arch:
        raise CapabilityError("a no-ISF kernel view needs 'arch' or an explicit 'format'",
                              category=ErrorCategory.INVALID_INPUT)
    require_va_bits(spec)
    from pakunoda.probes import resolve_arch
    fmt = resolve_arch(spec.arch).paging_format(va_bits=spec.va_bits,
                                                page_size=spec.page_size)
    if fmt is None:
        raise CapabilityError(
            f"pakunoda states no paging format for {spec.arch} (va_bits={spec.va_bits}, "
            f"page_size={spec.page_size}); pass an explicit 'format'",
            category=ErrorCategory.UNSUPPORTED)
    return fmt


def default_kernel_va_start(arch: Optional[str], va_bits: int) -> int:
    """Lowest kernel VA per architecture (the half/split the kernel's table owns)."""
    name = (arch or "").lower()
    if name in ("aarch64", "arm64"):
        return ((1 << 64) - 1) ^ ((1 << va_bits) - 1)       # TTBR1: all top bits set
    if va_bits >= 39:                                       # x86_64 and other 64-bit
        return ((1 << 64) - 1) ^ ((1 << (va_bits - 1)) - 1)  # upper canonical half
    return 0xC0000000                                       # 32-bit 3G/1G split


class TableWalk:
    """Enumerate the leaves of one page-table tree below ``kernel_va_start``.

    ``read_phys(addr, n)`` returns ``n`` bytes or ``None`` when the image lacks
    them; ``captured(phys, size)`` splits a physical range into
    ``(start, size, captured?)`` pieces. Both are injected so the walk is pure
    and testable without an image.
    """

    def __init__(self, fmt: Any, pgd_phys: int, endian: str, kernel_va_start: int,
                 read_phys: Any, captured: Any, max_leaves: int = MAX_LEAVES,
                 max_tables: int = MAX_TABLES) -> None:
        self.fmt = fmt
        self.pgd_phys = pgd_phys
        self.order = "little" if endian == "little" else "big"
        self.kernel_va_start = kernel_va_start
        self.high_bits = kernel_va_start & ~((1 << fmt.va_bits) - 1)
        self._read_phys = read_phys
        self._captured = captured
        self._max_leaves, self._max_tables = max_leaves, max_tables
        self._tables_read = self._leaves_seen = 0

    def _budget(self, what: str, limit: int) -> CapabilityError:
        return CapabilityError(
            f"page-table walk exceeded the {what} limit of {limit:,}; is pgd_phys "
            f"{self.pgd_phys:#x} really a kernel page-table root?",
            category=ErrorCategory.INVALID_INPUT, code="paging_walk_budget",
            details={"limit": what, "max": limit})

    def leaves(self) -> Iterator[Leaf]:
        first = (self.kernel_va_start & ((1 << self.fmt.va_bits) - 1)) \
            >> self.fmt.level_shift(0)
        yield from self._table(self.pgd_phys, 0, 0, first)

    def _table(self, table: int, level: int, va_low: int, first: int = 0) -> Iterator[Leaf]:
        fmt = self.fmt
        entries = 1 << fmt.index_bits
        span = 1 << fmt.level_shift(level)
        self._tables_read += 1
        if self._tables_read > self._max_tables:
            raise self._budget("tables read", self._max_tables)
        raw = self._read_phys(table, entries * fmt.descriptor_size)
        if raw is None:
            # The parent says this range is mapped, but its table is not in the
            # image: the bytes exist and are not here.
            self._leaves_seen += 1
            yield Leaf(self.high_bits | (va_low + first * span), (entries - first) * span,
                       None, RunState.FAILED)
            return
        size = fmt.descriptor_size
        for index in range(first, entries):
            desc = int.from_bytes(raw[index * size:(index + 1) * size], self.order)
            if not desc & VALID_BIT:
                continue
            child_va = va_low + index * span
            if fmt.is_leaf(desc, level):
                yield from self._leaf(desc, level, child_va, span)
            else:
                yield from self._table(desc & fmt.pa_mask, level + 1, child_va)

    def _leaf(self, desc: int, level: int, va_low: int, span: int) -> Iterator[Leaf]:
        fmt = self.fmt
        required = fmt.leaf_required_bits
        if level == fmt.levels - 1 and (desc & required) != required:
            return  # reserved encoding: the hardware faults, so it is not a mapping
        phys = desc & fmt.leaf_pa_mask(level)
        cursor = self.high_bits | va_low
        for start, size, is_captured in self._captured(phys, span):
            self._leaves_seen += 1
            if self._leaves_seen > self._max_leaves:
                raise self._budget("leaves", self._max_leaves)
            yield Leaf(cursor + (start - phys), size, start,
                       RunState.CAPTURED if is_captured else RunState.FAILED)


def coalesce(leaves: Sequence[Leaf]) -> List[LayerRun]:
    """Adjacent same-state leaves merged into runs (physically scattered is fine)."""
    runs: List[LayerRun] = []
    for leaf in leaves:
        if runs and runs[-1].end == leaf.va and runs[-1].state is leaf.state:
            last = runs.pop()
            runs.append(LayerRun(last.start, last.length + leaf.size, last.state))
        else:
            runs.append(LayerRun(leaf.va, leaf.size, leaf.state))
    return runs


def captured_pieces(physical_runs: Sequence[LayerRun]) -> Any:
    """``captured(phys, size)`` over the image's physical runs (sorted by start)."""
    starts = [r.start for r in physical_runs]

    def pieces(phys: int, size: int) -> Iterator[Tuple[int, int, bool]]:
        cursor, end = phys, phys + size
        i = max(bisect.bisect_right(starts, cursor) - 1, 0)
        while cursor < end:
            run = physical_runs[i] if i < len(physical_runs) else None
            if run is None or run.start >= end:
                yield cursor, end - cursor, False
                return
            if cursor < run.start:
                yield cursor, run.start - cursor, False
                cursor = run.start
            elif cursor < run.end:
                stop = min(run.end, end)
                yield cursor, stop - cursor, True
                cursor = stop
                i += 1
            else:
                i += 1
    return pieces


class NoIsfKernelAdapter:
    """Layer adapter (``Vol3LayerSource`` protocol) for a kernel view without a profile."""

    def __init__(self, image_ctx: ImageContext, paging: PagingSpec) -> None:
        if paging is None or paging.pgd_phys is None:
            raise CapabilityError("a no-ISF kernel view needs paging.pgd_phys",
                                  category=ErrorCategory.INVALID_INPUT)
        self._ctx = image_ctx
        self._spec = paging
        self._fmt = paging_format_for(paging)
        self._physical = image_ctx.context.layers[image_ctx.physical_layer]
        self._leaves: Optional[List[Leaf]] = None
        self._starts: List[int] = []
        self._walk_lock = threading.Lock()

    # -- LayerAdapter protocol ------------------------------------------------
    def runs(self) -> Sequence[LayerRun]:
        return coalesce(self._all_leaves())

    def read(self, address: int, length: int) -> bytes:
        """Bytes of a CAPTURED stretch; raises on anything else (never pads)."""
        leaves = self._all_leaves()
        out, cursor, end = bytearray(), address, address + length
        while cursor < end:
            i = bisect.bisect_right(self._starts, cursor) - 1
            leaf = leaves[i] if i >= 0 else None
            if leaf is None or cursor >= leaf.va + leaf.size or leaf.state is not RunState.CAPTURED:
                raise CapabilityError(f"kernel VA {cursor:#x} is not captured in this view",
                                      category=ErrorCategory.INVALID_INPUT)
            take = min(end, leaf.va + leaf.size) - cursor
            out += self._read_physical(leaf.phys + (cursor - leaf.va), take)
            cursor += take
        return bytes(out)

    def describe(self) -> Dict[str, Any]:
        fmt = self._fmt
        return {"view": "kernel", "profile": None, "paging": self._spec.to_dict(),
                "levels": fmt.levels, "va_bits": fmt.va_bits,
                "kernel_va_start": f"{self._kernel_va_start():#x}",
                "leaves": len(self._leaves) if self._leaves is not None else None}

    def close(self) -> None:
        """Nothing to release: the ImageContext is shared through its cache."""

    def translate(self, address: int) -> Optional[int]:
        """Physical address of a captured kernel VA, else None (used by struct walks)."""
        leaves = self._all_leaves()
        i = bisect.bisect_right(self._starts, address) - 1
        if i < 0:
            return None
        leaf = leaves[i]
        if address >= leaf.va + leaf.size or leaf.state is not RunState.CAPTURED:
            return None
        return leaf.phys + (address - leaf.va)

    # -- internals -------------------------------------------------------------
    def _kernel_va_start(self) -> int:
        spec = self._spec
        if spec.kernel_va_start is not None:
            return int(spec.kernel_va_start)
        return default_kernel_va_start(spec.arch, self._fmt.va_bits)

    def _all_leaves(self) -> List[Leaf]:
        if self._leaves is None:
            with self._walk_lock:
                if self._leaves is None:
                    leaves = self._walk_leaves()
                    self._starts = [leaf.va for leaf in leaves]   # before _leaves: readers
                    self._leaves = leaves                         # gate on _leaves
        return self._leaves

    def _walk_leaves(self) -> List[Leaf]:
        from memdiver.core.image.adapters import physical_runs
        with self._ctx.lock:
            phys_runs = sorted(physical_runs(self._physical), key=lambda r: r.start)
        walk = TableWalk(self._fmt, int(self._spec.pgd_phys), self._spec.endian,
                         self._kernel_va_start(), self._read_table,
                         captured_pieces(phys_runs))
        return sorted(walk.leaves(), key=lambda leaf: leaf.va)

    def _read_table(self, phys: int, length: int) -> Optional[bytes]:
        with self._ctx.lock:
            if not self._physical.is_valid(phys, length):
                return None
            return self._physical.read(phys, length, pad=False)

    def _read_physical(self, phys: int, length: int) -> bytes:
        with self._ctx.lock:
            return self._physical.read(phys, length, pad=False)
