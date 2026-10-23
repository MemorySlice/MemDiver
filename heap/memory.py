"""Virtual-address reads over any dump source.

Allocator parsers think in virtual addresses: follow ``fd``, read the size
word at ``chunk - 8``. Dump sources think in view offsets. :class:`VaMemory`
is the bridge:

* a source with a sparse ``"va"`` view (``.msl``) is read through
  :func:`core.dump_source.read_range_with_validity`, so a page the dump never
  captured yields ``None`` instead of synthesized ``0x00`` filler;
* a source with a VA map but no ``"va"`` view (gcore, gdb/lldb regioned raw)
  is read through its dense ``"vas"`` projection, after checking that the
  whole requested range lies in contiguous captured runs;
* a flat source with no VA map (``RawDumpSource``) is mapped linearly:
  ``offset = va - base_va`` (``base_va`` defaults to 0).

Every read either returns exactly ``n`` captured bytes or ``None``.
"""

from __future__ import annotations

import bisect
import struct
from functools import cached_property
from typing import Any, Iterator, List, Optional, Tuple

from memdiver.core.dump_source import read_range_with_validity, supported_views
from memdiver.heap.platform import (MappedRegion, TargetPlatform, memory_map_of,
                                    platform_of)

#: arm64 Top-Byte-Ignore: Android tags heap pointers in bits 56-63.
_TBI_MASK = 0x00FF_FFFF_FFFF_FFFF

#: ``(view_offset, va, length)`` — one contiguous captured run.
_Run = Tuple[int, int, int]


def strip_tag(ptr: int, platform: Optional[TargetPlatform]) -> int:
    """Clear an arm64 TBI pointer tag (``0xb400007a…`` -> ``0x0000007a…``)."""
    if platform is not None and platform.arch == "arm64":
        return ptr & _TBI_MASK
    return ptr


class VaMemory:
    """Read captured bytes of *source* by virtual address.

    ``base_va`` forces flat mode (``offset = va - base_va`` into the
    ``"raw"`` view); a source without any VA map is flat at ``base_va=0``.
    """

    def __init__(self, source: Any, platform: Optional[TargetPlatform] = None,
                 *, base_va: Optional[int] = None):
        self._source = source
        self.platform = platform if platform is not None else platform_of(source)
        if base_va is None and not _has_va_map(source):
            base_va = 0
        self._base_va = base_va
        prefix = "<" if self.platform.endianness == "little" else ">"
        self._fmt = {2: prefix + "H", 4: prefix + "I", 8: prefix + "Q"}

    @property
    def source(self) -> Any:
        return self._source

    @property
    def base_va(self) -> Optional[int]:
        """The flat-mode base address, or ``None`` when a VA map is used."""
        return self._base_va

    @cached_property
    def regions(self) -> List[MappedRegion]:
        """The source's memory map (:func:`heap.platform.memory_map_of`)."""
        return memory_map_of(self._source)

    # -- reads ----------------------------------------------------------------

    def read(self, va: int, n: int) -> Optional[bytes]:
        """Exactly *n* captured bytes at *va*, or ``None`` if any is missing."""
        if n <= 0:
            return b"" if n == 0 else None
        if va < 0:
            return None
        if self._base_va is not None:
            return self._read_flat(va, n)
        if self._has_sparse_va_view:
            return self._read_sparse(va, n)
        return self._read_dense(va, n)

    def _read_flat(self, va: int, n: int) -> Optional[bytes]:
        offset = va - (self._base_va or 0)
        if offset < 0:
            return None
        return _exact(self._source.read_range(offset, n, view="raw"), n)

    def _read_sparse(self, va: int, n: int) -> Optional[bytes]:
        offset = self._va_view_offset(va)
        if offset is None:
            return None
        data, runs = read_range_with_validity(self._source, offset, n, view="va")
        return data if runs == [(0, n)] and len(data) == n else None

    def _read_dense(self, va: int, n: int) -> Optional[bytes]:
        first = self.va_to_view_offset(va, "vas")
        last = self.va_to_view_offset(va + n - 1, "vas")
        if first is None or last != first + n - 1:
            return None  # a gap (or an uncaptured tail) inside the range
        return _exact(self._source.read_range(first, n, view="vas"), n)

    def _unpack(self, va: int, width: int) -> Optional[int]:
        data = self.read(va, width)
        return None if data is None else struct.unpack(self._fmt[width], data)[0]

    def u16(self, va: int) -> Optional[int]:
        return self._unpack(va, 2)

    def u32(self, va: int) -> Optional[int]:
        return self._unpack(va, 4)

    def u64(self, va: int) -> Optional[int]:
        return self._unpack(va, 8)

    def ptr(self, va: int) -> Optional[int]:
        """A target-pointer-sized word (4 or 8 bytes) at *va*."""
        return self._unpack(va, self.platform.pointer_size)

    # -- translation ------------------------------------------------------------

    def va_to_view_offset(self, va: int, view: str = "vas") -> Optional[int]:
        """Offset of *va* in *view* of the source, ``None`` when unmapped."""
        if self._base_va is not None:
            offset = va - self._base_va
            return offset if offset >= 0 else None
        if view == "va":
            return self._va_view_offset(va)
        return self._table(view).to_offset(va)

    def view_offset_to_va(self, offset: int, view: str = "vas") -> Optional[int]:
        """Virtual address of *offset* in *view*, ``None`` when unmappable."""
        if offset < 0:
            return None
        if self._base_va is not None:
            return self._base_va + offset
        if view == "va":
            return self._va_span_start + offset if self._va_in_span(offset) else None
        return self._table(view).to_va(offset)

    def view_window_segments(self, offset: int, length: int,
                             view: str = "vas") -> List[_Run]:
        """Contiguous ``(view_offset, va, length)`` pieces of a view window.

        The window ``[offset, offset + length)`` of *view* is split wherever
        the view -> VA mapping jumps (a gap between captured runs), so within
        each piece ``va = piece_va + (o - piece_offset)``. Unmapped offsets
        are left out; pieces are in ascending view-offset order.
        """
        if length <= 0 or offset < 0:
            return []
        end = offset + length
        if self._base_va is not None:
            return [(offset, self._base_va + offset, length)]
        if view == "va":
            hi = min(end, self._source.size_for("va")) if self._has_sparse_va_view else 0
            return ([(offset, self._va_span_start + offset, hi - offset)]
                    if hi > offset else [])
        return self._table(view).segments(offset, end)

    # -- internals ------------------------------------------------------------

    @cached_property
    def _has_sparse_va_view(self) -> bool:
        return ("va" in supported_views(self._source)
                and callable(getattr(self._source, "va_span_start", None)))

    @cached_property
    def _va_span_start(self) -> int:
        start = self._source.va_span_start() if self._has_sparse_va_view else None
        return start or 0

    def _va_in_span(self, offset: int) -> bool:
        if not self._has_sparse_va_view:
            return False
        return 0 <= offset < self._source.size_for("va")

    def _va_view_offset(self, va: int) -> Optional[int]:
        offset = va - self._va_span_start
        return offset if self._va_in_span(offset) else None

    def _table(self, view: str) -> "_RunTable":
        if view == "vas":
            return self._vas_table
        if view == "raw":
            return self._raw_table
        return _EMPTY_TABLE

    @cached_property
    def _vas_table(self) -> "_RunTable":
        return _RunTable(self._vas_runs())

    @cached_property
    def _raw_table(self) -> "_RunTable":
        return _RunTable(self._raw_runs())

    def _vas_runs(self) -> List[_Run]:
        """Captured runs in ``"vas"`` order (dense, ascending offsets)."""
        captured = getattr(self._source, "captured_runs", None)
        if callable(captured):  # .msl: (va, length, vas_offset)
            return [(vas, va, length) for va, length, vas in captured()]
        runs, cursor = [], 0
        for start, end, _file_offset in _iter_va_ranges(self._source):
            runs.append((cursor, start, end - start))
            cursor += end - start
        return runs

    def _raw_runs(self) -> List[_Run]:
        """``(file_offset, va, length)`` for sources whose ranges carry one."""
        if callable(getattr(self._source, "captured_runs", None)):
            return []  # .msl raw view is the container, not memory
        return [(off, start, end - start)
                for start, end, off in _iter_va_ranges(self._source)]


def _exact(data: bytes, n: int) -> Optional[bytes]:
    return data if len(data) == n else None


def _has_va_map(source: Any) -> bool:
    return callable(getattr(source, "va_to_vas_offset", None))


def _iter_va_ranges(source: Any) -> Iterator[Tuple[int, int, int]]:
    """``(start_va, end_va, file_offset)`` of gcore / regioned sources."""
    if not _has_va_map(source):
        return iter(())
    return source.iter_ranges()


class _RunTable:
    """Captured runs indexed both ways: VA -> view offset and back."""

    def __init__(self, runs: List[_Run]):
        self._by_offset = sorted(runs)
        self._offset_starts = [r[0] for r in self._by_offset]
        self._by_va = sorted(runs, key=lambda r: r[1])
        self._va_starts = [r[1] for r in self._by_va]

    def to_offset(self, va: int) -> Optional[int]:
        run = _containing(self._by_va, self._va_starts, va, key_index=1)
        return None if run is None else run[0] + (va - run[1])

    def to_va(self, offset: int) -> Optional[int]:
        run = _containing(self._by_offset, self._offset_starts, offset, key_index=0)
        return None if run is None else run[1] + (offset - run[0])

    def segments(self, lo: int, hi: int) -> List[_Run]:
        """Runs intersected with the view-offset window ``[lo, hi)``."""
        first = max(bisect.bisect_right(self._offset_starts, lo) - 1, 0)
        pieces: List[_Run] = []
        for run_offset, run_va, run_len in self._by_offset[first:]:
            if run_offset >= hi:
                break
            start, stop = max(lo, run_offset), min(hi, run_offset + run_len)
            if stop > start:
                pieces.append((start, run_va + (start - run_offset), stop - start))
        return pieces


def _containing(runs: List[_Run], starts: List[int], key: int,
                key_index: int) -> Optional[_Run]:
    idx = bisect.bisect_right(starts, key) - 1
    if idx < 0:
        return None
    run = runs[idx]
    return run if key < run[key_index] + run[2] else None


_EMPTY_TABLE = _RunTable([])
