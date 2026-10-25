"""Run table of one address-space view: which stretches are captured, and why not the rest.

A view of a memory image (physical, kernel, one process) is sparse. Its
:class:`RunIndex` lists the stretches the view knows about, each with a
:class:`RunState`; anything outside every run is unmapped. From that one table
it derives the three byte views a :class:`~memdiver.core.dump_source.DumpSource`
serves — the sparse ``"va"`` span, the packed ``"vas"`` stream of captured
bytes — and the :class:`~memdiver.core.location.Coverage` of any read.

Pure arithmetic: no I/O, no Volatility.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Iterator, List, Optional, Tuple

from memdiver.core.location import Coverage, CoverageGap, GapReason


class RunState(Enum):
    """State of a known stretch of a view (cf. the ``.msl`` page states)."""

    CAPTURED = "captured"          # bytes are in the image and readable
    FAILED = "failed"              # translated, but the target is not readable
    NOT_RESIDENT = "not_resident"  # mapped (e.g. inside a VMA) but no translation


_GAP_REASON = {RunState.FAILED: GapReason.FAILED,
               RunState.NOT_RESIDENT: GapReason.NOT_RESIDENT}


def _gap_reason(state: Optional[RunState]) -> GapReason:
    """Coverage reason for a non-captured piece; ``None`` (no run) is unmapped."""
    return GapReason.UNMAPPED if state is None else _GAP_REASON[state]


@dataclass(frozen=True)
class LayerRun:
    """``length`` bytes from ``start`` in the view's address space, all in ``state``."""

    start: int
    length: int
    state: RunState

    @property
    def end(self) -> int:
        return self.start + self.length


@dataclass(frozen=True)
class CapturedRun:
    """A captured stretch and where it sits in the packed ``"vas"`` stream."""

    va_start: int
    length: int
    vas_offset: int


class RunIndex:
    """Sorted, merged run table with VA <-> VAS translation and coverage."""

    def __init__(self, runs: Iterable[LayerRun]) -> None:
        self._runs: Tuple[LayerRun, ...] = _merge_runs(runs)
        self._starts: List[int] = [r.start for r in self._runs]
        self._captured: Tuple[CapturedRun, ...] = _pack_captured(self._runs)
        self._vas_starts: List[int] = [c.vas_offset for c in self._captured]
        self._captured_starts: List[int] = [c.va_start for c in self._captured]

    @property
    def runs(self) -> Tuple[LayerRun, ...]:
        return self._runs

    @property
    def captured(self) -> Tuple[CapturedRun, ...]:
        return self._captured

    @property
    def span_start(self) -> int:
        return self._runs[0].start if self._runs else 0

    @property
    def span_size(self) -> int:
        return self._runs[-1].end - self.span_start if self._runs else 0

    @property
    def vas_size(self) -> int:
        last = self._captured[-1] if self._captured else None
        return last.vas_offset + last.length if last else 0

    def pieces(self, start: int, length: int) -> Iterator[Tuple[int, int, Optional[RunState]]]:
        """Partition ``[start, start+length)`` into ``(start, length, state)``; ``None`` = unmapped."""
        cursor, end = start, start + length
        idx = max(bisect.bisect_right(self._starts, start) - 1, 0)
        for run in self._runs[idx:]:
            if run.start >= end:
                break
            if run.end <= cursor:
                continue
            if run.start > cursor:
                yield cursor, run.start - cursor, None
                cursor = run.start
            stop = min(run.end, end)
            yield cursor, stop - cursor, run.state
            cursor = stop
        if cursor < end:
            yield cursor, end - cursor, None

    def coverage(self, start: int, length: int) -> Coverage:
        """Coverage of a read of ``[start, start+length)``, with a reason per gap."""
        gaps = (CoverageGap(s, n, _gap_reason(state))
                for s, n, state in self.pieces(start, length)
                if state is not RunState.CAPTURED)
        return Coverage.from_gaps(start, length, gaps)

    def vas_pieces(self, vas_offset: int, length: int) -> Iterator[Tuple[int, int]]:
        """``(va, length)`` captured pieces backing ``[vas_offset, vas_offset+length)``."""
        cursor, end = vas_offset, min(vas_offset + length, self.vas_size)
        idx = max(bisect.bisect_right(self._vas_starts, cursor) - 1, 0)
        for run in self._captured[idx:]:
            if cursor >= end:
                break
            inner = cursor - run.vas_offset
            take = min(run.length - inner, end - cursor)
            if take > 0:
                yield run.va_start + inner, take
                cursor += take

    def vas_of_va(self, va: int) -> Optional[int]:
        """Packed offset of a captured VA, or ``None`` when ``va`` is not captured."""
        for run in self._captured_containing(va):
            return run.vas_offset + (va - run.va_start)
        return None

    def va_of_vas(self, vas_offset: int) -> Optional[int]:
        """VA of a packed offset, or ``None`` past the end of the stream."""
        for va, _ in self.vas_pieces(vas_offset, 1):
            return va
        return None

    def _captured_containing(self, va: int) -> Iterator[CapturedRun]:
        idx = bisect.bisect_right(self._captured_starts, va) - 1
        if idx >= 0 and va < self._captured[idx].va_start + self._captured[idx].length:
            yield self._captured[idx]


def _merge_runs(runs: Iterable[LayerRun]) -> Tuple[LayerRun, ...]:
    merged: List[LayerRun] = []
    for run in sorted((r for r in runs if r.length > 0), key=lambda r: r.start):
        last = merged[-1] if merged else None
        if last is not None and run.start < last.end:
            raise ValueError(f"overlapping runs at {run.start:#x}")
        if last is not None and last.end == run.start and last.state is run.state:
            merged[-1] = LayerRun(last.start, last.length + run.length, run.state)
        else:
            merged.append(run)
    return tuple(merged)


def _pack_captured(runs: Tuple[LayerRun, ...]) -> Tuple[CapturedRun, ...]:
    packed: List[CapturedRun] = []
    offset = 0
    for run in runs:
        if run.state is RunState.CAPTURED:
            packed.append(CapturedRun(run.start, run.length, offset))
            offset += run.length
    return tuple(packed)
