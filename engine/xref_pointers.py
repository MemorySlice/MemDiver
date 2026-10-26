"""Who points here — find the captured words that hold a pointer into a target.

Given a target VA interval (a struct, a key buffer, a heap chunk) this scans the
CAPTURED memory of a VA-bearing dump for little-endian pointer-sized words whose
value lands inside it, and reports each holder with the field offset it points
at. It is the reverse of "follow this pointer": it answers "what object refers
to this one", which is how a key buffer is walked back up to its owning context.

Coverage is part of the answer. A dump only holds the pages that were captured,
so the result carries ``scanned_bytes`` / ``scanned_runs`` / ``skipped_bytes``
explicitly: memory that was never captured is reported as NOT SCANNED, never as
"no pointers there". ``truncated`` says the ``max_refs`` cap stopped the scan
early, so the ref list is a prefix, not the full census.

Captured runs are separate memory. A word is only ever read from inside ONE run;
two runs that merely sit near each other never form a word between them.

The target is the half-open interval ``[target_lo, target_hi)``. This module
sits in ``engine/`` and must not import ``app/``; the run-table normalization
below is the minimal copy of the idea in ``app.tools_consensus._vas_runs``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import gcd
from typing import Any, Iterator, List, Optional, Tuple

import numpy as np

SLAB_BYTES = 16 * 1024 * 1024
_DTYPES = {4: "<u4", 8: "<u8"}


@dataclass
class PointerRef:
    """One holder word: where it lives, what it holds, where that lands."""

    holder_va: int
    value: int
    target_delta: int  # value - target_lo: the field offset it points at


@dataclass
class XrefScan:
    """Pointers found plus the coverage they were found under."""

    refs: List[PointerRef] = field(default_factory=list)
    scanned_bytes: int = 0
    scanned_runs: int = 0
    skipped_bytes: int = 0  # uncaptured gaps between runs: NOT scanned
    truncated: bool = False
    word_size: int = 8
    alignment: int = 8
    target_lo: int = 0
    target_hi: int = 0


def _captured_runs(source: Any) -> List[Tuple[int, int, int]]:
    """``(va_start, length, vas_offset)`` per captured run, ascending VA."""
    if getattr(source, "format_name", "") == "raw":
        raise ValueError(
            "pointer scan needs a VA-bearing dump (.msl / core); a raw dump has no virtual addresses"
        )
    tabulate = getattr(source, "captured_runs", None)
    if callable(tabulate):
        runs = [tuple(r) for r in tabulate()]
    elif hasattr(source, "iter_ranges"):
        runs = list(_runs_from_ranges(source))
    else:
        raise ValueError("this dump source exposes no virtual-address run table")
    return sorted(runs)


def _runs_from_ranges(source: Any) -> Iterator[Tuple[int, int, int]]:
    """Normalize ``iter_ranges`` shapes; VAS offset = runs laid end to end."""
    is_msl = getattr(source, "format_name", "") == "msl"
    flat = 0
    for first, second, _third in source.iter_ranges():
        va = int(first)
        run = int(second) if is_msl else int(second) - va
        if run > 0:
            yield (va, run, flat)
            flat += run


def _slab_hits(data: bytes, va0: int, step: int, p: Tuple[int, int, int],
               target: Tuple[int, int], exclude: Optional[Tuple[int, int]]):
    """Yield ``(holder_va, value)`` for one slab; only holders starting < step."""
    word, alignment, _ = p
    lo, hi = target
    g = gcd(alignment, word)
    hits: List[Tuple[int, int]] = []
    for phase in range(word):
        if (va0 + phase) % g:
            continue
        n = (len(data) - phase) // word
        if n <= 0:
            continue
        values = np.frombuffer(data, dtype=_DTYPES[word], count=n, offset=phase)
        idx = np.flatnonzero((values >= lo) & (values < hi))
        for i in idx[(phase + idx * word) < step]:
            va = va0 + phase + int(i) * word
            if va % alignment == 0 and not (exclude and exclude[0] <= va < exclude[1]):
                hits.append((va, int(values[i])))
    # Phases are scanned one after another; restore VA order within the slab
    # (slabs and runs ascend, so the whole scan stays VA-sorted).
    yield from sorted(hits)


def _scan_run(source: Any, run: Tuple[int, int, int], params, target, exclude):
    """Yield hits of one run, slab by slab with a word-1 overlap."""
    va, length, vas_off = run
    word = params[0]
    for off in range(0, length, SLAB_BYTES):
        step = min(SLAB_BYTES, length - off)
        take = min(step + word - 1, length - off)
        data = source.read_range(vas_off + off, take, "vas")
        yield from _slab_hits(data, va + off, step, params, target, exclude)


def _validate(word_size: int, alignment: int, lo: int, hi: int) -> None:
    if word_size not in _DTYPES:
        raise ValueError("word_size must be 4 or 8")
    if alignment < 1:
        raise ValueError("alignment must be >= 1")
    if hi <= lo:
        raise ValueError("target interval is empty")


def find_pointers_to(
    source: Any, target_lo: int, target_hi: int, *,
    word_size: int = 8, alignment: int = 8, max_refs: int = 1000,
    exclude: Optional[Tuple[int, int]] = None,
) -> XrefScan:
    """Scan every captured run for words pointing into ``[target_lo, target_hi)``.

    Holders are reported in ascending VA order. ``exclude`` skips holders that
    lie inside that VA interval (e.g. the target object itself). Raises
    ``ValueError`` for a source with no virtual addresses.
    """
    _validate(word_size, alignment, target_lo, target_hi)
    runs = _captured_runs(source)
    scan = XrefScan(word_size=word_size, alignment=alignment,
                    target_lo=target_lo, target_hi=target_hi)
    scan.skipped_bytes = _gap_bytes(runs)
    params = (word_size, alignment, 0)
    for run in runs:
        for va, value in _scan_run(source, run, params, (target_lo, target_hi), exclude):
            scan.refs.append(PointerRef(va, value, value - target_lo))
        scan.scanned_bytes += run[1]
        scan.scanned_runs += 1
        if len(scan.refs) > max_refs:
            scan.refs = sorted(scan.refs, key=lambda r: r.holder_va)[:max_refs]
            scan.truncated = True
            break
    return scan


def _gap_bytes(runs: List[Tuple[int, int, int]]) -> int:
    """Uncaptured bytes between consecutive runs (never scanned)."""
    gap = 0
    for prev, nxt in zip(runs, runs[1:]):
        gap += max(0, nxt[0] - (prev[0] + prev[1]))
    return gap
