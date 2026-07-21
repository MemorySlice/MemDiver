"""Shared candidate-grid stride-snapping math.

Single source of truth for the ``(offset, size)`` grid that a region set
feeds the decryption oracle. Both :func:`engine.brute_force.iter_candidate_slices`
(the live brute-force loop) and :func:`engine.auto_floor._enumerate_candidates`
(the maximal-set enumerator) delegate here so the two can never drift.

The grid is snapped up to the first multiple of ``stride`` >= the region
start, so that when ``stride == alignment`` the candidate offsets align with
the same grid the alignment filter used to keep the region. Regions whose
first kept byte is slightly unaligned (common when the aligned filter keeps
block-edge bytes) still get their aligned interior offsets tested.
"""

from __future__ import annotations

from typing import Iterator, Sequence, Tuple


def iter_region_grid(
    r_start: int,
    r_end: int,
    key_sizes: Sequence[int],
    stride: int,
    dump_len: int,
) -> Iterator[Tuple[int, int]]:
    """Yield ``(offset, size)`` grid pairs for a single ``[r_start, r_end)`` region.

    Offsets start at the first multiple of ``stride`` >= ``r_start`` and step
    by ``stride``. A ``(offset, size)`` pair is yielded only when the window
    ``[offset, offset + size)`` fits entirely within both the region end and
    the overall ``dump_len``.
    """
    first_offset = ((r_start + stride - 1) // stride) * stride
    for offset in range(first_offset, r_end, stride):
        for size in key_sizes:
            end = offset + size
            if end > r_end or end > dump_len:
                continue
            yield offset, size
