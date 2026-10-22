"""Working-set estimates for single-dump algorithms (heap beyond the dump buffer).

Used by :meth:`algorithms.base.BaseAlgorithm.estimate_working_set`
implementations. Every formula is derived from the arrays the algorithm code
allocates and was validated with ``tracemalloc`` (see
``tests/test_algorithm_working_set.py`` and
``docs/design/large_dumps_and_memory.md``). Values are deliberately
conservative (rounded up), never tight lower bounds.

Two families:

* **Entropy profile** (``core/entropy.py`` ``compute_entropy_profile``, used by
  ``change_point``): the profile keeps an ``int64``
  offset and a ``float64`` entropy per position (16 B, ``core/entropy_profile``),
  plus one bounded slab of ``CHUNK_POSITIONS`` rows of temporaries.
* **Entropy scan** (``unknown_key/entropy_scan.py``), ``step == 1``: one
  bounded slab of temporaries (candidates are merged into regions slab by
  slab; the estimate-first scan uses ``ESTIMATE_SCAN_CHUNK_POSITIONS``-row
  slabs of W-wide scratch plus one bounded exact-entropy batch, the 256-bin
  fallback for huge windows ``CHUNK_POSITIONS``-row histogram slabs), plus ~0.5 KiB per *output region* (the ``Match``, its data slice,
  label and metadata). The region count is data-dependent (uniformly random
  bytes form ONE region; the densest input one per ``min(window)`` bytes), so
  the estimate uses the region density measured by scanning small pieces of a
  *sample* of the dump when one is given, and the densest case otherwise.
  ``step != 1`` keeps the incremental loop, which still collects one tuple
  per *candidate window*; there the sampled candidate fraction is used.
* **Structure scan** (``unknown_key/structure_scan.py``): the step-1 entropy
  overview of ONE bounded view at a time (per-worker estimate scratch, the
  pending per-position values of one read slab, the view's regions in the
  densest case), plus the capped matches -- independent of the dump size.
"""

from __future__ import annotations

import math
from typing import Iterable, List, Mapping, Optional, Sequence

import numpy as np

from memdiver.core.entropy import (
    CHUNK_POSITIONS,
    SORTED_PATH_MAX_WINDOW,
    SORTED_SLAB_WINDOW_BYTES,
    compute_entropy_profile,
)
from memdiver.core.entropy_overview import overview_workers
from memdiver.core.entropy_window import supports_estimate

#: Bytes per profile position: offsets int64 + values float64.
PROFILE_BYTES_PER_POSITION = 16
#: Per slab row in ``compute_entropy_profile``: 256-bin int64 counts (2 KiB)
#: + their ``flut[counts]`` float64 gather (2 KiB) + small row/sum temporaries.
PROFILE_SLAB_BYTES_PER_ROW = 4096 + 128
#: Per slab row in the entropy scan: int64 counts + float64 ``lut[counts]``.
SCAN_SLAB_BYTES_PER_ROW = 4096 + 128
#: Window positions per slab of the estimate-first step-1 entropy scan.
ESTIMATE_SCAN_CHUNK_POSITIONS = 1 << 16
#: Per slab position, one window size at a time: ``sliding_entropy_estimate``
#: scratch (3 uint8 sort slots + int64 argsort/prefix/scatter, counts, sums;
#: measured ~126 B).
ESTIMATE_SLAB_BYTES_PER_POSITION = 128
#: Per slab position per window size: the estimate grid + masks and, when
#: every window passes (random data), the candidate/cluster columns (~50 B).
ESTIMATE_SLAB_BYTES_PER_WINDOW_SIZE = 64
#: Window bytes per exact-entropy batch, and its scratch per window byte
#: (sorted rows, run masks, int64 run starts, float64 terms; ~60 B).
EXACT_BATCH_WINDOW_BYTES = 1 << 17
EXACT_BATCH_BYTES_PER_WINDOW_BYTE = 64
#: Per window byte per slab row: the int64 composite key (``row*256 + byte``)
#: plus the gathered uint8 row.
SLAB_BYTES_PER_WINDOW_BYTE = 9
#: Peak bytes per candidate window across scan + merge of the former one-shot
#: step-1 path (measured ~87-98 B); no longer used by ``entropy_scan_bytes``.
SCAN_BYTES_PER_CANDIDATE = 112
#: Retained bytes per output region beyond its data slice (``Match`` +
#: label + metadata dict + list slot; measured ~500 B for 32-byte windows).
SCAN_BYTES_PER_REGION = 576
#: Region-density sample: this many evenly spread pieces of the sample ...
REGION_SAMPLE_PIECES = 32
#: ... of at least this many bytes (and at least 8 windows), scanned at step 1.
REGION_SAMPLE_PIECE_BYTES = 2048
#: Absolute region-density margin, as a fraction of the densest case.
REGION_DENSITY_MARGIN = 0.005
#: Python-loop path (``step != 1``): one ``(int, float)`` tuple per hit.
SCAN_BYTES_PER_CANDIDATE_INCREMENTAL = 160
#: Safety margin on a sampled candidate fraction (relative, absolute).
SAMPLE_FRACTION_MARGIN = (1.25, 0.005)
#: Every n-th window of the sample is evaluated (keeps estimating ~0.1 s).
SAMPLE_STRIDE = 64
#: Fixed allowance for interpreter/numpy bookkeeping per call.
BASE_OVERHEAD = 1 << 20


def positions(size: int, window: int, step: int = 1) -> int:
    """Window positions ``0, step, ... <= size - window`` (0 if too small)."""
    if window <= 0 or step <= 0 or size < window:
        return 0
    return (size - window) // step + 1


def _slab_bytes(num_positions: int, window: int, per_row: int) -> int:
    rows = min(num_positions, CHUNK_POSITIONS)
    return rows * (per_row + SLAB_BYTES_PER_WINDOW_BYTE * window)


#: Sorted-run profile path (windows <= ``SORTED_PATH_MAX_WINDOW``): per window
#: byte the gathered row, int64 argsort order / row ids / run starts / slots and
#: float64 terms (worst case one run per byte, i.e. random data; ~60 B), per
#: row the 16 float64 pairwise accumulators.
SORTED_PROFILE_BYTES_PER_WINDOW_BYTE = 64
SORTED_PROFILE_BYTES_PER_ROW = 128


def _profile_slab_bytes(num_positions: int, window: int) -> int:
    """One ``window_entropies`` slab, for whichever path *window* takes."""
    if window > SORTED_PATH_MAX_WINDOW:
        return _slab_bytes(num_positions, window, PROFILE_SLAB_BYTES_PER_ROW)
    rows = min(num_positions, CHUNK_POSITIONS, max(1, SORTED_SLAB_WINDOW_BYTES // window))
    return rows * (SORTED_PROFILE_BYTES_PER_ROW
                   + SORTED_PROFILE_BYTES_PER_WINDOW_BYTE * window)


def entropy_profile_bytes(size: int, window: int, step: int,
                          per_position_extra: int = 0) -> int:
    """Peak heap of ``compute_entropy_profile`` (+ consumer bytes/position)."""
    count = positions(size, window, step)
    if count == 0:
        return 0
    per_position = PROFILE_BYTES_PER_POSITION + per_position_extra
    return (BASE_OVERHEAD + count * per_position
            + _profile_slab_bytes(count, window))


def conservative_fraction(sample_fraction: Optional[float]) -> float:
    """Upper bound for a sampled candidate fraction; worst case when unknown."""
    if sample_fraction is None:
        return 1.0
    relative, absolute = SAMPLE_FRACTION_MARGIN
    return min(1.0, sample_fraction * relative + absolute)


def entropy_scan_bytes(size: int, window_sizes: Iterable[int], step: int,
                       candidate_fractions: Optional[Mapping[int, float]] = None,
                       region_density: Optional[float] = None,
                       ) -> int:
    """Peak heap of ``EntropyScanAlgorithm.run`` for the given parameters.

    ``step == 1``: one slab + the output regions; ``region_density`` is the
    regions per byte measured on a sample (see :func:`region_sample_pieces`),
    ``None`` meaning the densest case. Other steps: one entry per candidate
    window; ``candidate_fractions`` maps a window size to the fraction of its
    windows that passed the threshold on a sample (see
    :func:`sampled_fraction`), a missing entry meaning every window.
    """
    windows = [w for w in window_sizes if positions(size, w, step) > 0]
    if not windows:
        return 0
    if step == 1:
        return BASE_OVERHEAD + _streaming_scan_bytes(size, windows, region_density)
    fractions = candidate_fractions or {}
    candidates = sum(positions(size, w, step) * conservative_fraction(fractions.get(w))
                     for w in windows)
    return BASE_OVERHEAD + math.ceil(candidates * SCAN_BYTES_PER_CANDIDATE_INCREMENTAL)


def _streaming_scan_bytes(size: int, windows: Sequence[int],
                          region_density: Optional[float]) -> int:
    """Largest slab (one window size at a time) + every output region."""
    if all(supports_estimate(w) for w in windows):
        slab = _estimated_scan_slab_bytes(size, windows)
    else:
        slab = max(_slab_bytes(positions(size, w, 1), w, SCAN_SLAB_BYTES_PER_ROW)
                   for w in windows)
    regions = size * conservative_region_density(region_density, min(windows))
    return slab + math.ceil(regions * (SCAN_BYTES_PER_REGION + max(windows)))


def _estimated_scan_slab_bytes(size: int, windows: Sequence[int]) -> int:
    """One estimate-first slab (all window sizes' grid) + one exact batch."""
    rows = min(positions(size, min(windows), 1), ESTIMATE_SCAN_CHUNK_POSITIONS)
    per_position = (ESTIMATE_SLAB_BYTES_PER_POSITION
                    + ESTIMATE_SLAB_BYTES_PER_WINDOW_SIZE * len(windows))
    return (rows * per_position
            + EXACT_BATCH_WINDOW_BYTES * EXACT_BATCH_BYTES_PER_WINDOW_BYTE)


def conservative_region_density(sample_density: Optional[float],
                                min_window: int) -> float:
    """Upper bound for a sampled regions-per-byte density.

    Clusters are disjoint and each spans at least ``min_window`` bytes, so
    ``1 / min_window`` is the densest possible case (used when unknown).
    """
    densest = 1.0 / max(min_window, 1)
    if sample_density is None:
        return densest
    relative, _ = SAMPLE_FRACTION_MARGIN
    return min(densest, sample_density * relative + REGION_DENSITY_MARGIN * densest)


def region_sample_pieces(sample: Optional[Sequence[bytes]], max_window: int,
                         pieces: int = REGION_SAMPLE_PIECES,
                         piece_bytes: int = REGION_SAMPLE_PIECE_BYTES,
                         ) -> Optional[List[bytes]]:
    """Up to *pieces* evenly spread slices of *sample* for a step-1 scan.

    A full step-1 scan still costs far more than a read per position, so
    only these small slices (not the whole sample) are scanned for the region density;
    ``None`` without a usable sample.
    """
    blocks = [block for block in (sample or []) if len(block)]
    if not blocks:
        return None
    length = max(piece_bytes, 8 * max_window)
    out: List[bytes] = []
    for block in blocks[:pieces]:
        per_block = max(1, min(pieces // len(blocks), len(block) // length))
        stride = max(len(block) - length, 0) // max(per_block - 1, 1)
        for i in range(per_block):
            start = min(i * stride, max(len(block) - length, 0))
            out.append(bytes(block[start:start + length]))
    return out


def sampled_fraction(sample: Optional[Iterable[bytes]], window: int,
                     threshold: float, stride: int = SAMPLE_STRIDE,
                     ) -> Optional[float]:
    """Fraction of *window*-byte windows in *sample* with entropy >= threshold.

    Evaluates every ``stride``-th window of each block with
    :func:`compute_entropy_profile` (blocks scanned separately, so no window
    spans two); ``None`` without a usable sample.
    """
    if sample is None:
        return None
    hits = total = 0
    for block in sample:
        profile = compute_entropy_profile(block, window=window, step=stride)
        if profile:
            hits += int(np.count_nonzero(profile.values >= threshold))
            total += len(profile)
    return hits / total if total else None


#: Structure scan: per overview region in the densest case (the run arrays'
#: 32 B + the merged ``(start, stop, mean)`` tuple and its objects; ~130 B
#: measured).
STRUCTURE_SCAN_BYTES_PER_REGION = 192
#: Structure scan: retained bytes per match (``Match``, data slice, metadata
#: with the field overlays and candidate names; ~1.3 KiB measured).
STRUCTURE_SCAN_BYTES_PER_MATCH = 2048
#: Per-position float64 values of one read slab, pending in the overview fold.
OVERVIEW_VALUE_BYTES_PER_POSITION = 8


def structure_scan_bytes(size: int, window: int, view_bytes: int, slab_bytes: int,
                         subslab_positions: int, max_matches: int,
                         region_density: Optional[float] = None,
                         dense_fraction: Optional[float] = None) -> int:
    """Peak heap of ``StructureScanAlgorithm.run`` (bounded by one view).

    Per-worker estimate scratch (only nonzero stretches are estimated, so it
    scales with the sampled *dense_fraction* of nonzero ``ZERO_BLOCK_BYTES``
    blocks) + one view's pending per-position values + the view's regions
    (*region_density* per byte, sampled; densest case one per ``window``) +
    the matches (at most one per region, capped). ``None`` = worst case.
    """
    view = min(size, view_bytes)
    count = positions(view, window)
    if count == 0:
        return 0
    workers = min(overview_workers(), count // subslab_positions + 1)
    scratch = (workers * min(subslab_positions, count) * ESTIMATE_SLAB_BYTES_PER_POSITION
               * conservative_fraction(dense_fraction))
    values = min(view, slab_bytes) * OVERVIEW_VALUE_BYTES_PER_POSITION
    density = conservative_region_density(region_density, window)
    regions = view * density * STRUCTURE_SCAN_BYTES_PER_REGION
    matches = min(max_matches, size * density) * STRUCTURE_SCAN_BYTES_PER_MATCH
    return BASE_OVERHEAD + math.ceil(scratch + values + regions + matches)


def dense_block_fraction(pieces: Optional[Sequence[bytes]],
                         block: int = 1024) -> Optional[float]:
    """Fraction of *block*-byte blocks of *pieces* holding a nonzero byte."""
    blocks = [piece[i:i + block] for piece in (pieces or [])
              for i in range(0, len(piece), block)]
    if not blocks:
        return None
    return sum(1 for b in blocks if any(b)) / len(blocks)
