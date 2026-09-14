"""Reusable Shannon entropy computation for TLS memory dump analysis.

Provides sliding-window entropy profiling used by change_point detection
and entropy visualization. ``entropy_from_freq`` stays pure-Python (it is
handed a 256-bin list and never sees the data); ``shannon_entropy`` and the
sliding-window profile are vectorized with numpy, because both are handed
whole dumps.

Used by change_point detection and entropy visualization.
"""

import logging
import math
from typing import List, Tuple

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

logger = logging.getLogger("memdiver.entropy")

# Number of window positions processed per slab in compute_entropy_profile.
# Bounds the peak per-slab histogram matrix (CHUNK_POSITIONS x 256 int64) at
# ~64 MiB regardless of dump size, mirroring the chunking style in variance.py.
CHUNK_POSITIONS = 1 << 15


def entropy_from_freq(freq: list, total: int) -> float:
    """Compute Shannon entropy from byte frequency counts.

    Iterates over 256 frequency bins and applies the standard formula:
        H = -sum(p * log2(p)) for each p = count / total where count > 0

    Args:
        freq: List of 256 integer counts (one per byte value).
        total: Sum of all counts (window size).

    Returns:
        Entropy in bits per byte, in range [0.0, 8.0].
        Returns 0.0 when total is zero.
    """
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of raw byte data.

    Builds a full frequency table over the input and computes entropy
    in a single pass.

    Args:
        data: Arbitrary byte sequence.

    Returns:
        Entropy in bits per byte, in range [0.0, 8.0].
        Returns 0.0 for empty input.
    """
    length = len(data)
    if length == 0:
        return 0.0
    # `for byte in data: freq[byte] += 1` is the obvious way to write this and
    # was what stood here, but it is one Python-level iteration PER BYTE holding
    # the GIL throughout. On the 220 MB corpus dump reached by
    # `GET /api/inspect/entropy?length=0` that is 220 million iterations, which
    # stalled every other request in the single-process backend for minutes.
    # `bincount` is the same frequency table from a C loop.
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    nonzero = counts[counts > 0].astype(np.float64)
    probabilities = nonzero / length
    return float(-(probabilities * np.log2(probabilities)).sum())


def compute_entropy_profile(
    data: bytes, window: int = 32, step: int = 1
) -> List[Tuple[int, float]]:
    """Sliding-window entropy profile over byte data.

    Vectorized with numpy. A ``sliding_window_view`` exposes every window as a
    row without copying; window positions are then processed in slabs of
    ``CHUNK_POSITIONS`` rows. Each slab's per-window 256-bin byte histogram is
    built in one ``np.bincount`` over a ``row * 256 + byte`` composite key, and
    entropy is evaluated in the algebraically identical but reduction-friendly
    form::

        H = log2(window) - (1 / window) * sum_b count_b * log2(count_b)

    The ``0 * log0 = 0`` convention is handled by a per-count lookup table
    (``flut[0] = 0``), which also replaces millions of ``log2`` evaluations
    with a cheap gather since counts are integers in ``[0, window]``. This
    produces the same offsets and step semantics as the previous incremental
    pure-Python implementation, matching its output to within floating-point
    tolerance.

    For large dumps (e.g. 10 MB), use step=16 to produce ~625K sample
    points instead of ~10M.

    Args:
        data: Raw memory dump bytes.
        window: Sliding window size in bytes (default 32).
        step: Advance step in bytes (default 1).

    Returns:
        List of (offset, entropy) tuples, one per window position.
        Returns an empty list when data is shorter than the window.
    """
    data_len = len(data)
    if data_len < window:
        return []

    arr = np.frombuffer(data, dtype=np.uint8)

    # Window start offsets: 0, step, 2*step, ... up to data_len - window.
    # Matches the original loop's ``pos <= data_len - window`` bound.
    offsets = np.arange(0, data_len - window + 1, step, dtype=np.int64)
    num_positions = offsets.shape[0]

    # Per-count contribution lookup: flut[c] = c * log2(c), flut[0] = 0.
    counts_range = np.arange(1, window + 1, dtype=np.float64)
    flut = np.zeros(window + 1, dtype=np.float64)
    flut[1:] = counts_range * np.log2(counts_range)

    windows = sliding_window_view(arr, window)  # (data_len - window + 1, window)
    log2_window = math.log2(window)
    entropies = np.empty(num_positions, dtype=np.float64)
    row_index = np.arange(CHUNK_POSITIONS, dtype=np.int64)

    for start in range(0, num_positions, CHUNK_POSITIONS):
        stop = min(start + CHUNK_POSITIONS, num_positions)
        rows = windows[offsets[start:stop]]  # (slab, window) uint8, one row/window
        slab = stop - start
        # Composite key row*256 + byte -> one bincount yields all slab histograms.
        composite = (row_index[:slab, None] * 256 + rows).ravel()
        counts = np.bincount(composite, minlength=slab * 256).reshape(slab, 256)
        entropy_sum = flut[counts].sum(axis=1)
        entropies[start:stop] = log2_window - entropy_sum / window

    return list(zip(offsets.tolist(), entropies.tolist()))


def find_high_entropy_regions(
    profile: List[Tuple[int, float]],
    threshold: float = 7.5,
    min_width: int = 32,
) -> List[Tuple[int, int, float]]:
    """Find contiguous high-entropy regions in an entropy profile.

    Scans the profile for runs of consecutive points at or above the
    threshold, then filters by minimum width.

    Args:
        profile: Output of compute_entropy_profile -- list of
            (offset, entropy) tuples, assumed sorted by offset.
        threshold: Minimum entropy (bits/byte) to qualify as
            high-entropy. Default 7.5 targets near-random data.
        min_width: Minimum span (end - start) in bytes for a region
            to be reported. Default 32 (one AES-256 key length).

    Returns:
        List of (start_offset, end_offset, mean_entropy) tuples for
        each qualifying region. Offsets refer to the window start
        positions from the profile.
    """
    if not profile:
        return []

    regions: List[Tuple[int, int, float]] = []
    in_region = False
    region_start = 0
    entropy_sum = 0.0
    region_count = 0

    for offset, entropy in profile:
        if entropy >= threshold:
            if not in_region:
                in_region = True
                region_start = offset
                entropy_sum = 0.0
                region_count = 0
            entropy_sum += entropy
            region_count += 1
        else:
            if in_region:
                region_end = offset
                if region_end - region_start >= min_width and region_count > 0:
                    mean_entropy = entropy_sum / region_count
                    regions.append((region_start, region_end, mean_entropy))
                in_region = False

    # Close any region that extends to the end of the profile.
    # Use the same exclusive-end convention as the interior close branch
    # above: that branch uses the first below-threshold window start as an
    # exclusive end. Here there is no following point, so advance the last
    # in-region window start by one step (inferred from the profile spacing,
    # defaulting to 1) to obtain the equivalent exclusive end.
    if in_region and region_count > 0:
        last_offset = profile[-1][0]
        step = profile[1][0] - profile[0][0] if len(profile) > 1 else 1
        region_end = last_offset + step
        if region_end - region_start >= min_width:
            mean_entropy = entropy_sum / region_count
            regions.append((region_start, region_end, mean_entropy))

    return regions
