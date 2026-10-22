"""Reusable Shannon entropy computation for TLS memory dump analysis.

Provides sliding-window entropy profiling used by change_point detection
and entropy visualization. ``entropy_from_freq`` stays pure-Python (it is
handed a 256-bin list and never sees the data); ``shannon_entropy`` and the
sliding-window profile are vectorized with numpy, because both are handed
whole dumps.

Used by change_point detection and entropy visualization.
"""

import functools
import logging
import math
from typing import Callable, List, Optional, Sequence, Tuple, Union

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

from memdiver.core.entropy_profile import EntropyProfile

logger = logging.getLogger("memdiver.entropy")

# Number of window positions processed per slab in compute_entropy_profile.
# Bounds the peak per-slab histogram matrix (CHUNK_POSITIONS x 256 int64) at
# ~16 MiB regardless of dump size, mirroring the chunking style in variance.py.
# (Was 1 << 15 / ~64 MiB; reduced once the profile itself stopped being a
# Python list, so the slab scratch no longer dominates the peak. Results are
# per-row and therefore independent of the slab size.)
CHUNK_POSITIONS = 1 << 13


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


def entropy_term_lut(total: int) -> np.ndarray:
    """``lut[count] = p * math.log2(p)`` with ``p = count / total``; ``lut[0] = 0``.

    The per-bin terms of :func:`entropy_from_freq`, computed with the very
    same Python expression, so any sequential sum of them reproduces it bit
    for bit. Shared by :func:`entropy_from_freq_batch` and
    :func:`memdiver.core.entropy_window.entropy_from_window_rows`.
    """
    lut = np.zeros(total + 1, dtype=np.float64)
    for count in range(1, total + 1):
        p = count / total
        lut[count] = p * math.log2(p)
    return lut


def entropy_from_freq_batch(counts: np.ndarray, total: int) -> np.ndarray:
    """Vectorised :func:`entropy_from_freq`, bit-identical row by row.

    ``counts`` is an ``(m, 256)`` matrix of non-negative histogram rows summing
    to at most ``total``. Each row's result equals
    ``entropy_from_freq(list(row), total)`` exactly (not merely to tolerance):

    * per-count terms ``p * math.log2(p)`` come from a lookup table built with
      the very same Python expression (``math.log2``, not ``np.log2``);
    * terms are accumulated strictly left-to-right over bins 0..255 with
      ``np.cumsum`` (sequential, never pairwise), and zero bins contribute an
      exact ``0.0``, matching the ``if count > 0`` skip;
    * ``e -= t`` equals ``-(s + t)`` under sign-symmetric IEEE rounding, and a
      final ``+ 0.0`` maps the all-zero ``-0.0`` back to the reference ``0.0``.
    """
    counts = np.asarray(counts)
    rows = counts.shape[0]
    if total == 0 or rows == 0:
        return np.zeros(rows, dtype=np.float64)
    terms = entropy_term_lut(total)[counts]
    np.cumsum(terms, axis=1, out=terms)
    return -terms[:, -1] + 0.0


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
    # `byte_histogram` is the same frequency table from C loops.
    return entropy_from_byte_counts(byte_histogram(data), length)


#: Bytes histogrammed per chunk in :func:`byte_histogram`. ``bincount`` casts
#: its input to ``intp`` first, so one call over a whole 256 MiB dump
#: allocated a 2 GiB index array; chunking bounds that copy at ~2 MiB.
#: A multiple of :data:`ZERO_BLOCK_BYTES`.
HISTOGRAM_CHUNK_BYTES = 1 << 19

#: All-zero blocks of this many bytes are counted without a ``bincount``
#: (memory dumps are mostly zero pages: a 208 MiB lldb dump histograms ~15x
#: faster). Must be a multiple of 8 (blocks are tested as ``uint64`` words).
ZERO_BLOCK_BYTES = 1024


def byte_histogram(data) -> np.ndarray:
    """256-bin ``int64`` byte-value histogram of *data* (bytes-like or uint8).

    Exactly ``np.bincount(data, minlength=256)``, faster and with bounded
    scratch. Per :data:`HISTOGRAM_CHUNK_BYTES` chunk, all-zero
    :data:`ZERO_BLOCK_BYTES` blocks are only counted; the remaining blocks are
    histogrammed as byte PAIRS (one ``uint16`` bincount over 65536 bins),
    which halves the elements and spreads runs of equal bytes over more bins,
    and the pair table is folded back to bytes (each pair counts both of its
    bytes, so the fold does not depend on endianness).
    """
    values = np.ascontiguousarray(
        data if isinstance(data, np.ndarray) else np.frombuffer(data, dtype=np.uint8),
        dtype=np.uint8)
    length = values.shape[0]
    pair_counts = np.zeros(1 << 16, dtype=np.int64)
    zero_blocks = 0
    whole = length - length % ZERO_BLOCK_BYTES
    for start in range(0, whole, HISTOGRAM_CHUNK_BYTES):
        blocks = values[start:min(start + HISTOGRAM_CHUNK_BYTES, whole)].reshape(
            -1, ZERO_BLOCK_BYTES)
        nonzero = blocks.view(np.uint64).any(axis=1)
        dense_count = int(np.count_nonzero(nonzero))
        zero_blocks += nonzero.shape[0] - dense_count
        if dense_count:
            dense = blocks if dense_count == nonzero.shape[0] else blocks[nonzero]
            pair_counts += np.bincount(dense.reshape(-1).view(np.uint16), minlength=1 << 16)
    table = pair_counts.reshape(256, 256)
    counts = table.sum(axis=0) + table.sum(axis=1)
    counts[0] += zero_blocks * ZERO_BLOCK_BYTES
    if whole < length:
        counts += np.bincount(values[whole:], minlength=256)
    return counts


def entropy_from_byte_counts(counts: np.ndarray, total: int) -> float:
    """Shannon entropy (bits/byte) of a 256-bin histogram summing to *total*.

    The float formula :func:`shannon_entropy` has always used (``np.log2`` over
    the nonzero probabilities, numpy pairwise sum), shared so a histogram
    accumulated slab by slab yields the same float as one whole-buffer call.
    """
    if total == 0:
        return 0.0
    counts = np.asarray(counts)
    nonzero = counts[counts > 0].astype(np.float64)
    probabilities = nonzero / total
    return float(-(probabilities * np.log2(probabilities)).sum())


def compute_entropy_profile(
    data: bytes, window: int = 32, step: int = 1
) -> EntropyProfile:
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

    The slab sums are now evaluated by :func:`window_entropies`, which for
    windows up to :data:`SORTED_PATH_MAX_WINDOW` touches only the nonzero bins
    (O(window) instead of O(256) per position) while reproducing the 256-bin
    histogram form above bit for bit.

    For large dumps (e.g. 10 MB), use step=16 to produce ~625K sample
    points instead of ~10M.

    Args:
        data: Raw memory dump bytes.
        window: Sliding window size in bytes (default 32).
        step: Advance step in bytes (default 1).

    Returns:
        An :class:`EntropyProfile` -- a read-only sequence of
        ``(offset, entropy)`` tuples (Python ``int``/``float``), one per window
        position, backed by two numpy arrays (16 B/position instead of
        ~120 B for the former ``list`` of tuples). Use ``.as_arrays()`` for
        zero-copy ``(offsets, values)`` access. Empty when data is shorter
        than the window.
    """
    data_len = len(data)
    if data_len < window:
        return EntropyProfile.empty()

    arr = np.frombuffer(data, dtype=np.uint8)

    # Window start offsets: 0, step, 2*step, ... up to data_len - window.
    # Matches the original loop's ``pos <= data_len - window`` bound.
    offsets = np.arange(0, data_len - window + 1, step, dtype=np.int64)
    return EntropyProfile(offsets, window_entropies(arr, offsets, window))


#: Window bytes per slab of the sorted-run path in :func:`window_entropies`
#: (~45 B of scratch per window byte, so ~12 MiB per slab). Rows per slab are
#: additionally capped at :data:`CHUNK_POSITIONS`.
SORTED_SLAB_WINDOW_BYTES = 1 << 18

#: Windows above this size take the 256-bin histogram path. The sorted-run
#: path costs O(window) per position (one radix argsort), the histogram path
#: O(256 + window) of cheaper passes; measured per position on heap-like /
#: random data: window 16 ~180 vs ~400 ns, 32 ~330 vs ~450 ns, 48 even,
#: 64+ the histogram wins.
SORTED_PATH_MAX_WINDOW = 32


def _count_log_lut(window: int) -> np.ndarray:
    """``flut[c] = c * log2(c)`` (``np.log2``), ``flut[0] = 0``, c in 0..window."""
    counts_range = np.arange(1, window + 1, dtype=np.float64)
    flut = np.zeros(window + 1, dtype=np.float64)
    flut[1:] = counts_range * np.log2(counts_range)
    return flut


def _count_log_sums_histogram(rows: np.ndarray, flut: np.ndarray) -> np.ndarray:
    """Per row ``flut[hist].sum()`` over the 256-bin histogram (reference form).

    Composite key ``row*256 + byte`` -> one bincount yields all slab
    histograms; the 256-wide gather is then reduced with numpy's pairwise sum.
    """
    slab = rows.shape[0]
    row_index = np.arange(slab, dtype=np.int64)
    composite = (row_index[:, None] * 256 + rows).ravel()
    counts = np.bincount(composite, minlength=slab * 256).reshape(slab, 256)
    return flut[counts].sum(axis=1)


# numpy's pairwise float sum of a contiguous 256-element row: two halves of 128
# (``n > 128`` splits at ``n / 2``), each summed by 8 strided accumulators
# (``r[i % 8] += a[i]`` in ascending i) combined as
# ``((r0 + r1) + (r2 + r3)) + ((r4 + r5) + (r6 + r7))``. Slot of byte value v:
_PAIRWISE_SLOTS = 16


def _pairwise_slot(values: np.ndarray) -> np.ndarray:
    """Accumulator slot (``half * 8 + v % 8``) of each byte value."""
    values = values.astype(np.int64)
    return ((values >> 7) << 3) | (values & 7)


#: ``_pairwise_slot`` of every byte value, for a cheap gather.
_PAIRWISE_SLOT_OF_BYTE = _pairwise_slot(np.arange(256))


def _combine_pairwise_slots(acc: np.ndarray) -> np.ndarray:
    """The pairwise tree over ``(m, 16)`` accumulators -> ``(m,)`` row sums."""
    def half(base: int) -> np.ndarray:
        a = [acc[:, base + k] for k in range(8)]
        return ((a[0] + a[1]) + (a[2] + a[3])) + ((a[4] + a[5]) + (a[6] + a[7]))
    return half(0) + half(8)


def _count_log_sums_sorted(rows: np.ndarray, flut: np.ndarray) -> np.ndarray:
    """:func:`_count_log_sums_histogram`, bit for bit, in O(window) per row.

    Zero bins add an exact ``+0.0`` to every accumulator (all terms are
    ``>= 0``), so each pairwise accumulator equals the sequential sum of its
    NONZERO terms in ascending byte order, and only those are computed. One
    stable radix argsort of the slab by byte value groups every (byte, row)
    pair into a contiguous run in byte-major order; ``np.add.at`` (which
    applies its updates in index order) then accumulates each run's term into
    its row's slot in ascending byte order, i.e. in the reference's order.
    """
    slab, window = rows.shape
    flat = rows.ravel()
    order = np.argsort(flat, kind="stable")
    sorted_values = flat[order]
    if window & (window - 1) == 0:  # power of two (the default 32): shift
        row_of = order >> (window.bit_length() - 1)
    else:
        row_of = order // window
    boundary = np.empty(order.shape[0] + 1, dtype=bool)
    boundary[0] = boundary[-1] = True
    np.not_equal(row_of[1:], row_of[:-1], out=boundary[1:-1])
    boundary[1:-1] |= sorted_values[1:] != sorted_values[:-1]
    run_starts = np.flatnonzero(boundary)
    run_lengths = np.diff(run_starts)
    first = run_starts[:-1]
    slots = row_of[first] * _PAIRWISE_SLOTS + _PAIRWISE_SLOT_OF_BYTE[sorted_values[first]]
    acc = np.zeros(slab * _PAIRWISE_SLOTS, dtype=np.float64)
    np.add.at(acc, slots, flut[run_lengths])
    return _combine_pairwise_slots(acc.reshape(slab, _PAIRWISE_SLOTS))


@functools.lru_cache(maxsize=1)
def sorted_path_matches_numpy() -> bool:
    """Whether :func:`_count_log_sums_sorted` reproduces this numpy's reduction.

    The sorted path mirrors numpy's pairwise-summation layout; checked once per
    process on crafted rows (falls back to the histogram path if a future numpy
    ever reduces differently).
    """
    rng = np.random.default_rng(0x5EED)
    for window, high in ((32, 256), (17, 7), (200, 256), (512, 256)):
        rows = rng.integers(0, high, size=(64, window), dtype=np.uint8)
        rows[::5] = rows[::5] // 16
        flut = _count_log_lut(window)
        expected = _count_log_sums_histogram(rows, flut)
        if not np.array_equal(expected.view(np.uint64),
                              _count_log_sums_sorted(rows, flut).view(np.uint64)):
            logger.warning("sorted entropy path disabled: numpy reduction layout differs")
            return False
    return True


def window_entropies(arr: np.ndarray, offsets: np.ndarray, window: int) -> np.ndarray:
    """Entropy of the *window*-byte window at each offset of the uint8 *arr*.

    The values of :func:`compute_entropy_profile`, bit for bit, for any
    ascending in-range ``offsets`` (rows are independent of each other and
    of the slab size). Scratch is one bounded slab.
    """
    num_positions = offsets.shape[0]
    entropies = np.empty(num_positions, dtype=np.float64)
    if num_positions == 0:
        return entropies
    flut = _count_log_lut(window)
    windows = sliding_window_view(arr, window)  # (len - window + 1, window)
    log2_window = math.log2(window)
    if window <= SORTED_PATH_MAX_WINDOW and sorted_path_matches_numpy():
        sums_of = _count_log_sums_sorted
        slab_rows = max(1, min(CHUNK_POSITIONS, SORTED_SLAB_WINDOW_BYTES // window))
    else:
        sums_of = _count_log_sums_histogram
        slab_rows = CHUNK_POSITIONS
    for start in range(0, num_positions, slab_rows):
        stop = min(start + slab_rows, num_positions)
        rows = windows[offsets[start:stop]]  # (slab, window) uint8, one row/window
        entropies[start:stop] = log2_window - sums_of(rows, flut) / window
    return entropies


#: Bytes read per slab by :func:`stream_entropy_profile`.
STREAM_SLAB_BYTES = 8 * 1024 * 1024


def stream_entropy_profile(
    read: Callable[[int, int], bytes],
    size: int,
    window: int = 32,
    step: int = 1,
    slab_bytes: Optional[int] = None,
) -> Tuple[float, EntropyProfile]:
    """``(shannon_entropy(data), compute_entropy_profile(data, window, step))``
    for ``data = read(0, size)``, without ever holding *data*.

    *read(offset, length)* returns ``data[offset:offset + length]``. Bytes are
    read in slabs of *slab_bytes* (default :data:`STREAM_SLAB_BYTES`; + ``window - 1`` bytes of look-ahead so the
    windows starting in a slab are complete); each slab feeds the byte
    histogram and the profile positions that start inside it. Both results
    are bit-identical to the whole-buffer calls. Peak heap: one slab plus the
    output arrays (16 B per position).
    """
    if size <= 0:
        return 0.0, EntropyProfile.empty()
    counts = np.zeros(256, dtype=np.int64)
    offsets = (np.arange(0, size - window + 1, step, dtype=np.int64)
               if size >= window else np.empty(0, dtype=np.int64))
    values = np.empty(offsets.shape[0], dtype=np.float64)
    slab_bytes = max(1, STREAM_SLAB_BYTES if slab_bytes is None else slab_bytes)
    for start in range(0, size, slab_bytes):
        stop = min(start + slab_bytes, size)
        chunk = read(start, min(stop + window - 1, size) - start)
        arr = np.frombuffer(chunk, dtype=np.uint8)
        if arr.shape[0] < min(stop + window - 1, size) - start:
            raise ValueError(f"short read at offset {start}: {arr.shape[0]} bytes")
        counts += byte_histogram(arr[:stop - start])
        first, last = np.searchsorted(offsets, (start, stop))
        if last > first:
            values[first:last] = window_entropies(arr, offsets[first:last] - start, window)
    return entropy_from_byte_counts(counts, size), EntropyProfile(offsets, values)


#: The sliding window every entropy consumer defaults to (bytes).
DEFAULT_ENTROPY_WINDOW = 32

#: The high-entropy threshold at :data:`DEFAULT_ENTROPY_WINDOW` -- the one
#: ``EntropyScanAlgorithm.DEFAULT_THRESHOLD`` has always used ("4.5 catches
#: real crypto keys"). Single source of truth for
#: :func:`default_entropy_threshold`; ``entropy_scan`` reads it from here.
REFERENCE_ENTROPY_THRESHOLD = 4.5


def max_window_entropy(window: int) -> float:
    """Upper bound on the Shannon entropy (bits/byte) of one *window*-byte window.

    ``log2(min(window, 256))``: a window cannot hold more distinct byte values
    than it has bytes (all-distinct is the maximum, ``log2(window)``), nor more
    than 256. Exact for ``window <= 256`` and for multiples of 256; a bound
    otherwise. 0.0 for ``window <= 1``.
    """
    if window <= 1:
        return 0.0
    return math.log2(min(window, 256))


@functools.lru_cache(maxsize=64)
def random_window_entropy(window: int) -> float:
    """Expected entropy (bits/byte) of a *window*-byte window of uniform random bytes.

    Each byte value's count is ``Binomial(window, 1/256)``, so
    ``E[H] = log2(window) - (256 / window) * E[c * log2(c)]``, summed exactly
    over ``c = 0..window`` (O(window), cached). This is what real key material
    scores, and it stays well below :func:`max_window_entropy` near 256 bytes
    (7.18 vs 8.0 at 256): a window that small cannot fill 256 bins evenly.
    """
    if window <= 1:
        return 0.0
    p = 1.0 / 256
    log_p, log_q = math.log(p), math.log1p(-p)
    expected = 0.0
    for count in range(2, window + 1):
        log_prob = (math.lgamma(window + 1) - math.lgamma(count + 1)
                    - math.lgamma(window - count + 1)
                    + count * log_p + (window - count) * log_q)
        expected += math.exp(log_prob) * count * math.log2(count)
    return math.log2(window) - 256.0 * expected / window


def default_entropy_threshold(window: int = DEFAULT_ENTROPY_WINDOW) -> float:
    """Window-aware default high-entropy threshold (bits/byte).

    :data:`REFERENCE_ENTROPY_THRESHOLD` (4.5) at :data:`DEFAULT_ENTROPY_WINDOW`
    (32) -- exactly, agreeing with ``entropy_scan`` -- and the same fraction
    (~0.92) of :func:`random_window_entropy` at every other window size, so
    random key bytes pass at the same rate (~99.98%) whatever the window:
    16 -> 3.63, 64 -> 5.31, 256 -> 6.61, 1024 -> 7.20.

    Scaling by the expected entropy of random data rather than by the
    achievable maximum (:func:`max_window_entropy`) matters near 256 bytes:
    0.9 * 8.0 = 7.2 at ``window=256`` is above the 7.18 a random window scores
    on average, so two thirds of the windows of a random key would miss it.
    The former fixed default, 7.5, is unreachable for any window below 182
    bytes (``2**7.5``) -- it reported nothing at the default ``window=32``.
    """
    if window == DEFAULT_ENTROPY_WINDOW:
        return REFERENCE_ENTROPY_THRESHOLD
    fraction = REFERENCE_ENTROPY_THRESHOLD / random_window_entropy(DEFAULT_ENTROPY_WINDOW)
    return fraction * random_window_entropy(window)


def threshold_is_reachable(threshold: float, window: int) -> bool:
    """Whether some *window*-byte window can reach *threshold* bits/byte."""
    return threshold <= max_window_entropy(window)


def find_high_entropy_regions(
    profile: Union[EntropyProfile, Sequence[Tuple[int, float]]],
    threshold: Optional[float] = None,
    min_width: int = 32,
    window: int = DEFAULT_ENTROPY_WINDOW,
) -> List[Tuple[int, int, float]]:
    """Find contiguous high-entropy regions in an entropy profile.

    Scans the profile for runs of consecutive points at or above the
    threshold, then filters by minimum width.

    Args:
        profile: Output of compute_entropy_profile (an EntropyProfile) or any
            sequence of (offset, entropy) tuples, assumed sorted by offset.
        threshold: Minimum entropy (bits/byte) to qualify as
            high-entropy. ``None`` (the default) is
            :func:`default_entropy_threshold` of *window* (4.5 at the default
            32-byte window). The former fixed default, 7.5, is unreachable
            for windows below 182 bytes; explicit values keep their meaning.
        min_width: Minimum span (end - start) in bytes for a region
            to be reported. Default 32 (one AES-256 key length).
        window: The window size the profile was computed with; only used to
            derive the default threshold.

    Returns:
        List of (start_offset, end_offset, mean_entropy) tuples for
        each qualifying region. Offsets refer to the window start
        positions from the profile. The region end is exclusive: the first
        below-threshold window start, or (for a run reaching the end of the
        profile) the last window start plus the profile step.
    """
    if threshold is None:
        threshold = default_entropy_threshold(window)
    if isinstance(profile, EntropyProfile):
        return _find_high_entropy_regions_vectorized(profile, threshold, min_width)
    return _find_high_entropy_regions_iterative(profile, threshold, min_width)


def _find_high_entropy_regions_vectorized(
    profile: EntropyProfile, threshold: float, min_width: int
) -> List[Tuple[int, int, float]]:
    """Array implementation of :func:`_find_high_entropy_regions_iterative`.

    Run boundaries come from a mask diff; each run's mean uses a sequential
    ``np.cumsum`` from the run's first value, i.e. the same left-to-right
    float additions as the iterative ``entropy_sum += entropy``.
    """
    offsets, values = profile.as_arrays()
    count = offsets.shape[0]
    if count == 0:
        return []
    mask = np.zeros(count + 2, dtype=np.int8)
    mask[1:-1] = values >= threshold
    edges = np.diff(mask)
    run_starts = np.flatnonzero(edges == 1)
    run_stops = np.flatnonzero(edges == -1)  # exclusive index
    step = int(offsets[1] - offsets[0]) if count > 1 else 1
    regions: List[Tuple[int, int, float]] = []
    for first, stop in zip(run_starts.tolist(), run_stops.tolist()):
        region_start = int(offsets[first])
        region_end = int(offsets[stop]) if stop < count else int(offsets[-1]) + step
        if region_end - region_start < min_width:
            continue
        entropy_sum = float(np.cumsum(values[first:stop])[-1])
        regions.append((region_start, region_end, entropy_sum / (stop - first)))
    return regions


def _find_high_entropy_regions_iterative(
    profile: List[Tuple[int, float]],
    threshold: float = 7.5,
    min_width: int = 32,
) -> List[Tuple[int, int, float]]:
    """Pure-Python region scan for generic ``(offset, entropy)`` sequences.

    Reference semantics for :func:`find_high_entropy_regions`; used for plain
    lists (any iterable of pairs). :class:`EntropyProfile` inputs take the
    vectorised path, which reproduces this output exactly.

    Find contiguous high-entropy regions in an entropy profile.

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
