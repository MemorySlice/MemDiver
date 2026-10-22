"""Full-resolution (step-1) entropy overview: display envelope + exact regions.

The Entropy tab used to plot ~200 evenly spaced points of a profile that was
itself sampled (``step = size / max_positions``), so a 32-byte key could fall
between two samples and never show. :func:`stream_entropy_overview` instead
visits EVERY window position (step 1) once, streaming the dump in bounded
slabs, and returns:

* an **envelope**: for each of ``buckets`` contiguous ranges of window starts,
  the min / max / mean entropy over ALL windows in it -- no window is skipped,
  so a single high-entropy window shows as a spike in its bucket's max;
* the **high-entropy regions** of the step-1 profile: with the default
  ``join_gap=1`` exactly ``find_high_entropy_regions(compute_entropy_profile(
  data, window, 1), threshold, min_width)`` (same starts and ends); a larger
  ``join_gap`` merges runs closer than that first (:func:`merge_close_runs`);
* the whole-input Shannon entropy and min / max / mean over all windows.

Accuracy contract
-----------------
Every window first gets :func:`~memdiver.core.entropy_window.sliding_entropy_estimate`
(the fixed-point O(1)-per-byte estimate ``entropy_scan`` uses; error below
~1e-12, guaranteed <= ``ESTIMATE_TOLERANCE`` = 1e-9). The **envelope and the
stats are computed from the estimates** (display values). **Region membership
is exact**: a window whose estimate is within ``ESTIMATE_TOLERANCE`` of the
threshold is re-evaluated with :func:`~memdiver.core.entropy.window_entropies`
(the bit-exact ``compute_entropy_profile`` float), the same estimate-first
decision ``entropy_scan`` makes. A region's ``mean_entropy`` is the mean of
its windows' estimates (within 1e-9 of the exact mean).

Memory: one read slab (``slab_bytes`` + ``window - 1``) plus, per worker, the
estimate scratch of one sub-slab (~128 B per position, ~16 MiB at the default
:data:`OVERVIEW_SUBSLAB_POSITIONS`), plus the output (O(buckets + regions)).
Sub-slabs are evaluated on a small thread pool (numpy releases the GIL in the
sort/ufunc kernels); results are folded in order, so the output does not
depend on the worker count.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

import numpy as np

from memdiver.core.entropy import (
    STREAM_SLAB_BYTES,
    ZERO_BLOCK_BYTES,
    byte_histogram,
    entropy_from_byte_counts,
    window_entropies,
)
from memdiver.core.entropy_profile import EntropyProfile
from memdiver.core.entropy_window import (
    ESTIMATE_TOLERANCE,
    sliding_entropy_estimate,
    supports_estimate,
)

#: Envelope buckets when the caller does not say (about a chart's pixel width).
DEFAULT_ENVELOPE_BUCKETS = 1500
#: Server-side ceiling on envelope buckets (response size stays O(4096)).
MAX_ENVELOPE_BUCKETS = 4096
#: Window positions per worker task (bounds the per-worker estimate scratch).
OVERVIEW_SUBSLAB_POSITIONS = 1 << 17
#: Upper bound on the worker threads of one overview.
MAX_OVERVIEW_WORKERS = 4
#: Zero gaps (in window starts) shorter than this are computed rather than
#: skipped, to keep the number of estimate calls per sub-slab small.
_MIN_ZERO_GAP_POSITIONS = 4 * ZERO_BLOCK_BYTES

Region = Tuple[int, int, float]


def overview_workers() -> int:
    """Worker threads for one overview: ``min(4, cpu_count - 1)``, at least 1.

    The same policy as the API's task pool (``api.config``), so one tab open
    never takes every core of the single-process backend.
    """
    return max(1, min(MAX_OVERVIEW_WORKERS, (os.cpu_count() or 2) - 1))


def clamp_buckets(buckets: Optional[int]) -> int:
    """*buckets* bounded to ``[1, MAX_ENVELOPE_BUCKETS]`` (``None`` = default)."""
    if buckets is None:
        return DEFAULT_ENVELOPE_BUCKETS
    return max(1, min(int(buckets), MAX_ENVELOPE_BUCKETS))


def envelope_bucket_edges(num_positions: int, buckets: int) -> np.ndarray:
    """``B + 1`` ascending window-start edges splitting ``[0, num_positions)``.

    ``B = min(buckets, num_positions)`` so every bucket holds at least one
    window; bucket ``k`` covers starts ``[edges[k], edges[k + 1])``. Sizes
    differ by at most one. Empty input -> ``[0]`` (no buckets).
    """
    if num_positions <= 0 or buckets <= 0:
        return np.zeros(1, dtype=np.int64)
    count = min(buckets, num_positions)
    return (np.arange(count + 1, dtype=np.int64) * num_positions) // count


@dataclass
class EntropyEnvelope:
    """Per-bucket min / max / mean entropy over every window start in the bucket."""

    starts: np.ndarray
    stops: np.ndarray
    minimum: np.ndarray
    maximum: np.ndarray
    mean: np.ndarray

    def __len__(self) -> int:
        return int(self.starts.shape[0])


@dataclass
class EntropyOverview:
    """Result of :func:`stream_entropy_overview` (see the module docstring)."""

    overall_entropy: float
    window: int
    positions: int
    envelope: EntropyEnvelope
    regions: List[Region] = field(default_factory=list)
    minimum: float = 0.0
    maximum: float = 0.0
    mean: float = 0.0
    #: Window starts sampled on request, and their (estimated) entropies.
    sample_offsets: np.ndarray = field(default_factory=lambda: np.empty(0, dtype=np.int64))
    sample_values: np.ndarray = field(default_factory=lambda: np.empty(0))


class _EnvelopeAccumulator:
    """Folds per-position values into fixed buckets, in any slab order."""

    def __init__(self, edges: np.ndarray) -> None:
        self.edges = edges
        buckets = edges.shape[0] - 1
        self.minimum = np.full(buckets, np.inf)
        self.maximum = np.full(buckets, -np.inf)
        self.total = np.zeros(buckets)
        self.count = np.zeros(buckets, dtype=np.int64)

    def add(self, first: int, values: np.ndarray) -> None:
        """Values of window starts ``[first, first + len(values))``."""
        if values.shape[0] == 0:
            return
        last = first + values.shape[0]
        lo = int(np.searchsorted(self.edges, first, side="right")) - 1
        hi = int(np.searchsorted(self.edges, last - 1, side="right")) - 1
        cuts = np.maximum(self.edges[lo:hi + 1] - first, 0)
        span = slice(lo, hi + 1)
        np.minimum(self.minimum[span], np.minimum.reduceat(values, cuts), out=self.minimum[span])
        np.maximum(self.maximum[span], np.maximum.reduceat(values, cuts), out=self.maximum[span])
        self.total[span] += np.add.reduceat(values, cuts)
        self.count[span] += np.diff(np.append(cuts, values.shape[0]))

    def finish(self) -> EntropyEnvelope:
        with np.errstate(invalid="ignore", divide="ignore"):
            mean = np.where(self.count > 0, self.total / np.maximum(self.count, 1), 0.0)
        empty = self.count == 0
        return EntropyEnvelope(
            starts=self.edges[:-1].copy(), stops=self.edges[1:].copy(),
            minimum=np.where(empty, 0.0, self.minimum),
            maximum=np.where(empty, 0.0, self.maximum), mean=mean)


def envelope_from_profile(profile: EntropyProfile, num_positions: int,
                          buckets: int = DEFAULT_ENVELOPE_BUCKETS) -> EntropyEnvelope:
    """Envelope of a (sampled) *profile* over the buckets of ``[0, num_positions)``.

    Same bucket edges as :func:`stream_entropy_overview`, but only the
    profile's own points are seen, so a sampled profile can miss windows
    between its points; buckets without a point are left out.
    """
    edges = envelope_bucket_edges(num_positions, clamp_buckets(buckets))
    offsets, values = profile.as_arrays()
    if edges.shape[0] < 2 or offsets.shape[0] == 0:
        empty = np.empty(0)
        return EntropyEnvelope(empty.astype(np.int64), empty.astype(np.int64),
                               empty, empty, empty)
    bucket = np.searchsorted(edges, offsets, side="right") - 1
    present, first = np.unique(bucket, return_index=True)
    return EntropyEnvelope(
        starts=edges[present], stops=edges[present + 1],
        minimum=np.minimum.reduceat(values, first),
        maximum=np.maximum.reduceat(values, first),
        mean=np.add.reduceat(values, first) / np.diff(np.append(first, values.shape[0])))


@dataclass
class _SubslabResult:
    """What one worker reports for window starts ``[first, first + count)``."""

    first: int
    values: np.ndarray        # estimate per window start
    run_starts: np.ndarray    # local, ascending: runs of windows >= threshold
    run_stops: np.ndarray     # local, exclusive
    run_sums: np.ndarray      # sum of the run's estimates


def _exact_mask(arr: np.ndarray, estimates: np.ndarray, window: int,
                threshold: float) -> np.ndarray:
    """``entropy >= threshold`` per window, exact (estimate-first, like entropy_scan)."""
    mask = estimates >= threshold + ESTIMATE_TOLERANCE
    undecided = np.flatnonzero(~mask & (estimates >= threshold - ESTIMATE_TOLERANCE))
    if undecided.size:
        mask[undecided] = window_entropies(arr, undecided.astype(np.int64), window) >= threshold
    return mask


def _dense_position_ranges(arr: np.ndarray, window: int,
                           block: int = ZERO_BLOCK_BYTES) -> List[Tuple[int, int]]:
    """Window-start ranges whose windows touch a nonzero byte of *arr*.

    Every other window lies inside zero bytes and has entropy exactly 0.0
    (in the estimate and in the exact float alike). Nonzero bytes are found
    per *block*; ranges closer than :data:`_MIN_ZERO_GAP_POSITIONS` are merged
    so the per-range overhead stays small.
    """
    positions = arr.shape[0] - window + 1
    whole = arr.shape[0] - arr.shape[0] % block
    dense = arr[:whole].reshape(-1, block).view(np.uint64).any(axis=1)
    if whole < arr.shape[0]:
        dense = np.append(dense, bool(arr[whole:].any()))
    starts = np.flatnonzero(dense) * block
    if starts.size == 0:
        return []
    ranges: List[Tuple[int, int]] = []
    for byte_start in starts.tolist():
        first = max(0, byte_start - window + 1)
        stop = min(byte_start + block, positions)
        if ranges and first - ranges[-1][1] < _MIN_ZERO_GAP_POSITIONS:
            ranges[-1] = (ranges[-1][0], stop)
        elif first < stop:
            ranges.append((first, stop))
    return ranges


def _window_values(arr: np.ndarray, window: int) -> np.ndarray:
    """Per-window entropy of every window of *arr* (estimate, or exact fallback).

    Windows inside zero blocks are 0.0 without being computed.
    """
    values = np.zeros(arr.shape[0] - window + 1)
    for first, stop in _dense_position_ranges(arr, window):
        segment = arr[first:stop + window - 1]
        if supports_estimate(window):
            values[first:stop] = sliding_entropy_estimate(segment, window)
        else:
            values[first:stop] = window_entropies(
                segment, np.arange(stop - first, dtype=np.int64), window)
    return values


def _evaluate_subslab(arr: np.ndarray, first: int, window: int,
                      threshold: float) -> _SubslabResult:
    """Estimates + exact above-threshold runs of the windows of *arr*."""
    values = _window_values(arr, window)
    if supports_estimate(window):
        mask = _exact_mask(arr, values, window, threshold)
    else:  # values are already exact
        mask = values >= threshold
    edges = np.diff(np.concatenate(([0], mask.view(np.int8), [0])))
    starts = np.flatnonzero(edges == 1)
    stops = np.flatnonzero(edges == -1)
    # Runs are separated by >= 1 below-threshold window, so the interleaved
    # cuts are strictly ascending; the even segments are the runs.
    cuts = np.column_stack((starts, stops)).ravel()
    sums = (np.add.reduceat(np.append(values, 0.0), cuts)[::2]
            if starts.size else np.empty(0))
    return _SubslabResult(first, values, starts, stops, sums)


def merge_close_runs(starts: np.ndarray, stops: np.ndarray, sums: np.ndarray,
                     counts: np.ndarray, join_gap: int, min_width: int) -> List[Region]:
    """Runs of above-threshold windows -> ``(start, stop, mean)`` regions.

    Runs (ascending, ``stop`` exclusive, in window-start space) are joined
    when the next one starts less than ``max(join_gap, 1)`` starts after the
    previous stop -- ``1`` joins only touching runs (a run split across two
    slabs), which reproduces :func:`~memdiver.core.entropy.find_high_entropy_regions`
    exactly; ``window - step`` joins runs whose windows' BYTES overlap, so a
    few windows dipping just below the threshold inside a long random buffer
    (~2 in 10000 at window 32) do not shred it into thousands of regions.
    Joined regions keep spans ``>= min_width``; the mean is over the windows
    of the runs (``sums / counts``), not over the gaps.
    """
    if starts.shape[0] == 0:
        return []
    head = np.ones(starts.shape[0], dtype=bool)
    head[1:] = (starts[1:] - stops[:-1]) >= max(int(join_gap), 1)
    heads = np.flatnonzero(head)
    tails = np.append(heads[1:] - 1, starts.shape[0] - 1)
    first, last = starts[heads], stops[tails]
    means = np.add.reduceat(sums, heads) / np.add.reduceat(counts, heads)
    keep = (last - first) >= min_width
    return list(zip(first[keep].tolist(), last[keep].tolist(), means[keep].tolist()))


class _RegionCollector:
    """Collects per-sub-slab runs (in start order) for :func:`merge_close_runs`.

    Runs are kept as arrays (32 B per run), so a dump with many short
    high-entropy runs never builds a Python object per run before merging.
    """

    def __init__(self, min_width: int, join_gap: int) -> None:
        self.min_width = min_width
        self.join_gap = join_gap
        self._parts: List[Tuple[np.ndarray, np.ndarray, np.ndarray]] = []

    def feed(self, result: _SubslabResult) -> None:
        if result.run_starts.size:
            self._parts.append((result.run_starts + result.first,
                                result.run_stops + result.first, result.run_sums))

    def finish(self) -> List[Region]:
        if not self._parts:
            return []
        starts, stops, sums = (np.concatenate(column) for column in zip(*self._parts))
        return merge_close_runs(starts, stops, sums, (stops - starts).astype(np.float64),
                                self.join_gap, self.min_width)


def _subslab_ranges(first: int, last: int, positions_per_task: int):
    for start in range(first, last, positions_per_task):
        yield start, min(start + positions_per_task, last)


def _read_slabs(read: Callable[[int, int], bytes], size: int, window: int,
                slab_bytes: int):
    """``(start, stop, arr)`` per slab; *arr* has ``window - 1`` look-ahead bytes."""
    for start in range(0, max(size, 0), slab_bytes):
        stop = min(start + slab_bytes, size)
        want = min(stop + window - 1, size) - start
        arr = np.frombuffer(read(start, want), dtype=np.uint8)
        if arr.shape[0] < want:
            raise ValueError(f"short read at offset {start}: {arr.shape[0]} bytes")
        yield start, stop, arr


class _OverviewFold:
    """Folds sub-slab results, in start order, into an :class:`EntropyOverview`."""

    def __init__(self, positions: int, window: int, buckets: int, min_width: int,
                 sample_positions: Optional[np.ndarray], join_gap: int = 1) -> None:
        self.positions = positions
        self.window = window
        self.envelope = _EnvelopeAccumulator(envelope_bucket_edges(positions, buckets))
        self.regions = _RegionCollector(min_width, join_gap)
        self.counts = np.zeros(256, dtype=np.int64)
        self.stats = [np.inf, -np.inf, 0.0]
        self.sample_positions = (np.empty(0, dtype=np.int64) if sample_positions is None
                                 else np.asarray(sample_positions, dtype=np.int64))
        self.sample_values = np.zeros(self.sample_positions.shape[0])

    def add(self, result: _SubslabResult) -> None:
        values = result.values
        self.envelope.add(result.first, values)
        self.regions.feed(result)
        self.stats[0] = min(self.stats[0], float(values.min()))
        self.stats[1] = max(self.stats[1], float(values.max()))
        self.stats[2] += float(values.sum())
        lo, hi = np.searchsorted(self.sample_positions,
                                 (result.first, result.first + values.shape[0]))
        self.sample_values[lo:hi] = values[self.sample_positions[lo:hi] - result.first]

    def finish(self, size: int) -> EntropyOverview:
        overall = entropy_from_byte_counts(self.counts, size) if size > 0 else 0.0
        if self.positions == 0:
            return EntropyOverview(overall, self.window, 0, self.envelope.finish())
        return EntropyOverview(
            overall_entropy=overall, window=self.window, positions=self.positions,
            envelope=self.envelope.finish(), regions=self.regions.finish(),
            minimum=self.stats[0], maximum=self.stats[1],
            mean=self.stats[2] / self.positions,
            sample_offsets=self.sample_positions, sample_values=self.sample_values)


def stream_entropy_overview(
    read: Callable[[int, int], bytes],
    size: int,
    window: int,
    threshold: float,
    min_width: int = 32,
    buckets: int = DEFAULT_ENVELOPE_BUCKETS,
    slab_bytes: Optional[int] = None,
    workers: Optional[int] = None,
    subslab_positions: int = OVERVIEW_SUBSLAB_POSITIONS,
    sample_positions: Optional[np.ndarray] = None,
    join_gap: int = 1,
) -> EntropyOverview:
    """Step-1 overview of ``data = read(0, size)`` without holding *data*.

    *read(offset, length)* returns ``data[offset:offset + length]``. See the
    module docstring for what is returned and how exact each part is.
    *min_width* has :func:`~memdiver.core.entropy.find_high_entropy_regions`
    semantics (span of window starts, ``end`` exclusive); *join_gap* is
    :func:`merge_close_runs`'s (1 = no merging). *sample_positions*
    (ascending, in ``[0, positions)``) are window starts whose (estimated)
    entropy is also returned, for point samples of the profile.
    """
    window = max(1, int(window))
    positions = max(0, size - window + 1)
    fold = _OverviewFold(positions, window, clamp_buckets(buckets), min_width,
                         sample_positions, join_gap)
    slab_bytes = max(window, STREAM_SLAB_BYTES if slab_bytes is None else slab_bytes)
    tasks = max(1, int(subslab_positions))
    with ThreadPoolExecutor(max_workers=workers or overview_workers()) as pool:
        for start, stop, arr in _read_slabs(read, size, window, slab_bytes):
            fold.counts += byte_histogram(arr[:stop - start])
            jobs = list(_subslab_ranges(start, min(stop, positions), tasks))
            for result in pool.map(lambda job, arr=arr, start=start: _evaluate_subslab(
                    arr[job[0] - start:job[1] - start + window - 1], job[0],
                    window, threshold), jobs):
                fold.add(result)
    return fold.finish(size)
