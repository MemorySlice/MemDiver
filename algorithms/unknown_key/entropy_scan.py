"""Shannon entropy sliding window algorithm for detecting high-entropy key material.

The step-1 scan is vectorised: per-window histograms come from a numpy
``bincount`` over a ``sliding_window_view`` in bounded slabs, entropies from
:func:`entropy_from_freq_batch` (bit-identical to ``entropy_from_freq``), and
overlapping candidates are merged into regions slab by slab (the open region
is carried across slab boundaries), so peak memory is one slab plus the output
regions -- never one entry per window above threshold -- and a ``Match``
(with its data slice) is only built for each surviving region. ``dump_data`` may be any buffer (``bytes``, ``bytearray``,
``mmap``, ``memoryview``).

The default step-1 path (:meth:`EntropyScanAlgorithm._scan_and_merge_estimated`,
~20x faster) avoids the 256-bin work: a fixed-point sliding estimate
(:mod:`memdiver.core.entropy_window`, error <= ``ESTIMATE_TOLERANCE``)
settles every window that is not within the tolerance of the threshold or of
its cluster's best, and only those few get the exact float. Output (offsets,
lengths, entropy floats, merge winners) is bit-identical to the histogram
path, which stays as the fallback for windows too large for the estimate.
"""

from typing import List, Optional, Sequence, Tuple

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

from memdiver.algorithms import working_set
from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from memdiver.core.constants import UNKNOWN_KEY
from memdiver.core.entropy import (
    REFERENCE_ENTROPY_THRESHOLD,
    entropy_from_freq,
    entropy_from_freq_batch,
)
from memdiver.core.entropy_window import (
    ESTIMATE_TOLERANCE,
    entropy_from_window_rows,
    sliding_entropy_estimate,
    supports_estimate,
)

# Window positions per histogram slab (slab x 256 int64 + float64 scratch,
# ~32 MiB peak), independent of dump size.
_SCAN_CHUNK_POSITIONS = 1 << 13

# Window positions per slab of the estimate-first scan
# (:meth:`EntropyScanAlgorithm._scan_and_merge_estimated`): ~128 B scratch per
# position (one window size at a time) + ~64 B per position per window size
# (estimate grid, candidate columns); ~12 MiB measured peak for [32, 48].
_ESTIMATE_CHUNK_POSITIONS = working_set.ESTIMATE_SCAN_CHUNK_POSITIONS
# Window bytes per exact-entropy batch: bounds the sorted-row scratch of
# ``entropy_from_window_rows`` (~60 B per window byte, ~8 MiB) on inputs
# where most windows tie for a cluster maximum (e.g. a repeated key).
_EXACT_CHUNK_BYTES = working_set.EXACT_BATCH_WINDOW_BYTES
# Up to this window size the sorted-row exact entropy is cheaper than the
# 256-bin histogram (``np.sort`` per row grows with the row length).
_SORTED_EXACT_MAX_WINDOW = 128

# (offsets int64, lengths int64, entropies float64) candidate columns.
Candidates = Tuple[np.ndarray, np.ndarray, np.ndarray]


class EntropyScanAlgorithm(BaseAlgorithm):
    """Detect high-entropy regions that likely contain cryptographic key material."""

    name = "entropy_scan"
    description = "Shannon entropy sliding window scan for key-sized regions"
    mode = UNKNOWN_KEY

    DEFAULT_WINDOW_SIZES = [32, 48]
    # 7.0 requires near-perfect randomness; 4.5 catches real crypto keys. Shared
    # with the Entropy tab's window-aware default (core.entropy).
    DEFAULT_THRESHOLD = REFERENCE_ENTROPY_THRESHOLD
    DEFAULT_STEP = 1

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        window_sizes = context.extra.get("window_sizes", self.DEFAULT_WINDOW_SIZES)
        threshold = context.extra.get("entropy_threshold", self.DEFAULT_THRESHOLD)
        step = context.extra.get("step", self.DEFAULT_STEP)

        offsets, lengths, entropies = self._scan_and_merge(
            dump_data, window_sizes, threshold, step)
        matches = self._build_matches(dump_data, offsets, lengths, entropies)

        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=min(len(matches) / 10.0, 1.0) if matches else 0.0,
            matches=matches,
            metadata={
                "window_sizes": window_sizes,
                "threshold": threshold,
                "total_candidates": len(matches),
            },
        )

    def estimate_working_set(self, size: int,
                             context: Optional[AnalysisContext] = None,
                             sample: Optional[Sequence[bytes]] = None) -> int:
        """Slab temporaries + output regions (see ``working_set``).

        ``step == 1``: the region density is measured by scanning small
        evenly spread pieces of *sample*; without a sample the densest case
        (one region per smallest window) is assumed. Other steps keep the
        per-candidate estimate, with the candidate fraction per window size
        measured on every 64th window of *sample* (worst case: every window).
        """
        extra = context.extra if context is not None else {}
        window_sizes = extra.get("window_sizes", self.DEFAULT_WINDOW_SIZES)
        threshold = extra.get("entropy_threshold", self.DEFAULT_THRESHOLD)
        step = extra.get("step", self.DEFAULT_STEP)
        if step == 1:
            density = self._sampled_region_density(sample, window_sizes, threshold)
            return working_set.entropy_scan_bytes(
                size, window_sizes, step, region_density=density)
        fractions = {}
        for window in window_sizes:
            fraction = working_set.sampled_fraction(sample, window, threshold)
            if fraction is not None:
                fractions[window] = fraction
        return working_set.entropy_scan_bytes(size, window_sizes, step, fractions)

    def _sampled_region_density(self, sample: Optional[Sequence[bytes]],
                                window_sizes: Sequence[int],
                                threshold: float) -> Optional[float]:
        """Merged regions per byte over :func:`working_set.region_sample_pieces`."""
        if not window_sizes or min(window_sizes) <= 0:
            return None
        pieces = working_set.region_sample_pieces(sample, max(window_sizes))
        if not pieces:
            return None
        regions = sum(len(self._scan_and_merge(piece, window_sizes, threshold, 1)[0])
                      for piece in pieces)
        return regions / sum(len(piece) for piece in pieces)

    def _scan_and_merge(self, data, window_sizes: Sequence[int],
                        threshold: float, step: int) -> Candidates:
        """Merged regions for all *window_sizes* (columns of the survivors).

        ``step == 1`` streams slabs through :class:`_RegionMerger`; any other
        step (or a non-positive window) collects the incremental columns and
        merges them at once, as before.
        """
        if step == 1 and all(w > 0 for w in window_sizes):
            if all(supports_estimate(w) for w in window_sizes):
                return self._scan_and_merge_estimated(data, window_sizes, threshold)
            return self._scan_and_merge_streaming(data, window_sizes, threshold)
        columns = [
            self._scan_entropy_arrays(data, window_size, threshold, step)
            for window_size in window_sizes
        ]
        return self._merge_overlapping_arrays(columns)

    @staticmethod
    def _scan_and_merge_streaming(data, window_sizes: Sequence[int],
                                  threshold: float) -> Candidates:
        """Step-1 scan of every window size per offset slab, merged on the fly.

        Slab ``[start, start + chunk)`` holds the windows of every size that
        START there, so feeding the slabs in order hands the merger the
        candidates in the same global ``(offset, -length)`` order as the
        one-shot merge; within a slab the columns are concatenated in
        ``window_sizes`` order, preserving its stable tie-breaking.
        """
        merger = _RegionMerger()
        if len(data) == 0:
            return merger.finish()
        values = np.frombuffer(data, dtype=np.uint8)
        views = [(w, sliding_window_view(values, w))
                 for w in window_sizes if len(data) >= w]
        if not views:
            return merger.finish()
        chunk = _SCAN_CHUNK_POSITIONS
        row_keys = _row_keys(chunk)
        num_positions = max(view.shape[0] for _, view in views)
        for start in range(0, num_positions, chunk):
            parts = [_slab_hits(view, start, chunk, w, threshold, row_keys)
                     for w, view in views]
            merger.feed(*(np.concatenate(column) for column in zip(*parts)))
        return merger.finish()

    @staticmethod
    def _scan_and_merge_estimated(data, window_sizes: Sequence[int],
                                  threshold: float) -> Candidates:
        """Same regions as :meth:`_scan_and_merge_streaming`, estimate-first.

        Per slab, every window gets a :func:`sliding_entropy_estimate` (error
        <= ``ESTIMATE_TOLERANCE``); exact entropies are computed only where
        the estimate cannot decide: windows within the tolerance of the
        threshold, and per slab-local cluster the windows within twice the
        tolerance of the cluster's best estimate (every other window is
        strictly beaten by a window of its own cluster, so it can never be a
        winner). See :func:`_estimated_slab_regions`.
        """
        merger = _RegionMerger()
        sizes = [w for w in window_sizes if len(data) >= w]
        if len(data) == 0 or not sizes:
            return merger.finish()
        values = np.frombuffer(data, dtype=np.uint8)
        # Columns by descending length (stable for duplicates): row-major
        # order of a (position, size) grid is then the stable
        # ``(offset, -length)`` order of the one-shot merge.
        sizes = np.array(sorted(sizes, key=lambda w: -w), dtype=np.int64)
        num_positions = len(data) - int(sizes.min()) + 1
        chunk = _ESTIMATE_CHUNK_POSITIONS
        for start in range(0, num_positions, chunk):
            stop = min(start + chunk, num_positions)
            merger.feed_sorted(*_estimated_slab_regions(values, start, stop,
                                                        sizes, threshold))
        return merger.finish()

    def _scan_entropy(self, data: bytes, window_size: int, threshold: float,
                      step: int) -> list:
        """One ``Match`` per window with entropy >= threshold (unmerged)."""
        offsets, lengths, entropies = self._scan_entropy_arrays(
            data, window_size, threshold, step)
        return self._build_matches(data, offsets, lengths, entropies)

    def _scan_entropy_arrays(self, data, window_size: int, threshold: float,
                             step: int) -> Candidates:
        """Candidate windows as arrays; same windows/values as ``_scan_entropy``.

        ``step == 1`` (the default) is vectorised. Any other step keeps the
        original incremental loop: that loop only slides the histogram by one
        byte per *visited* position, so for ``step > 1`` its counts drift from
        the true window contents, and reproducing it exactly is only possible
        by running it.
        """
        if step == 1 and window_size > 0:
            return self._scan_entropy_vectorized(data, window_size, threshold)
        hits = self._scan_entropy_incremental(data, window_size, threshold, step)
        return (
            np.fromiter((pos for pos, _ in hits), dtype=np.int64, count=len(hits)),
            np.full(len(hits), window_size, dtype=np.int64),
            np.fromiter((ent for _, ent in hits), dtype=np.float64, count=len(hits)),
        )

    @staticmethod
    def _scan_entropy_vectorized(data, window_size: int,
                                 threshold: float) -> Candidates:
        """Step-1 sliding-window scan without per-window Python work."""
        empty = np.empty(0, dtype=np.int64)
        if window_size <= 0 or len(data) < window_size:
            return empty, empty.copy(), np.empty(0, dtype=np.float64)
        windows = sliding_window_view(np.frombuffer(data, dtype=np.uint8), window_size)
        chunk = _SCAN_CHUNK_POSITIONS
        row_keys = _row_keys(chunk)
        parts = [_slab_hits(windows, start, chunk, window_size, threshold, row_keys)
                 for start in range(0, windows.shape[0], chunk)]
        return tuple(np.concatenate(column) for column in zip(*parts))

    @staticmethod
    def _build_matches(data, offsets: np.ndarray, lengths: np.ndarray,
                       entropies: np.ndarray) -> list:
        """Materialise ``Match`` objects exactly as the per-window loop did."""
        matches = []
        for pos, size, entropy in zip(offsets.tolist(), lengths.tolist(),
                                      entropies.tolist()):
            matches.append(Match(
                offset=pos,
                length=size,
                confidence=entropy / 8.0,
                label=f"high_entropy_{size}B",
                data=data[pos:pos + size],
                metadata={"entropy": round(entropy, 4), "window_size": size},
            ))
        return matches

    @staticmethod
    def _merge_overlapping_arrays(columns: List[Candidates]) -> Candidates:
        """Array form of :meth:`_merge_overlapping`; identical survivors.

        Same stable ``(offset, -length)`` ordering, same clusters (a candidate
        joins the current cluster iff it starts before the running max end),
        and per cluster the first candidate with the lexicographically largest
        ``(confidence, length)`` -- what the strict ``>`` replacement keeps.
        """
        offsets = np.concatenate([c[0] for c in columns]) if columns else np.empty(0, np.int64)
        if offsets.size == 0:
            empty = np.empty(0, dtype=np.int64)
            return empty, empty.copy(), np.empty(0, dtype=np.float64)
        lengths = np.concatenate([c[1] for c in columns])
        entropies = np.concatenate([c[2] for c in columns])
        order = np.lexsort((-lengths, offsets))  # stable, like list.sort
        offsets, lengths, entropies = offsets[order], lengths[order], entropies[order]
        keep, _ = _cluster_winners(offsets, lengths, entropies, offsets + lengths)
        return offsets[keep], lengths[keep], entropies[keep]

    @staticmethod
    def _scan_entropy_incremental(data: bytes, window_size: int,
                                  threshold: float,
                                  step: int) -> List[Tuple[int, float]]:
        """Original per-byte incremental scan (used for ``step != 1``).

        Returns ``(offset, entropy)`` for each window with entropy >= threshold;
        the histogram update is kept verbatim from the original implementation.
        """
        hits: List[Tuple[int, float]] = []
        if len(data) < window_size:
            return hits

        freq = [0] * 256
        for i in range(window_size):
            freq[data[i]] += 1

        for pos in range(0, len(data) - window_size + 1, step):
            if pos > 0:
                freq[data[pos - 1]] -= 1
                freq[data[pos + window_size - 1]] += 1

            entropy = entropy_from_freq(freq, window_size)
            if entropy >= threshold:
                hits.append((pos, entropy))

        return hits

    @staticmethod
    def _merge_overlapping(matches: list) -> list:
        # Sibling interval-merge: differential.DifferentialAnalyzer._merge_nearby_runs.
        # Deliberately NOT shared -- the semantics diverge on both axes:
        #   * merge DECISION: here strict overlap only (gap tolerance 0, tracked
        #     via a running cluster_end); there gaps up to MAX_GAP_BYTES are
        #     bridged unless the gap contains an invariant byte.
        #   * merge ACTION: here the higher-confidence (then wider) Match is KEPT
        #     with its original bounds; there the (start, end) bounds are FUSED
        #     into a spanning interval.
        # Unifying would require a behaviour-changing merge, so they stay separate.
        if not matches:
            return []
        matches.sort(key=lambda m: (m.offset, -m.length))
        merged = [matches[0]]
        # ``cluster_end`` tracks the furthest right edge of the current run of
        # overlapping matches. Comparing against this (rather than only
        # ``merged[-1]``) ensures a later match that overlaps an earlier kept
        # interval is still merged even when it does not overlap the most
        # recently kept one, which previously inflated the match count.
        cluster_end = merged[0].offset + merged[0].length
        for m in matches[1:]:
            if m.offset < cluster_end:
                kept = merged[-1]
                # Per existing intent: keep the higher-confidence interval; on a
                # confidence tie keep the wider one. The match's own
                # offset/length/data are preserved unchanged (no synthesizing).
                if (m.confidence, m.length) > (kept.confidence, kept.length):
                    merged[-1] = m
                cluster_end = max(cluster_end, m.offset + m.length)
            else:
                merged.append(m)
                cluster_end = m.offset + m.length
        return merged


def _row_keys(chunk: int) -> np.ndarray:
    """``row * 256`` per slab row (column vector) for the composite bincount."""
    return np.arange(chunk, dtype=np.int64)[:, None] * 256


def _slab_hits(windows: np.ndarray, start: int, chunk: int, window_size: int,
               threshold: float, row_keys: np.ndarray) -> Candidates:
    """Windows starting in ``[start, start + chunk)`` with entropy >= threshold."""
    rows = windows[start:start + chunk]
    slab = rows.shape[0]
    composite = (row_keys[:slab] + rows).ravel()
    counts = np.bincount(composite, minlength=slab * 256).reshape(slab, 256)
    entropies = entropy_from_freq_batch(counts, window_size)
    hits = np.flatnonzero(entropies >= threshold)
    offsets = (hits + start).astype(np.int64, copy=False)
    return (offsets, np.full(offsets.shape[0], window_size, dtype=np.int64),
            entropies[hits])


def _exact_entropies(values: np.ndarray, offsets: np.ndarray,
                     lengths: np.ndarray) -> np.ndarray:
    """Exact (``entropy_from_freq_batch``-identical) entropy per window."""
    result = np.empty(offsets.shape[0], dtype=np.float64)
    for window in np.unique(lengths).tolist():
        selected = np.flatnonzero(lengths == window)
        windows = sliding_window_view(values, window)
        batch_rows = max(1, _EXACT_CHUNK_BYTES // window)
        for first in range(0, selected.shape[0], batch_rows):
            batch = selected[first:first + batch_rows]
            result[batch] = _exact_batch(windows[offsets[batch]], window)
    return result


def _exact_batch(rows: np.ndarray, window: int) -> np.ndarray:
    """``entropy_from_freq_batch`` of the rows, by the cheaper exact route."""
    if window <= _SORTED_EXACT_MAX_WINDOW:
        return entropy_from_window_rows(rows, window)
    keys = _row_keys(rows.shape[0]) + rows
    counts = np.bincount(keys.ravel(), minlength=rows.shape[0] * 256)
    return entropy_from_freq_batch(counts.reshape(rows.shape[0], 256), window)


def _slab_estimates(values: np.ndarray, start: int, stop: int,
                    sizes: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """``(stop - start, len(sizes))`` estimates and the mask of real windows."""
    estimates = np.zeros((stop - start, sizes.shape[0]), dtype=np.float64)
    exists = np.zeros(estimates.shape, dtype=bool)
    for column, window in enumerate(sizes.tolist()):
        count = min(stop, values.shape[0] - window + 1) - start
        if count > 0:
            segment = values[start:start + count + window - 1]
            estimates[:count, column] = sliding_entropy_estimate(segment, window)
            exists[:count, column] = True
    return estimates, exists


def _slab_candidates(values: np.ndarray, start: int, estimates: np.ndarray,
                     exists: np.ndarray, sizes: np.ndarray,
                     threshold: float) -> Tuple[np.ndarray, np.ndarray]:
    """Exact ``entropy >= threshold`` mask over the slab grid.

    Estimates at least the tolerance above the threshold pass, those more
    than the tolerance below fail; only the band in between is computed.
    """
    candidate = exists & (estimates >= threshold + ESTIMATE_TOLERANCE)
    undecided = exists & ~candidate & (estimates >= threshold - ESTIMATE_TOLERANCE)
    rows, columns = np.nonzero(undecided)
    if rows.size:
        exact = _exact_entropies(values, rows + start, sizes[columns])
        candidate[rows, columns] = exact >= threshold
    return np.nonzero(candidate)


def _estimated_slab_regions(values: np.ndarray, start: int, stop: int,
                            sizes: np.ndarray, threshold: float):
    """Merger input for windows starting in ``[start, stop)``, sorted.

    Candidates in ``(offset, -length)`` order are grouped into slab-local
    clusters (each a subset of one global cluster). Only each cluster's head
    (it decides joins; its end is the cluster's running end) and its
    *potential winners* (estimate within ``2 * tolerance`` of the cluster's
    best estimate, exact entropies) are passed on; the head gets ``-inf``
    unless it is a potential winner itself. Every dropped window is strictly
    beaten by a potential winner of its own cluster, so the merged winners --
    and their exact values -- are those of the full candidate list.
    """
    estimates, exists = _slab_estimates(values, start, stop, sizes)
    rows, columns = _slab_candidates(values, start, estimates, exists, sizes, threshold)
    if rows.size == 0:
        empty = np.empty(0, dtype=np.int64)
        return empty, empty.copy(), np.empty(0, dtype=np.float64), empty.copy()
    offsets = rows.astype(np.int64) + start
    lengths = sizes[columns]
    approx = estimates[rows, columns]
    running_end = np.maximum.accumulate(offsets + lengths)
    head = np.empty(offsets.shape[0], dtype=bool)
    head[0] = True
    head[1:] = offsets[1:] >= running_end[:-1]
    heads = np.flatnonzero(head)
    cluster_id = np.cumsum(head) - 1
    best = np.maximum.reduceat(approx, heads)[cluster_id]
    potential = approx >= best - 2 * ESTIMATE_TOLERANCE
    cluster_end = running_end[np.append(heads[1:] - 1, offsets.shape[0] - 1)]
    keep = np.flatnonzero(potential | head)
    entropies = np.full(keep.shape[0], -np.inf)
    winners = potential[keep]
    entropies[winners] = _exact_entropies(values, offsets[keep[winners]],
                                          lengths[keep[winners]])
    return (offsets[keep], lengths[keep], entropies,
            cluster_end[cluster_id[keep]])


def _cluster_winners(offsets: np.ndarray, lengths: np.ndarray,
                     entropies: np.ndarray,
                     ends: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Winner index per cluster and the running max end, for sorted columns.

    A candidate joins the current cluster iff it starts before the running
    max of ``ends``; per cluster the first candidate with the largest
    ``(confidence, length)`` wins (the strict ``>`` replacement of
    :meth:`EntropyScanAlgorithm._merge_overlapping`). ``ends`` is normally
    ``offsets + lengths``; the streaming merger overrides row 0 with the
    carried cluster's running end.
    """
    confidences = entropies / 8.0
    running_end = np.maximum.accumulate(ends)
    cluster_head = np.empty(offsets.shape[0], dtype=bool)
    cluster_head[0] = True
    cluster_head[1:] = offsets[1:] >= running_end[:-1]
    heads = np.flatnonzero(cluster_head)
    cluster_id = np.cumsum(cluster_head) - 1

    best_conf = np.maximum.reduceat(confidences, heads)[cluster_id]
    is_best_conf = confidences == best_conf
    best_len = np.maximum.reduceat(np.where(is_best_conf, lengths, -1), heads)
    winners = np.flatnonzero(is_best_conf & (lengths == best_len[cluster_id]))
    first_per_cluster = np.ones(winners.shape[0], dtype=bool)
    first_per_cluster[1:] = cluster_id[winners[1:]] != cluster_id[winners[:-1]]
    return winners[first_per_cluster], running_end


class _RegionMerger:
    """Incremental :meth:`EntropyScanAlgorithm._merge_overlapping_arrays`.

    Fed candidate columns slab by slab in ascending offset ranges; closed
    clusters are reduced to their winner immediately, and the one still-open
    cluster is carried to the next slab as a single pseudo-candidate (its
    current winner, with the cluster's running end). Prepending it is exact:
    it precedes every later candidate in ``(offset, -length)`` order, so it
    keeps the first-wins tie-breaking. Memory: one slab + output regions.
    """

    def __init__(self) -> None:
        self._regions: List[Candidates] = []
        self._open: Optional[Tuple[int, int, float, int]] = None

    def feed(self, offsets: np.ndarray, lengths: np.ndarray,
             entropies: np.ndarray) -> None:
        if offsets.size == 0:
            return
        order = np.lexsort((-lengths, offsets))  # stable, like list.sort
        self.feed_sorted(offsets[order], lengths[order], entropies[order])

    def feed_sorted(self, offsets: np.ndarray, lengths: np.ndarray,
                    entropies: np.ndarray,
                    ends: Optional[np.ndarray] = None) -> None:
        """:meth:`feed` for columns already in ``(offset, -length)`` order.

        ``ends`` (default ``offsets + lengths``) lets a caller stand in one
        entry for a dropped run of candidates by giving it their running end.
        """
        if offsets.size == 0:
            return
        if ends is None:
            ends = offsets + lengths
        if self._open is not None:
            offset, length, entropy, end = self._open
            offsets = np.concatenate(([offset], offsets))
            lengths = np.concatenate(([length], lengths))
            entropies = np.concatenate(([entropy], entropies))
            ends = np.concatenate(([end], ends))
        keep, running_end = _cluster_winners(offsets, lengths, entropies, ends)
        closed, last = keep[:-1], keep[-1]
        if closed.size:
            self._regions.append((offsets[closed], lengths[closed], entropies[closed]))
        self._open = (int(offsets[last]), int(lengths[last]),
                      float(entropies[last]), int(running_end[-1]))

    def finish(self) -> Candidates:
        """All regions in order (closing the open one)."""
        regions = list(self._regions)
        if self._open is not None:
            offset, length, entropy, _ = self._open
            regions.append((np.array([offset], dtype=np.int64),
                            np.array([length], dtype=np.int64),
                            np.array([entropy], dtype=np.float64)))
        if not regions:
            empty = np.empty(0, dtype=np.int64)
            return empty, empty.copy(), np.empty(0, dtype=np.float64)
        return tuple(np.concatenate(column) for column in zip(*regions))
