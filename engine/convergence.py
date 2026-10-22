"""Convergence sweep — measure detection quality vs number of dumps.

Builds consensus at increasing N values and tracks precision, recall,
false positives, and decryption verification at each point. The
user-facing n-sweep (driven by the ``memdiver n-sweep`` CLI) lives in
``engine/nsweep.py`` and does not share code with this file.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set

import numpy as np

from memdiver.core.alignment_filter import alignment_filter
from memdiver.core.entropy import compute_entropy_profile
from memdiver.core.memory_budget import check_budget, resolve_memory_budget
from memdiver.core.slab_variance import plan_slab_variance
from memdiver.core.variance import ByteClass
from memdiver.engine.consensus import ConsensusVector, MemoryBudgetLike

logger = logging.getLogger("memdiver.engine.convergence")

DEFAULT_N_VALUES = [2, 3, 5, 7, 10, 15, 20, 25, 30, 50, 75, 100]
MAX_N = 100

#: Window positions per entropy-profile slab in the array-backed scan. Keeps
#: the step-1 profile (16 B/position) bounded at ~16 MiB instead of 16x the
#: dump size.
ENTROPY_SLAB_POSITIONS = 1 << 20

#: Resident bytes per dump position the sweep holds besides the consensus
#: build itself: first dump bytes, entropy mask, variance mask, combined mask.
SWEEP_BYTES_PER_POSITION = {
    "first_dump": 1, "entropy_mask": 1, "variance_mask": 1, "combined_mask": 1,
}


@dataclass(frozen=True)
class DetectionMetrics:
    """Precision/recall/FP metrics for one method at one N."""
    tp: int
    fp: int
    precision: float
    recall: float
    candidates: int


@dataclass(frozen=True)
class ConvergencePoint:
    """Metrics at a single N value in the sweep."""
    n: int
    variance: DetectionMetrics
    combined: DetectionMetrics | None = None
    aligned: DetectionMetrics | None = None
    decryption_verified: bool | None = None


@dataclass
class ConvergenceSweepResult:
    """Full sweep result across all N values."""
    points: list[ConvergencePoint] = field(default_factory=list)
    first_detection_n: int | None = None
    first_decryption_n: int | None = None
    first_fp_target_n: int | None = None
    total_dumps: int = 0
    max_fp: int = 0


def _compute_metrics(candidates: Set[int], truth: Set[int]) -> DetectionMetrics:
    """Compute detection metrics."""
    tp = len(candidates & truth)
    fp = len(candidates - truth)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / len(truth) if truth else 0.0
    return DetectionMetrics(
        tp=tp, fp=fp, precision=precision, recall=recall,
        candidates=len(candidates),
    )


def _entropy_candidates(dump_data: bytes, threshold: float = 4.5,
                        window: int = 32) -> Set[int]:
    """Return byte offsets flagged by entropy scan."""
    profile = compute_entropy_profile(dump_data, window=window, step=1)
    candidates: Set[int] = set()
    for offset, entropy in profile:
        if entropy >= threshold:
            for b in range(offset, min(offset + window, len(dump_data))):
                candidates.add(b)
    return candidates


def _variance_candidates(cm: ConsensusVector) -> Set[int]:
    """Return KEY_CANDIDATE byte offsets from consensus."""
    return {i for i, c in enumerate(cm.classifications)
            if c == ByteClass.KEY_CANDIDATE}


# ---------------------------------------------------------------------------
# Array-backed equivalents of the set helpers above. Same answers, but one
# byte (bool) per dump position instead of ~60-100 B per Python int in a set.
# ---------------------------------------------------------------------------


def _truth_array(truth: Set[int]) -> np.ndarray:
    """Sorted unique ``int64`` array of ground-truth offsets."""
    return np.unique(np.fromiter((int(t) for t in truth), dtype=np.int64,
                                 count=len(truth)))


def _metrics_from_mask(mask: np.ndarray, truth_arr: np.ndarray) -> DetectionMetrics:
    """:func:`_compute_metrics` for a boolean candidate mask."""
    in_range = truth_arr[(truth_arr >= 0) & (truth_arr < mask.shape[0])]
    return _metrics_from_counts(int(mask[in_range].sum()),
                                int(np.count_nonzero(mask)), len(truth_arr))


def _metrics_from_positions(positions: np.ndarray,
                            truth_arr: np.ndarray) -> DetectionMetrics:
    """:func:`_compute_metrics` for a sorted unique offset array."""
    idx = np.searchsorted(positions, truth_arr)
    hit = idx < positions.shape[0]
    tp = int(np.count_nonzero(positions[idx[hit]] == truth_arr[hit]))
    return _metrics_from_counts(tp, int(positions.shape[0]), len(truth_arr))


def _metrics_from_counts(tp: int, candidates: int, truth_count: int) -> DetectionMetrics:
    fp = candidates - tp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / truth_count if truth_count else 0.0
    return DetectionMetrics(tp=tp, fp=fp, precision=precision, recall=recall,
                            candidates=candidates)


def _entropy_mask(dump_data: bytes, threshold: float = 4.5,
                  window: int = 32) -> np.ndarray:
    """Boolean mask equal to :func:`_entropy_candidates` (as offsets).

    Byte ``i`` is covered iff some window start ``s`` with entropy >=
    threshold satisfies ``s <= i < s + window``, i.e. the latest hit start
    at or before ``i`` is greater than ``i - window``. The step-1 profile is
    computed slab by slab (each window's entropy depends only on its own
    bytes, so the values are bit-identical to one whole-dump profile).
    """
    size = len(dump_data)
    mask = np.zeros(size, dtype=bool)
    positions = size - window + 1
    if window <= 0 or positions <= 0:
        return mask
    view = memoryview(dump_data)
    no_hit = np.int64(-(1 << 62))
    carry = no_hit
    for start in range(0, positions, ENTROPY_SLAB_POSITIONS):
        stop = min(start + ENTROPY_SLAB_POSITIONS, positions)
        profile = compute_entropy_profile(bytes(view[start:stop + window - 1]),
                                          window=window, step=1)
        _, values = profile.as_arrays()
        here = np.arange(start, stop, dtype=np.int64)
        last = np.where(values >= threshold, here, no_hit)
        np.maximum.accumulate(last, out=last)
        np.maximum(last, carry, out=last)
        mask[start:stop] = last > here - window
        carry = last[-1]
    tail = np.arange(positions, size, dtype=np.int64)
    mask[positions:] = carry > tail - window
    return mask


def _variance_mask(cm: ConsensusVector) -> np.ndarray:
    """Boolean mask equal to :func:`_variance_candidates` (as offsets)."""
    return np.asarray(cm.classifications) == ByteClass.KEY_CANDIDATE


def _aligned_positions(positions: np.ndarray, block_size: int = 32,
                       alignment: int = 16,
                       density_threshold: float = 0.75) -> np.ndarray:
    """:func:`alignment_filter` over a sorted unique offset array.

    Evaluates the same aligned block starts (``first_start..last_start``) with
    the same bisect counts, and keeps the union of passing blocks' members.
    """
    if positions.shape[0] == 0 or block_size <= 0 or alignment <= 0:
        return np.empty(0, dtype=np.int64)
    first_start = (int(positions[0]) // alignment) * alignment
    last_start = (int(positions[-1]) // alignment) * alignment
    starts = np.arange(first_start, last_start + 1, alignment, dtype=np.int64)
    lo = np.searchsorted(positions, starts, side="left")
    hi = np.searchsorted(positions, starts + block_size, side="left")
    passing = (hi - lo) >= int(block_size * density_threshold)
    cover = np.zeros(positions.shape[0] + 1, dtype=np.int64)
    np.add.at(cover, lo[passing], 1)
    np.add.at(cover, hi[passing], -1)
    keep = np.cumsum(cover[:-1]) > 0
    return positions[keep]


def _check_sweep_budget(dump_paths: list[Path], n_max: int, *, force: bool,
                        budget: MemoryBudgetLike) -> None:
    """One upfront budget check for the largest consensus build of the sweep."""
    sizes = [p.stat().st_size for p in dump_paths[:n_max]]
    min_size = min(sizes) if sizes else 0
    if min_size == 0:
        return
    if budget is None:
        budget = resolve_memory_budget()
    extra = {k: v * max(sizes[0], min_size)
             for k, v in SWEEP_BYTES_PER_POSITION.items()}
    plan = plan_slab_variance(n_max, min_size, budget=budget, extra=extra,
                              operation=f"convergence sweep (N<={n_max})")
    check_budget(plan.estimate, force=force, budget=budget)


def run_convergence_sweep(
    dump_paths: list[Path],
    ground_truth: Set[int] | None = None,
    n_values: list[int] | None = None,
    entropy_threshold: float = 4.5,
    alignment_params: dict | None = None,
    verifier_fn=None,
    recall_threshold: float = 0.875,
    max_fp: int = 0,
    *,
    force: bool = False,
    budget: MemoryBudgetLike = None,
) -> ConvergenceSweepResult:
    """Sweep N=[2..max] building consensus and measuring detection.

    Args:
        dump_paths: All available dump file paths.
        ground_truth: Set of byte offsets that are actual key bytes.
            If None, precision/recall cannot be computed.
        n_values: List of N values to sweep. Default: [2,3,5,7,10,...,100].
            Capped at len(dump_paths) and MAX_N.
        entropy_threshold: Shannon entropy threshold for entropy scan.
        alignment_params: Dict with block_size, alignment, density_threshold
            for alignment_filter. Default: {32, 16, 0.75}.
        verifier_fn: Optional callable(dump_data, aligned_candidates) -> bool
            for decryption verification at each N.
        recall_threshold: Minimum recall to consider "detected" (default 0.875).
        max_fp: FP target for convergence reporting (default 0).
        force: Proceed past a memory-budget refusal (logged instead).
        budget: Memory budget (bytes / ``MemoryBudget``); None = host default.
            Checked once upfront for the largest N, then per build.

    Returns:
        ConvergenceSweepResult with per-N metrics and convergence points.
    """
    if n_values is None:
        n_values = [n for n in DEFAULT_N_VALUES if n <= MAX_N]

    total = len(dump_paths)
    n_values = [n for n in n_values if n <= min(total, MAX_N)]

    if not n_values or total < 2:
        return ConvergenceSweepResult(total_dumps=total, max_fp=max_fp)

    align_params = alignment_params or {
        "block_size": 32, "alignment": 16, "density_threshold": 0.75,
    }

    _check_sweep_budget(dump_paths, max(n_values), force=force, budget=budget)

    # Entropy candidates from first dump (constant across sweep)
    first_data = dump_paths[0].read_bytes()
    ent_mask = _entropy_mask(first_data, entropy_threshold)
    truth_arr = _truth_array(ground_truth) if ground_truth else None

    result = ConvergenceSweepResult(total_dumps=total, max_fp=max_fp)

    for n in n_values:
        # Bit-identical one-shot (two-pass) consensus per N; slab-streamed, so
        # only one slab per file is resident while it re-reads the prefix.
        cm = ConsensusVector()
        cm.build(dump_paths[:n], force=force, budget=budget)
        var_mask = _variance_mask(cm)
        del cm
        var_count = int(np.count_nonzero(var_mask))

        # Variance-only metrics
        var_m = _metrics_from_mask(var_mask, truth_arr) if ground_truth else None

        # Combined: entropy ∩ variance
        common = min(ent_mask.shape[0], var_mask.shape[0])
        combined = ent_mask[:common] & var_mask[:common]
        del var_mask
        com_m = _metrics_from_mask(combined, truth_arr) if ground_truth else None

        # Combined + aligned
        aligned_pos = _aligned_positions(np.flatnonzero(combined), **align_params)
        del combined
        ali_m = _metrics_from_positions(aligned_pos, truth_arr) if ground_truth else None

        # Decryption verification
        dec = None
        if verifier_fn is not None:
            dec = verifier_fn(first_data, set(aligned_pos.tolist()))

        point = ConvergencePoint(
            n=n,
            variance=var_m or DetectionMetrics(0, 0, 0.0, 0.0, var_count),
            combined=com_m,
            aligned=ali_m,
            decryption_verified=dec,
        )
        result.points.append(point)

        # Track convergence milestones
        if ground_truth:
            if result.first_detection_n is None and var_m and var_m.recall >= recall_threshold:
                result.first_detection_n = n
            if result.first_fp_target_n is None and ali_m and ali_m.fp <= max_fp and ali_m.recall >= recall_threshold:
                result.first_fp_target_n = n
        if result.first_decryption_n is None and dec is True:
            result.first_decryption_n = n

        logger.debug("N=%d: var_recall=%.1f%% comb_fp=%d aligned_fp=%d dec=%s",
                      n,
                      (var_m.recall * 100) if var_m else 0,
                      com_m.fp if com_m else -1,
                      ali_m.fp if ali_m else -1,
                      dec)

    return result

