"""Composable search-space reduction: variance → alignment → entropy.

Drives the ``memdiver search-reduce`` CLI. Loads a finalized consensus
state, extracts high-variance byte offsets, filters them through an
alignment grid, then narrows surviving regions by sliding-window Shannon
entropy. At N<3 dumps, variance is meaningless (Welford's population
variance at n=1 is zero everywhere), so the pipeline falls back to
entropy-only candidate generation and logs a warning.

All stages operate on length-``total_size`` numpy bool masks so a 210 MB
dump costs ~210 MB of transient memory (one bool per byte), not the
6 GB a Python ``Set[int]`` would take.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import List

import numpy as np

from core.entropy import compute_entropy_profile, shannon_entropy
from core.variance import find_contiguous_runs
from engine.progress import (
    ProgressEvent,
    ProgressFn,
    noop_progress,
    safe_emit,
)

logger = logging.getLogger("memdiver.engine.candidate_pipeline")

MIN_N_FOR_VARIANCE = 3


@dataclass
class CandidateRegion:
    offset: int
    length: int
    mean_entropy: float
    mean_variance: float

    def to_dict(self) -> dict:
        return {
            "offset": int(self.offset),
            "length": int(self.length),
            "mean_entropy": float(self.mean_entropy),
            "mean_variance": float(self.mean_variance),
        }


@dataclass
class StageCounts:
    total_bytes: int = 0
    variance: int = 0
    aligned: int = 0
    high_entropy: int = 0

    def to_dict(self) -> dict:
        return {
            "total_bytes": self.total_bytes,
            "variance": self.variance,
            "aligned": self.aligned,
            "high_entropy": self.high_entropy,
        }


@dataclass
class ReductionResult:
    regions: List[CandidateRegion] = field(default_factory=list)
    stages: StageCounts = field(default_factory=StageCounts)
    thresholds: dict = field(default_factory=dict)
    num_dumps: int = 0

    @property
    def fallback_entropy_only(self) -> bool:
        return self.num_dumps < MIN_N_FOR_VARIANCE

    def to_dict(self) -> dict:
        return {
            "N": self.num_dumps,
            "stages": self.stages.to_dict(),
            "thresholds": dict(self.thresholds),
            "fallback_entropy_only": self.fallback_entropy_only,
            "regions": [r.to_dict() for r in self.regions],
        }


def _variance_mask(variance: np.ndarray, min_variance: float) -> np.ndarray:
    """Purely threshold-based candidate mask.

    The global KEY_CANDIDATE enum threshold (3000) is a reasonable
    default for synthetic data, but real crypto keys on real datasets
    have per-byte variance that swings widely across runs — sometimes
    dipping to ~2000 even for bytes that DO change every run. We let
    ``--min-variance`` be the single tunable cutoff so the caller can
    match observed variance distributions without recompiling the enum.
    """
    return variance >= min_variance


def _aligned_mask(
    candidate_mask: np.ndarray,
    block_size: int,
    alignment: int,
    density_threshold: float,
) -> np.ndarray:
    """Vectorized alignment filter over a bool mask.

    Byte ``i`` survives iff it's a candidate AND is inside at least one
    ``alignment``-aligned, ``block_size``-wide block whose candidate
    density ≥ ``density_threshold``.
    """
    total = len(candidate_mask)
    if total < block_size or not candidate_mask.any():
        return np.zeros(total, dtype=bool)
    cum = np.concatenate([[0], np.cumsum(candidate_mask.astype(np.int32))])
    starts = np.arange(0, total - block_size + 1, alignment, dtype=np.int64)
    counts = cum[starts + block_size] - cum[starts]
    min_count = int(block_size * density_threshold)
    kept_starts = starts[counts >= min_count]
    if kept_starts.size == 0:
        return np.zeros(total, dtype=bool)
    events = np.zeros(total + 1, dtype=np.int32)
    np.add.at(events, kept_starts, 1)
    np.add.at(events, np.minimum(kept_starts + block_size, total), -1)
    in_kept_block = np.cumsum(events)[:total] > 0
    return candidate_mask & in_kept_block


def _entropy_profile_array(
    reference_data: bytes,
    window: int,
    step: int,
) -> np.ndarray:
    """Sliding-window entropy sampled every ``step`` bytes as a float32 array.

    Element ``k`` is the entropy of the window starting at ``k*step``.
    """
    profile = compute_entropy_profile(reference_data, window=window, step=step)
    return np.fromiter((e for _, e in profile), dtype=np.float32, count=len(profile))


def _entropy_coverage_mask(
    profile_arr: np.ndarray,
    total_size: int,
    window: int,
    step: int,
    threshold: float,
) -> np.ndarray:
    """Bool mask marking every byte covered by a high-entropy window."""
    mask = np.zeros(total_size, dtype=bool)
    if profile_arr.size == 0:
        return mask
    high_windows = np.flatnonzero(profile_arr >= threshold)
    if high_windows.size == 0:
        return mask
    events = np.zeros(total_size + 1, dtype=np.int32)
    starts = high_windows.astype(np.int64) * step
    ends = np.minimum(starts + window, total_size)
    np.add.at(events, starts, 1)
    np.add.at(events, ends, -1)
    return np.cumsum(events)[:total_size] > 0


def _runs_from_mask(mask: np.ndarray) -> List[tuple[int, int]]:
    """Contiguous (start, end) runs of True values in a bool mask."""
    return find_contiguous_runs(mask.astype(np.uint8), 1)


def _region_mean_entropy(
    start: int,
    end: int,
    profile_arr: np.ndarray,
    step: int,
    window: int,
    reference_data: bytes,
) -> float:
    """Mean entropy over window samples whose start offset falls in [start, end)."""
    lo_k = (start + step - 1) // step
    hi_k = end // step
    lo_k = max(0, lo_k)
    hi_k = min(int(profile_arr.size), hi_k)
    if hi_k > lo_k:
        return float(profile_arr[lo_k:hi_k].mean())
    # Region shorter than one window sample — fall back to direct entropy.
    return float(shannon_entropy(reference_data[start:end]))


def reduce_search_space(
    variance: np.ndarray,
    reference_data: bytes,
    num_dumps: int,
    *,
    alignment: int = 8,
    block_size: int = 32,
    density_threshold: float = 0.5,
    min_variance: float = 3000.0,
    entropy_window: int = 32,
    entropy_threshold: float = 4.5,
    min_region: int = 16,
    progress_callback: ProgressFn = noop_progress,
) -> ReductionResult:
    """Run the consensus → alignment → entropy reduction chain.

    All stages use numpy bool masks so memory stays O(total_size) instead
    of O(total_size × int64) a set would require.
    """
    if entropy_threshold > math.log2(entropy_window):
        raise ValueError(
            f"entropy_threshold={entropy_threshold} exceeds log2(window)"
            f"={math.log2(entropy_window):.2f}; pick a smaller threshold "
            f"or a larger window"
        )

    variance = np.asarray(variance)
    total_size = int(variance.size) if variance.size > 0 else len(reference_data)
    if variance.size > 0 and len(reference_data) < total_size:
        raise ValueError(
            f"reference dump shorter than variance array "
            f"({len(reference_data)} < {total_size})"
        )

    stages = StageCounts(total_bytes=total_size)
    thresholds = {
        "alignment": alignment,
        "block_size": block_size,
        "density_threshold": density_threshold,
        "min_variance": min_variance,
        "entropy_window": entropy_window,
        "entropy_threshold": entropy_threshold,
        "min_region": min_region,
    }

    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:start",
            pct=0.0,
            msg=f"total={total_size}",
            extra={"total_bytes": total_size, "num_dumps": num_dumps},
        ),
    )

    fallback = num_dumps < MIN_N_FOR_VARIANCE
    if fallback:
        logger.warning(
            "N=%d < %d; variance is unreliable, falling back to entropy-only",
            num_dumps, MIN_N_FOR_VARIANCE,
        )
        variance_mask = np.ones(total_size, dtype=bool)
    else:
        variance_mask = _variance_mask(variance, min_variance)
    stages.variance = int(variance_mask.sum())
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:variance",
            pct=0.25,
            msg=f"variance survivors={stages.variance}",
            extra={"survivor_bytes": stages.variance, "input_bytes": total_size},
        ),
    )

    if fallback:
        aligned_mask = variance_mask
    else:
        aligned_mask = _aligned_mask(
            variance_mask, block_size, alignment, density_threshold
        )
    stages.aligned = int(aligned_mask.sum())
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:aligned",
            pct=0.5,
            msg=f"aligned survivors={stages.aligned}",
            extra={"survivor_bytes": stages.aligned, "input_bytes": stages.variance},
        ),
    )

    entropy_step = alignment
    profile_arr = _entropy_profile_array(
        reference_data[:total_size], entropy_window, entropy_step
    )
    entropy_mask = _entropy_coverage_mask(
        profile_arr, total_size, entropy_window, entropy_step, entropy_threshold
    )
    surviving_mask = aligned_mask & entropy_mask
    stages.high_entropy = int(surviving_mask.sum())
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:entropy",
            pct=0.75,
            msg=f"high-entropy survivors={stages.high_entropy}",
            extra={"survivor_bytes": stages.high_entropy, "input_bytes": stages.aligned},
        ),
    )

    regions: List[CandidateRegion] = []
    for start, end in _runs_from_mask(surviving_mask):
        if end - start < min_region:
            continue
        mean_entropy = _region_mean_entropy(
            start, end, profile_arr, entropy_step, entropy_window, reference_data
        )
        mean_variance = (
            float(variance[start:end].mean()) if variance.size >= end else 0.0
        )
        regions.append(
            CandidateRegion(
                offset=int(start),
                length=int(end - start),
                mean_entropy=mean_entropy,
                mean_variance=mean_variance,
            )
        )

    result = ReductionResult(
        regions=regions,
        stages=stages,
        thresholds=thresholds,
        num_dumps=num_dumps,
    )
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:regions",
            pct=1.0,
            msg=f"{len(regions)} regions",
            extra={"num_regions": len(regions)},
        ),
    )
    return result
