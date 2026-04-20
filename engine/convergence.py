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

from core.alignment_filter import alignment_filter
from core.entropy import compute_entropy_profile
from core.variance import ByteClass
from engine.consensus import ConsensusVector

logger = logging.getLogger("memdiver.engine.convergence")

DEFAULT_N_VALUES = [2, 3, 5, 7, 10, 15, 20, 25, 30, 50, 75, 100]
MAX_N = 100


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


def run_convergence_sweep(
    dump_paths: list[Path],
    ground_truth: Set[int] | None = None,
    n_values: list[int] | None = None,
    entropy_threshold: float = 4.5,
    alignment_params: dict | None = None,
    verifier_fn=None,
    recall_threshold: float = 0.875,
    max_fp: int = 0,
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

    # Entropy candidates from first dump (constant across sweep)
    first_data = dump_paths[0].read_bytes()
    ent_cands = _entropy_candidates(first_data, entropy_threshold)

    result = ConvergenceSweepResult(total_dumps=total, max_fp=max_fp)

    for n in n_values:
        cm = ConsensusVector()
        cm.build(dump_paths[:n])
        var_cands = _variance_candidates(cm)

        # Variance-only metrics
        var_m = _compute_metrics(var_cands, ground_truth) if ground_truth else None

        # Combined: entropy ∩ variance
        combined = ent_cands & var_cands
        com_m = _compute_metrics(combined, ground_truth) if ground_truth else None

        # Combined + aligned
        aligned = alignment_filter(combined, **align_params)
        ali_m = _compute_metrics(aligned, ground_truth) if ground_truth else None

        # Decryption verification
        dec = None
        if verifier_fn is not None:
            dec = verifier_fn(first_data, aligned)

        point = ConvergencePoint(
            n=n,
            variance=var_m or DetectionMetrics(0, 0, 0.0, 0.0, len(var_cands)),
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

