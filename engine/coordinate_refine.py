"""Correspondence / alignment-quality diagnostics (C2).

Before a variance floor means anything, the SAME aligned offset must refer to
the SAME logical structure across all N captures.  Allocation-order jitter
breaks that: a fixed offset lands on the key in some runs and on a neighbour in
others, so the observed variance is a mixture (the master-equation dilution).

This module measures, per region, HOW positionally stable the high-entropy
content is across the N captures — a ground-truth-free score in [0,1]:

    ~1.0  the same structure sits at the same place in every run (module-relative
          alignment suffices; a floor is meaningful);
    ~0.0  offsets are not reliably comparable (a no-hit must NOT be read as the
          key being absent → the caller gates the verdict to INCONCLUSIVE).

It uses a bounded-lag normalized cross-correlation (NCC) of a high-entropy
*anchor* window (cheap; O(N * window * max_lag)), NOT a full-region FFT.  The
score combines peak height (is there a real match?) with peak-LAG consistency
(does the match sit at the same offset across runs?).  Actual re-registration —
shifting each run so p_i -> 1 — is the deferred consensus-time build; this only
scores and reports.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

import numpy as np

from memdiver.core.entropy import compute_entropy_profile

logger = logging.getLogger("memdiver.engine.coordinate_refine")


@dataclass
class CorrespondenceResult:
    score: float                 # [0,1] positional stability
    peak_ncc: float              # mean best-lag NCC across runs
    lag_consistency: float       # fraction of runs whose best lag ≈ the median
    best_lags: List[int]
    anchor_offset: int
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "score": self.score, "peak_ncc": self.peak_ncc,
            "lag_consistency": self.lag_consistency,
            "best_lags": list(self.best_lags), "anchor_offset": self.anchor_offset,
            "detail": self.detail,
        }


def _zscore(x: np.ndarray) -> np.ndarray:
    x = x.astype(np.float64)
    mu = x.mean()
    sd = x.std()
    return (x - mu) / sd if sd > 0 else np.zeros_like(x)


def _ncc_best_lag(anchor: np.ndarray, signal: np.ndarray,
                  max_lag: int) -> tuple:
    """Best-lag normalized cross-correlation of ``anchor`` within ``signal``.

    Returns (best_lag, peak_ncc in [-1,1]).  ``signal`` must be at least
    ``anchor.size + 2*max_lag`` long, with the aligned position at its centre.
    """
    a = _zscore(anchor)
    w = anchor.size
    best_lag, best = 0, -1.0
    centre = (signal.size - w) // 2
    for lag in range(-max_lag, max_lag + 1):
        start = centre + lag
        if start < 0 or start + w > signal.size:
            continue
        seg = _zscore(signal[start:start + w])
        ncc = float(np.dot(a, seg) / w)
        if ncc > best:
            best, best_lag = ncc, lag
    return best_lag, best


def _pick_anchor(reference_region: np.ndarray, window: int) -> int:
    """Offset (within the region) of the highest-entropy anchor window."""
    prof = compute_entropy_profile(reference_region.tobytes(), window=window, step=window)
    if not prof:
        return 0
    return max(prof, key=lambda p: p[1])[0]


def correspondence_score(
    region_stack: np.ndarray,
    *,
    window: int = 32,
    max_lag: int = 64,
    lag_tol: int = 1,
) -> CorrespondenceResult:
    """Per-region positional-stability score in [0,1] over N captures.

    ``region_stack`` is an (N, L) uint8 matrix: the SAME region across the N
    runs.  Run 0 is the reference; its highest-entropy window is the anchor.
    """
    region_stack = np.asarray(region_stack, dtype=np.uint8)
    if region_stack.ndim != 2 or region_stack.shape[0] < 2:
        return CorrespondenceResult(0.0, 0.0, 0.0, [], 0,
                                    detail="need >=2 runs")
    N, L = region_stack.shape
    window = min(window, L)
    anchor_off = _pick_anchor(region_stack[0], window)
    anchor = region_stack[0, anchor_off:anchor_off + window]
    if anchor.size < window:
        return CorrespondenceResult(0.0, 0.0, 0.0, [], anchor_off,
                                    detail="region shorter than window")

    lags: List[int] = []
    nccs: List[float] = []
    # Pad each run so the anchor's own position is the search centre.
    pad = max_lag
    for r in range(N):
        sig = np.zeros(L + 2 * pad, dtype=np.uint8)
        sig[pad:pad + L] = region_stack[r]
        # centre the search on the anchor's reference position
        seg = sig[anchor_off:anchor_off + window + 2 * pad]
        lag, ncc = _ncc_best_lag(anchor, seg, max_lag)
        lags.append(int(lag)); nccs.append(float(ncc))

    peak_ncc = float(np.mean(nccs))
    med = float(np.median(lags))
    lag_consistency = float(np.mean([abs(l - med) <= lag_tol for l in lags]))
    # positional stability = do real matches (high NCC) sit at a consistent lag?
    score = float(max(0.0, min(1.0, peak_ncc)) * lag_consistency)
    return CorrespondenceResult(
        score=score, peak_ncc=peak_ncc, lag_consistency=lag_consistency,
        best_lags=lags, anchor_offset=int(anchor_off),
        detail=(f"anchor@{anchor_off} window={window} max_lag={max_lag}; "
                f"mean peak NCC={peak_ncc:.3f}, lag consistency={lag_consistency:.3f}. "
                f"Low score → offsets not comparable → gate verdict to INCONCLUSIVE."),
    )
