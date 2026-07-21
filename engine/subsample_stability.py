"""Complementary-pairs subsample-stability instrument (A3, EXPERIMENTAL).

A ground-truth-free *reliability* signal for candidate windows that is only
meaningful at large N (N ≳ 100). The N captures are split into two disjoint
halves; per-byte variance is computed on each; every candidate window is then
scored by how closely its two half-variance estimates agree.

Why large N. The relative error of a sample variance over m observations is
≈ √(2/(m−1)). At N=20 (m≈10 per half) that is ≈ 0.47, which swamps the bulk
separation and makes stability uninformative. At N=100 (m≈50 per half) it drops
to ≈ 0.20, so a window whose variance is *stable* across the two halves is a
more-reliable high-variance candidate than one that is high in only one half.

This is a research instrument, NOT a shipped default and NOT a paper claim. On
targets whose non-key clutter is per-run-fresh (fresh nonces, IVs, other keys),
that clutter is just as stable-and-high-variance as the key, so stability alone
still cannot rank the key first — only the oracle can. The numbers this module
produces quantify exactly how much (if any) stability re-ranks the key relative
to the plain descending-variance baseline R_var.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np


def window_means(values: np.ndarray, offsets: np.ndarray,
                 sizes: np.ndarray) -> np.ndarray:
    """Mean of ``values`` over each ``(offset, size)`` window, vectorized.

    Uses a prefix sum so all candidate windows are reduced in one pass; window
    ends are clamped to the array length so out-of-range candidates degrade to
    a shorter mean rather than raising.
    """
    values = np.asarray(values, dtype=np.float64)
    csum = np.concatenate(([0.0], np.cumsum(values)))
    offs = np.asarray(offsets, dtype=np.intp)
    szs = np.asarray(sizes, dtype=np.intp)
    ends = np.minimum(offs + szs, values.size)
    offs = np.minimum(offs, values.size)
    widths = np.maximum(ends - offs, 1)
    return (csum[ends] - csum[offs]) / widths


def stability_score(
    var_a: np.ndarray, var_b: np.ndarray, offsets: np.ndarray, sizes: np.ndarray,
    *, eps: float = 1e-9,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Per-window half-variance agreement.

    Returns ``(wvar_a, wvar_b, rel_err, stability)`` where ``rel_err`` is the
    symmetric relative difference of the two half means and
    ``stability = 1/(1+rel_err) ∈ (0, 1]`` (1.0 ⇒ the two halves agree exactly).
    """
    a = window_means(var_a, offsets, sizes)
    b = window_means(var_b, offsets, sizes)
    rel_err = np.abs(a - b) / (0.5 * (a + b) + eps)
    stability = 1.0 / (1.0 + rel_err)
    return a, b, rel_err, stability


@dataclass
class SubsampleStabilityResult:
    key_index: int
    r_var: int                 # baseline: #candidates with wvar >= wvar(key)
    r_stable: int              # stability-aware: #candidates ranked >= key
    maximal: int
    key_stability: float       # 1/(1+rel_err) for the key window
    median_stability: float
    key_rel_err: float
    expected_rel_err: float    # sqrt(2/(m-1)) reference scale at this half size
    num_dumps_a: int
    num_dumps_b: int
    beats_variance: bool       # r_stable < r_var
    detail: str = ""

    def to_dict(self) -> dict:
        return {k: (v.item() if isinstance(v, np.generic) else v)
                for k, v in self.__dict__.items()}


def subsample_experiment(
    var_a: np.ndarray, var_b: np.ndarray, offsets: np.ndarray, sizes: np.ndarray,
    wvar: np.ndarray, key_index: int, num_a: int, num_b: int,
) -> SubsampleStabilityResult:
    """Rank the maximal set by a stability-aware composite and report the key's
    rank against the plain descending-variance baseline (``R_var``).

    The composite rewards windows that are BOTH high-variance and stable across
    the two halves (``wvar_normalized × stability``). ``r_stable`` is the number
    of oracle calls a composite-ordered sweep would need to reach the key.
    """
    _, _, rel_err, stability = stability_score(var_a, var_b, offsets, sizes)
    wv = np.asarray(wvar, dtype=np.float64)
    wv_norm = wv / (float(wv.max()) + 1e-9) if wv.size else wv
    composite = wv_norm * stability
    r_stable = int((composite >= composite[key_index]).sum())
    r_var = int((wv >= wv[key_index]).sum())
    m = min(num_a, num_b)
    expected = math.sqrt(2.0 / (m - 1)) if m > 1 else float("inf")
    return SubsampleStabilityResult(
        key_index=int(key_index), r_var=r_var, r_stable=r_stable,
        maximal=int(offsets.size),
        key_stability=float(stability[key_index]),
        median_stability=float(np.median(stability)) if stability.size else 0.0,
        key_rel_err=float(rel_err[key_index]),
        expected_rel_err=float(expected),
        num_dumps_a=int(num_a), num_dumps_b=int(num_b),
        beats_variance=bool(r_stable < r_var),
        detail=("EXPERIMENTAL. Stability = cross-half variance agreement; the "
                "composite rewards stable high-variance windows. r_stable < r_var "
                "means stability demotes windows that are high-variance in only "
                "one half. On per-run-fresh-clutter targets stability cannot beat "
                "the oracle — this quantifies by how little it helps."),
    )


def load_halves(artifact_dir) -> Tuple[Optional[np.ndarray], Optional[np.ndarray],
                                       int, int]:
    """Load ``(var_a, var_b, num_a, num_b)`` from a consensus dir built with
    ``--emit-halves``; returns ``(None, None, 0, 0)`` when the halves are absent."""
    import json
    from pathlib import Path
    artifact_dir = Path(artifact_dir)
    pa, pb = artifact_dir / "variance_a.npy", artifact_dir / "variance_b.npy"
    if not (pa.exists() and pb.exists()):
        return None, None, 0, 0
    num_a = num_b = 0
    meta = artifact_dir / "meta.json"
    if meta.exists():
        m = json.loads(meta.read_text())
        num_a = int(m.get("num_dumps_a", 0))
        num_b = int(m.get("num_dumps_b", 0))
    return np.load(pa), np.load(pb), num_a, num_b
