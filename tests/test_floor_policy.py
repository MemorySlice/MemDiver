"""Tests for engine.floor_policy — shared online floor-policy helpers.

window_variance is the ranking helper lifted verbatim from auto_floor;
recommended_floor is the compute_phi0-based advisory with never-miss guards.
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.engine.auto_floor import DEFAULT_FLOOR, compute_phi0  # noqa: E402
from memdiver.engine.candidate_pipeline import MIN_N_FOR_VARIANCE  # noqa: E402
from memdiver.engine.floor_policy import (  # noqa: E402
    recommended_floor,
    window_variance,
)


def _diluted_sample() -> np.ndarray:
    """Structural bulk + a depressed 'crypto' band (footnote-2 shape)."""
    rng = np.random.default_rng(1)
    structural = rng.uniform(50, 200, 4000)
    crypto = rng.uniform(2231, 5380, 400)
    return np.concatenate([structural, crypto])


# ── window_variance ──────────────────────────────────────────────────
def test_window_variance_matches_inline_cumsum():
    rng = np.random.default_rng(7)
    variance = rng.uniform(0, 6000, 10_000).astype(np.float64)
    offsets = rng.integers(0, 9000, 200, dtype=np.int64)
    sizes = rng.integers(16, 64, 200, dtype=np.int64)
    cumvar = np.concatenate([[0.0], np.cumsum(variance)])
    legacy = (cumvar[offsets + sizes] - cumvar[offsets]) / sizes
    np.testing.assert_allclose(window_variance(variance, offsets, sizes), legacy)


def test_window_variance_empty_input():
    out = window_variance(np.arange(100.0), np.empty(0, np.int64), np.empty(0, np.int64))
    assert out.shape == (0,)
    assert out.dtype == np.float64


# ── recommended_floor: never-miss guards ─────────────────────────────
def test_recommended_floor_low_n_returns_zero():
    assert recommended_floor(_diluted_sample(), num_dumps=MIN_N_FOR_VARIANCE - 1) == 0.0


def test_recommended_floor_no_signal_returns_zero():
    # All structural (max 50 < 200 no-signal ceiling): no crypto component.
    assert recommended_floor(np.full(2000, 50.0), num_dumps=20) == 0.0


# ── recommended_floor: matches compute_phi0 above threshold ───────────
def test_recommended_floor_matches_compute_phi0_above_threshold():
    sample = _diluted_sample()
    rf = recommended_floor(sample, num_dumps=20)
    assert rf == compute_phi0(sample, num_dumps=20).phi0
    assert 1500.0 < rf < DEFAULT_FLOOR


def test_recommended_floor_accepts_wvar_or_variance():
    # Full per-byte variance array (mostly background + a crypto band).
    var = np.full(50_000, 50.0, dtype=np.float64)
    var[10_000:10_400] = np.random.default_rng(3).uniform(2231, 5380, 400)
    rf_full = recommended_floor(var, num_dumps=20)
    # A precomputed wvar-shaped sample.
    rf_wvar = recommended_floor(_diluted_sample(), num_dumps=20)
    for rf in (rf_full, rf_wvar):
        assert 0.0 < rf <= DEFAULT_FLOOR
