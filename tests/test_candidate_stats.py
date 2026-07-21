"""Tests for engine.candidate_stats (Phase-A offline experiments).

Builds a synthetic consensus that faithfully encodes the master-equation
regime — a diluted key (depressed variance, uniform content), per-run-fresh
clutter at the uniform ceiling, structured high-variance clutter (a ramp,
high autocorrelation), and a low-variance heap band — and checks that the
harness measurements behave exactly as the theory predicts.
"""
from __future__ import annotations

import numpy as np
import pytest

from memdiver.engine.candidate_stats import (
    SIGMA_K2,
    calibrate_thresholds,
    compute_window_features,
    composite_rank_from_dumps,
    keylike_gate,
    kneedle_descending,
    run_phase_a,
    render_report,
    trimmed_mean_window,
)

BG = 0x41            # low-entropy background byte (entropy 0 → excluded)
BLOCK = 256
KEY_OFF = 0x1000
KEY_SIZE = 32


def _build_synthetic(seed: int = 1234):
    """Return (variance, reference_bytes, num_dumps, key_offset)."""
    total = 0x8000
    rng = np.random.default_rng(seed)
    ref = np.full(total, BG, dtype=np.uint8)
    var = np.zeros(total, dtype=np.float64)

    def uniform_fill(off, length):
        ref[off:off + length] = rng.integers(0, 256, size=length, dtype=np.uint8)

    # KEY block: uniform content; key window variance depressed (~p·σ_k²).
    uniform_fill(KEY_OFF, BLOCK)
    var[KEY_OFF:KEY_OFF + BLOCK] = 2156.0
    # 18 diluted bytes @1500, 14 @3000 within the key window → mean ≈ 2156.
    kv = np.full(KEY_SIZE, 3000.0); kv[:18] = 1500.0
    var[KEY_OFF:KEY_OFF + KEY_SIZE] = kv

    # Fresh clutter blocks at the uniform ceiling (nonces / other keys).
    for off in (0x1400, 0x1800, 0x1C00):
        uniform_fill(off, BLOCK)
        var[off:off + BLOCK] = 5400.0

    # Structured high-variance clutter: a byte ramp (high entropy, high
    # autocorrelation) — demoted by the uniformity gate, not by variance.
    struct_off = 0x2000
    ref[struct_off:struct_off + BLOCK] = (np.arange(BLOCK) % 256).astype(np.uint8)
    var[struct_off:struct_off + BLOCK] = 5000.0

    # Large low-variance heap band (uniform content) → appears only at low φ;
    # its onset is the dominant candidate-count explosion (the knee sits above it).
    heap_off, heap_len = 0x4000, 0x2000
    uniform_fill(heap_off, heap_len)
    var[heap_off:heap_off + heap_len] = 1300.0

    return var, ref.tobytes(), 8, KEY_OFF


def test_phase_a_runs_and_locates_key():
    var, ref, n, key_off = _build_synthetic()
    res = run_phase_a(var, ref, n, key_off, key_size=KEY_SIZE, stride=8)
    assert res.ordering.maximal > 0
    # the located candidate window must start at the key offset
    assert res.key_offset == key_off


def test_composite_beats_variance_but_bounded_by_fresh_clutter():
    var, ref, n, key_off = _build_synthetic()
    res = run_phase_a(var, ref, n, key_off, key_size=KEY_SIZE, stride=8)
    o = res.ordering
    # The uniformity gate demotes the structured ramp that outranks the key
    # under pure variance ordering → composite strictly improves.
    assert o.r_composite < o.r_var
    # ...but fresh uniform clutter at the ceiling is irreducible: it exists and
    # bounds how far ordering can go (only the oracle separates it from the key).
    assert o.clutter_at_ceiling > 0
    # the key itself looks like a uniform key at W=32
    assert o.key_passes_gate is True


def test_floor_selection_knee_descends_and_retains_key():
    var, ref, n, key_off = _build_synthetic()
    res = run_phase_a(var, ref, n, key_off, key_size=KEY_SIZE, stride=8)
    f = res.floor
    # φ_theory at default p_min=0.35 ≈ 0.35·5461 ≈ 1911
    assert abs(f.phi_theory["0.35"] - 0.35 * f.sigma_k2_hat) < 1e-6
    # σ_k²̂ within the clamped band
    assert 0.5 * SIGMA_K2 <= f.sigma_k2_hat <= SIGMA_K2
    # the descending knee must retain the diluted key (key wvar ≈ 2156)
    assert f.key_retained_at_knee is True
    assert 1200.0 <= f.phi_knee <= 3000.0
    # key retained at φ_theory(0.35) too
    assert f.key_retained_at_theory["0.35"] is True


def test_trimmed_mean_ignores_diluted_edge_bytes():
    var = np.array([1500.0] * 18 + [3000.0] * 14, dtype=np.float64)
    tm = trimmed_mean_window(var, 0, 32, trim=0.1)
    plain = float(var.mean())
    # trimmed mean stays a sensible central value, unaffected by trimming a few
    assert 1500.0 < tm <= 3000.0
    assert abs(tm - plain) < 700.0


def test_kneedle_returns_ladder_value():
    ladder = [3000, 2500, 2000, 1750, 1500, 1200]
    counts = [30, 30, 60, 60, 62, 400]   # explosion at the low end
    knee = kneedle_descending(ladder, counts)
    assert knee in ladder
    assert knee >= 1200


def test_uniformity_gate_rejects_ramp_accepts_uniform():
    rng = np.random.default_rng(7)
    thr = calibrate_thresholds(32)
    uniform = rng.integers(0, 256, size=(1, 32), dtype=np.uint8)
    ramp = (np.arange(32) % 256).astype(np.uint8)[None, :]
    from memdiver.engine.candidate_stats import _features_for_windows
    assert bool(keylike_gate(_features_for_windows(uniform), thr)[0]) is True
    assert bool(keylike_gate(_features_for_windows(ramp), thr)[0]) is False


def test_composite_from_dumps_prefers_displaced_key_over_static_table():
    """Corrected Σ_r KeyLike: a displaced fresh key beats a static uniform table."""
    rng = np.random.default_rng(99)
    N, total, size = 8, 512, 32
    dumps = np.zeros((N, total), dtype=np.uint8)
    key = rng.integers(0, 256, size=size, dtype=np.uint8)
    static_table = rng.integers(0, 256, size=size, dtype=np.uint8)
    key_base, static_base = 64, 256
    for r in range(N):
        shift = 0 if r == 0 else int(rng.integers(-4, 5))  # run 0 is the aligned reference
        dumps[r, key_base + shift:key_base + shift + size] = key
        dumps[r, static_base:static_base + size] = static_table  # identical every run
    thr = calibrate_thresholds(size)
    offs = np.array([key_base, static_base], dtype=np.int64)
    szs = np.array([size, size], dtype=np.int64)
    scores = composite_rank_from_dumps(dumps, offs, szs, thr, w_tol=8)
    assert scores[0] > scores[1]        # displaced fresh key > static table
    assert scores[1] == 0.0             # static table killed by freshness req


def test_render_report_is_nonempty():
    var, ref, n, key_off = _build_synthetic()
    res = run_phase_a(var, ref, n, key_off, key_size=KEY_SIZE, stride=8)
    report = render_report(res)
    assert "Phase A" in report and "R_composite" in report
