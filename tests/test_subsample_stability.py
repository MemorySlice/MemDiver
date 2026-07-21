"""Tests for the experimental complementary-pairs subsample-stability instrument
(``engine.subsample_stability``, Phase-A A3)."""
from __future__ import annotations

import numpy as np

from memdiver.engine.subsample_stability import (
    load_halves, stability_score, subsample_experiment, window_means,
)


def test_window_means_basic_and_clamped():
    values = np.arange(64, dtype=np.float64)
    offsets = np.array([0, 4, 62], dtype=np.intp)
    sizes = np.array([4, 4, 4], dtype=np.intp)
    means = window_means(values, offsets, sizes)
    assert means[0] == 1.5            # mean of [0,1,2,3]
    assert means[1] == 5.5            # mean of [4,5,6,7]
    assert means[2] == 62.5           # clamped to [62,63] at the tail


def test_stability_score_identical_halves_is_one():
    var = np.full(128, 4000.0)
    offsets = np.array([0, 32, 64], dtype=np.intp)
    sizes = np.full(3, 32, dtype=np.intp)
    _, _, rel_err, stability = stability_score(var, var, offsets, sizes)
    assert np.allclose(rel_err, 0.0)
    assert np.allclose(stability, 1.0)


def test_stability_score_divergent_halves_is_low():
    a = np.full(64, 6000.0)
    b = np.full(64, 1000.0)
    offsets = np.array([0], dtype=np.intp)
    sizes = np.array([32], dtype=np.intp)
    _, _, rel_err, stability = stability_score(a, b, offsets, sizes)
    assert rel_err[0] > 1.0
    assert stability[0] < 0.5


def _fixture():
    """3 windows: a stable high-variance key, a spurious clutter window that is
    high in only ONE half, and a low-variance heap window."""
    size = 32
    offsets = np.array([0, 32, 64], dtype=np.intp)   # key, spurious, heap
    sizes = np.full(3, size, dtype=np.intp)
    var_a = np.empty(96, dtype=np.float64)
    var_b = np.empty(96, dtype=np.float64)
    var_a[0:32], var_b[0:32] = 5000.0, 5000.0        # key: stable, high
    var_a[32:64], var_b[32:64] = 6000.0, 1000.0      # spurious: unstable
    var_a[64:96], var_b[64:96] = 500.0, 500.0        # heap: stable, low
    wvar = np.array([5000.0, 5500.0, 500.0])          # full-N: spurious outranks key
    return var_a, var_b, offsets, sizes, wvar


def test_subsample_experiment_demotes_unstable_clutter():
    var_a, var_b, offsets, sizes, wvar = _fixture()
    key_index = 0
    r = subsample_experiment(var_a, var_b, offsets, sizes, wvar, key_index, 50, 50)
    # By variance alone the spurious window outranks the key (r_var counts both).
    assert r.r_var == 2
    # Stability demotes the one-sided-high spurious window below the key.
    assert r.r_stable == 1
    assert r.beats_variance is True
    assert r.key_stability > 0.99          # key halves agree
    assert 0.19 < r.expected_rel_err < 0.21  # sqrt(2/49) ≈ 0.202
    assert r.maximal == 3


def test_subsample_experiment_degenerate_half():
    var_a, var_b, offsets, sizes, wvar = _fixture()
    r = subsample_experiment(var_a, var_b, offsets, sizes, wvar, 0, 1, 1)
    assert r.expected_rel_err == float("inf")


def test_load_halves_absent_and_present(tmp_path):
    assert load_halves(tmp_path) == (None, None, 0, 0)
    np.save(tmp_path / "variance_a.npy", np.full(64, 3.0, dtype=np.float32))
    np.save(tmp_path / "variance_b.npy", np.full(64, 4.0, dtype=np.float32))
    (tmp_path / "meta.json").write_text(
        '{"num_dumps": 100, "num_dumps_a": 50, "num_dumps_b": 50}')
    va, vb, na, nb = load_halves(tmp_path)
    assert va is not None and vb is not None
    assert na == 50 and nb == 50
    assert np.allclose(va, 3.0) and np.allclose(vb, 4.0)


def test_run_phase_a_wires_a3_when_halves_present():
    """End-to-end: run_phase_a attaches an A3 block only when halves are given."""
    from memdiver.engine.candidate_stats import run_phase_a
    rng = np.random.default_rng(7)
    total = 0x8000
    ref = np.full(total, 0x41, dtype=np.uint8)
    var = np.zeros(total, dtype=np.float64)
    key_off, ksize = 0x1000, 32
    ref[key_off:key_off + 256] = rng.integers(0, 256, size=256, dtype=np.uint8)
    var[key_off:key_off + 256] = 2156.0
    var_a = var * 1.05
    var_b = var * 0.95
    without = run_phase_a(var, ref.tobytes(), 100, key_off, key_size=ksize)
    assert without.subsample is None
    with_halves = run_phase_a(var, ref.tobytes(), 100, key_off, key_size=ksize,
                              var_a=var_a, var_b=var_b, num_a=50, num_b=50)
    assert with_halves.subsample is not None
    assert with_halves.subsample.num_dumps_a == 50
