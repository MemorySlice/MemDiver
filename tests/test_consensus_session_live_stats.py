"""Slab-wise ``ConsensusSession.live_stats`` vs the original whole-vector code.

``mean_variance`` / ``max_variance`` must be bit-identical. ``top_offsets``
must be identical whenever the top-k has no ties; with ties the original
``argpartition`` order is unspecified, so the new deterministic order
(descending variance, ascending offset) is checked against a full-sort
oracle and the reference is checked for equal sorted variances.
"""

import time
import tracemalloc

import numpy as np
import pytest

import memdiver.core.variance as variance_mod
from memdiver.api.services.consensus_session import ConsensusSession
from memdiver.core.variance import RunningTopK, WelfordVariance, pairwise_leaves_sum
from memdiver.engine.consensus import ConsensusVector


def reference_live_stats(variance):
    """Verbatim copy of the pre-slab ``ConsensusSession.live_stats`` body."""
    if len(variance) == 0:
        return {"mean_variance": 0.0, "max_variance": 0.0, "top_offsets": []}
    k = min(5, len(variance))
    unsorted_top = np.argpartition(variance, -k)[-k:]
    top_idx = unsorted_top[np.argsort(variance[unsorted_top])[::-1]].tolist()
    return {
        "mean_variance": float(variance.mean()),
        "max_variance": float(variance.max()),
        "top_offsets": [
            {"offset": int(i), "variance": float(variance[i])} for i in top_idx
        ],
    }


def oracle_top(variance, k=5):
    order = np.lexsort((np.arange(len(variance)), -variance.astype(np.float64)))
    return [{"offset": int(i), "variance": float(variance[i])} for i in order[:k]]


def _session(matrix, size):
    return ConsensusSession("s", size, time.time(), time.time(), matrix)


def _welford_session(m2, n):
    matrix = ConsensusVector()
    matrix.build_incremental(len(m2))
    matrix._welford = WelfordVariance.from_state(np.zeros_like(m2), m2, n)
    return _session(matrix, len(m2))


def _assert_matches(session, variance):
    got = session.live_stats()
    ref = reference_live_stats(variance)
    assert got["mean_variance"] == ref["mean_variance"]
    assert got["max_variance"] == ref["max_variance"]
    assert got["top_offsets"] == oracle_top(variance)
    ref_vals = sorted(t["variance"] for t in ref["top_offsets"])
    assert sorted(t["variance"] for t in got["top_offsets"]) == ref_vals
    if len(set(variance.tolist())) == len(variance):  # no ties at all
        assert got["top_offsets"] == ref["top_offsets"]
    return got


@pytest.fixture
def small_leaf(monkeypatch):
    monkeypatch.setattr(variance_mod, "PAIRWISE_LEAF", 256)


SIZES = [1, 2, 4, 5, 6, 127, 128, 129, 255, 256, 257, 1000, 4099, 65_537]


@pytest.mark.parametrize("size", SIZES)
def test_random_welford_state_matches_reference(small_leaf, size):
    rng = np.random.default_rng(size)
    for n, scale in ((1, 1.0), (3, 1000.0), (17, 65025.0)):
        m2 = (rng.random(size, dtype=np.float32) * scale * n).astype(np.float32)
        variance = WelfordVariance.from_state(np.zeros_like(m2), m2, n).variance()
        _assert_matches(_welford_session(m2, n), variance)


@pytest.mark.parametrize("size", [5, 300, 1025, 5000])
def test_ties_and_all_equal(small_leaf, size):
    rng = np.random.default_rng(7)
    few_levels = rng.integers(0, 3, size).astype(np.float32) * 4
    for m2 in (np.zeros(size, np.float32), np.full(size, 9.0, np.float32), few_levels):
        variance = WelfordVariance.from_state(np.zeros_like(m2), m2, 2).variance()
        got = _assert_matches(_welford_session(m2, 2), variance)
        assert len(got["top_offsets"]) == 5


def test_k_larger_than_size_and_empty(small_leaf):
    for size in (1, 3, 4):
        m2 = np.arange(size, dtype=np.float32)
        got = _assert_matches(_welford_session(m2, 1), m2.copy())
        assert len(got["top_offsets"]) == size
    assert _welford_session(np.zeros(0, np.float32), 1).live_stats() == \
        reference_live_stats(np.zeros(0, np.float32))


def test_zero_dumps_reports_zeros(small_leaf):
    session = _welford_session(np.zeros(700, np.float32), 0)
    _assert_matches(session, np.zeros(700, np.float32))


def test_real_incremental_and_finalized_matrix(small_leaf):
    rng = np.random.default_rng(3)
    size = 3001
    matrix = ConsensusVector()
    matrix.build_incremental(size)
    for _ in range(4):
        matrix.add_source(rng.integers(0, 256, size, dtype=np.uint8).tobytes())
    session = _session(matrix, size)
    _assert_matches(session, matrix.get_live_variance())
    matrix.finalize()
    _assert_matches(session, matrix.get_live_variance())


def test_default_leaf_size_not_multiple_of_slab():
    size = 2 * variance_mod.PAIRWISE_LEAF + 12_345
    rng = np.random.default_rng(11)
    m2 = (rng.random(size, dtype=np.float32) * 9000).astype(np.float32)
    variance = WelfordVariance.from_state(np.zeros_like(m2), m2, 3).variance()
    _assert_matches(_welford_session(m2, 3), variance)


def test_pairwise_leaves_sum_equals_numpy_sum():
    rng = np.random.default_rng(5)
    for size in (1, 129, 1000, 10_007):
        v = (rng.random(size, dtype=np.float32) * 1e4).astype(np.float32)
        total = pairwise_leaves_sum(size, lambda s, e, v=v: np.add.reduce(v[s:e]), 128)
        assert total == np.add.reduce(v)
    with pytest.raises(ValueError):
        pairwise_leaves_sum(10, lambda s, e: None, 64)


def test_running_top_k_tie_break_lowest_offset():
    top = RunningTopK(3)
    top.add_slab(np.array([1.0, 5.0, 5.0], np.float32), 0)
    top.add_slab(np.array([5.0, 7.0, 1.0], np.float32), 3)
    assert top.result() == [(4, 7.0), (1, 5.0), (2, 5.0)]


def test_live_stats_peak_memory_is_bounded():
    """64 Mi positions: the old path peaked at ~12 B/position (768 MiB)."""
    size = 64 * 1024 * 1024
    m2 = np.ones(size, dtype=np.float32)
    m2[12345] = 9.0
    session = _welford_session(m2, 2)
    tracemalloc.start()
    stats = session.live_stats()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert stats["top_offsets"][0] == {"offset": 12345, "variance": 4.5}
    assert peak < 32 * 1024 * 1024, peak
