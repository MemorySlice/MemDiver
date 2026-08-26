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


# ── B4: streaming enumeration + PairMembership (equivalence gates) ────
#
# These pin the three cost fixes measured by tools/bench_auto_floor_memory.py.
# Each fix is a pure cost change, so every test below asserts EQUIVALENCE to
# the eager form it replaced — never merely "the new thing runs".


def _grid_regions():
    from memdiver.engine.candidate_pipeline import CandidateRegion
    return [
        CandidateRegion(offset=0, length=200, mean_entropy=4.9, mean_variance=5000.0),
        CandidateRegion(offset=311, length=97, mean_entropy=4.8, mean_variance=4000.0),
        CandidateRegion(offset=900, length=16, mean_entropy=4.7, mean_variance=3500.0),
    ]


def test_iter_candidates_matches_enumerate_candidates():
    from memdiver.engine.floor_policy import enumerate_candidates, iter_candidates
    regions = _grid_regions()
    for stride in (1, 4, 8, 16):
        for key_sizes in ((32,), (16, 32), (8, 24, 48)):
            eager = enumerate_candidates(regions, 1024, key_sizes, stride)
            streamed = list(iter_candidates(regions, 1024, key_sizes, stride))
            assert streamed == eager, (stride, key_sizes)


def test_count_candidates_matches_iter_candidates():
    from memdiver.engine.floor_policy import count_candidates, iter_candidates
    regions = _grid_regions()
    for stride in (1, 3, 8, 64):
        for key_sizes in ((32,), (16, 32), (8, 24, 48)):
            expected = sum(1 for _ in iter_candidates(regions, 1024, key_sizes, stride))
            assert count_candidates(regions, 1024, key_sizes, stride) == expected


def test_count_candidates_zero_for_empty_regions():
    from memdiver.engine.floor_policy import count_candidates
    assert count_candidates([], 1024, (32,), 1) == 0


def test_pair_membership_matches_a_plain_set():
    from memdiver.engine.floor_policy import PairMembership
    rng = np.random.default_rng(7)
    offsets = rng.integers(0, 50_000, size=4000)
    sizes = rng.choice([16, 24, 32, 48], size=4000)
    reference = set(zip(offsets.tolist(), sizes.tolist()))
    membership = PairMembership(offsets, sizes)

    assert len(membership) == len(offsets)          # pre-dedup, like the array
    assert set(membership) == reference             # iteration round-trips
    # Every member is found, and a dense probe grid never disagrees with the set.
    for pair in reference:
        assert pair in membership
    for off in range(0, 50_000, 97):
        for size in (8, 16, 24, 32, 48, 64):
            assert ((off, size) in membership) == ((off, size) in reference)


def test_pair_membership_rejects_out_of_range_and_malformed():
    from memdiver.engine.floor_policy import PairMembership
    membership = PairMembership(np.array([10, 20]), np.array([32, 32]))
    assert (10, 32) in membership
    assert (10, 33) not in membership   # size above the encoded scale
    assert (10, -1) not in membership
    assert (11, 32) not in membership
    assert "not-a-pair" not in membership   # unpacks to 10 items -> ValueError
    assert "ab" not in membership           # unpacks, but int("a") -> ValueError
    assert (1, 2, 3) not in membership
    assert 42 not in membership
    assert None not in membership


def test_pair_membership_empty_is_empty():
    from memdiver.engine.floor_policy import PairMembership
    membership = PairMembership(np.empty(0, dtype=np.int64), np.empty(0, dtype=np.int64))
    assert len(membership) == 0
    assert list(membership) == []
    assert (0, 32) not in membership


def test_entropy_cache_reuse_is_byte_identical():
    """The shared entropy profile must not change ANY reduce output."""
    from memdiver.engine.candidate_pipeline import reduce_search_space
    rng = np.random.default_rng(11)
    reference = rng.integers(0, 256, size=20_000, dtype=np.uint8).tobytes()
    variance = rng.uniform(2500.0, 5400.0, size=20_000)

    def regions_at(min_variance, cache):
        res = reduce_search_space(variance, reference, 5, min_variance=min_variance,
                                  entropy_threshold=4.0, entropy_cache=cache)
        return [(r.offset, r.length, r.mean_entropy) for r in res.regions]

    cache: dict = {}
    cached_lo = regions_at(0.0, cache)
    cached_hi = regions_at(3000.0, cache)      # second call must HIT the cache
    assert cache.get("profile") is not None
    assert regions_at(0.0, None) == cached_lo
    assert regions_at(3000.0, None) == cached_hi
    assert cached_lo != [] and cached_hi != []


def test_entropy_cache_never_hits_for_a_different_buffer():
    """A cache filled from one buffer must not leak into another."""
    from memdiver.engine.candidate_pipeline import reduce_search_space
    rng = np.random.default_rng(13)
    a = rng.integers(0, 256, size=8_000, dtype=np.uint8).tobytes()
    b = bytes(8_000)                            # same length, zero entropy
    variance = np.full(8_000, 5000.0)

    cache: dict = {}
    reduce_search_space(variance, a, 5, entropy_threshold=4.0, entropy_cache=cache)
    shared = reduce_search_space(variance, b, 5, entropy_threshold=4.0,
                                 entropy_cache=cache)
    fresh = reduce_search_space(variance, b, 5, entropy_threshold=4.0)
    assert [(r.offset, r.length) for r in shared.regions] == \
           [(r.offset, r.length) for r in fresh.regions]
    assert shared.regions == []                 # zero-entropy buffer keeps nothing
