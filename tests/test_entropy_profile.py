"""Tests for core.entropy_profile.EntropyProfile and its consumers.

``_compute_entropy_profile_reference`` / ``_find_high_entropy_regions_reference``
are verbatim copies of the pre-EntropyProfile implementation (list of tuples),
used to prove the new return value is element-for-element identical.
"""
import json
import math
import pickle
import random
import sys
import tracemalloc
from pathlib import Path

import numpy as np
import pytest
from numpy.lib.stride_tricks import sliding_window_view

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.algorithms.unknown_key.change_point import ChangePointAlgorithm
from memdiver.core.entropy import compute_entropy_profile, find_high_entropy_regions
from memdiver.core.entropy_profile import EntropyProfile
from memdiver.engine import coordinate_refine


# --- reference (old) implementation -------------------------------------

_REF_CHUNK_POSITIONS = 1 << 15


def _compute_entropy_profile_reference(data, window=32, step=1):
    data_len = len(data)
    if data_len < window:
        return []
    arr = np.frombuffer(data, dtype=np.uint8)
    offsets = np.arange(0, data_len - window + 1, step, dtype=np.int64)
    num_positions = offsets.shape[0]
    counts_range = np.arange(1, window + 1, dtype=np.float64)
    flut = np.zeros(window + 1, dtype=np.float64)
    flut[1:] = counts_range * np.log2(counts_range)
    windows = sliding_window_view(arr, window)
    log2_window = math.log2(window)
    entropies = np.empty(num_positions, dtype=np.float64)
    row_index = np.arange(_REF_CHUNK_POSITIONS, dtype=np.int64)
    for start in range(0, num_positions, _REF_CHUNK_POSITIONS):
        stop = min(start + _REF_CHUNK_POSITIONS, num_positions)
        rows = windows[offsets[start:stop]]
        slab = stop - start
        composite = (row_index[:slab, None] * 256 + rows).ravel()
        counts = np.bincount(composite, minlength=slab * 256).reshape(slab, 256)
        entropy_sum = flut[counts].sum(axis=1)
        entropies[start:stop] = log2_window - entropy_sum / window
    return list(zip(offsets.tolist(), entropies.tolist()))


def _find_high_entropy_regions_reference(profile, threshold=7.5, min_width=32):
    if not profile:
        return []
    regions = []
    in_region = False
    region_start = 0
    entropy_sum = 0.0
    region_count = 0
    for offset, entropy in profile:
        if entropy >= threshold:
            if not in_region:
                in_region = True
                region_start = offset
                entropy_sum = 0.0
                region_count = 0
            entropy_sum += entropy
            region_count += 1
        else:
            if in_region:
                region_end = offset
                if region_end - region_start >= min_width and region_count > 0:
                    regions.append((region_start, region_end, entropy_sum / region_count))
                in_region = False
    if in_region and region_count > 0:
        last_offset = profile[-1][0]
        step = profile[1][0] - profile[0][0] if len(profile) > 1 else 1
        region_end = last_offset + step
        if region_end - region_start >= min_width:
            regions.append((region_start, region_end, entropy_sum / region_count))
    return regions


def _mixed_dump(seed, size=40_000):
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        n = rng.randrange(1, 400)
        out += rng.randbytes(n) if rng.random() < 0.4 else bytes([rng.randrange(4)]) * n
    return bytes(out[:size])


CASES = [(seed, window, step)
         for seed in range(4)
         for window, step in [(32, 1), (32, 16), (8, 3), (48, 7), (64, 64)]]


# --- sequence semantics ---------------------------------------------------

def _small_profile():
    return EntropyProfile(np.array([0, 4, 8], dtype=np.int64),
                          np.array([1.5, 7.25, 3.0]))


def test_sequence_basics():
    p = _small_profile()
    assert len(p) == 3 and bool(p)
    assert p[0] == (0, 1.5) and p[-1] == (8, 3.0) and p[-3] == (0, 1.5)
    assert type(p[1][0]) is int and type(p[1][1]) is float
    assert list(p) == [(0, 1.5), (4, 7.25), (8, 3.0)]
    assert p.tolist() == list(p)
    assert (4, 7.25) in p and p.index((8, 3.0)) == 2
    assert list(reversed(p)) == [(8, 3.0), (4, 7.25), (0, 1.5)]
    with pytest.raises(IndexError):
        p[3]
    with pytest.raises(IndexError):
        p[-4]


def test_slicing_returns_profile():
    p = _small_profile()
    sliced = p[1:]
    assert isinstance(sliced, EntropyProfile)
    assert sliced == [(4, 7.25), (8, 3.0)]
    assert p[::2] == [(0, 1.5), (8, 3.0)]
    assert p[5:] == [] and not p[5:]


def test_equality_semantics():
    p = _small_profile()
    assert p == [(0, 1.5), (4, 7.25), (8, 3.0)]
    assert p == ((0, 1.5), (4, 7.25), (8, 3.0))
    assert p == EntropyProfile.from_pairs(list(p))
    assert p != [(0, 1.5), (4, 7.25)]
    assert p != [(0, 1.5), (4, 7.25), (8, 3.5)]
    assert p != [[0, 1.5], [4, 7.25], [8, 3.0]]  # like list-of-tuples == list-of-lists
    assert p != "not a profile"
    assert EntropyProfile.empty() == [] and not EntropyProfile.empty()


def test_read_only_and_arrays():
    p = _small_profile()
    offsets, values = p.as_arrays()
    assert offsets.dtype == np.int64 and values.dtype == np.float64
    with pytest.raises(ValueError):
        values[0] = 0.0
    with pytest.raises(TypeError):
        p[0] = (1, 2.0)
    with pytest.raises(TypeError):
        hash(p)


def test_source_arrays_not_frozen():
    raw = np.array([1.0, 2.0])
    EntropyProfile(np.array([0, 1]), raw)
    raw[0] = 3.0  # caller's array stays writable


def test_shape_mismatch_rejected():
    with pytest.raises(ValueError):
        EntropyProfile(np.arange(3), np.zeros(2))


def test_json_and_pickle():
    p = compute_entropy_profile(_mixed_dump(9, 2000), window=32, step=16)
    ref = _compute_entropy_profile_reference(_mixed_dump(9, 2000), window=32, step=16)
    assert json.dumps(list(p)) == json.dumps(ref)
    assert json.dumps([{"offset": o, "entropy": round(e, 4)} for o, e in p]) == \
        json.dumps([{"offset": o, "entropy": round(e, 4)} for o, e in ref])
    assert pickle.loads(pickle.dumps(p)) == p


def test_iteration_crosses_chunk_boundary():
    n = (1 << 16) + 5
    p = EntropyProfile(np.arange(n), np.linspace(0, 8, n))
    items = list(p)
    assert len(items) == n and items[-1] == p[-1] and items[1 << 16] == p[1 << 16]


# --- equality with the old list output -------------------------------------

@pytest.mark.parametrize("seed,window,step", CASES)
def test_profile_identical_to_reference(seed, window, step):
    data = _mixed_dump(seed)
    new = compute_entropy_profile(data, window=window, step=step)
    ref = _compute_entropy_profile_reference(data, window=window, step=step)
    assert isinstance(new, EntropyProfile)
    assert new == ref and new.tolist() == ref


def test_profile_identical_random_bytes():
    data = random.Random(99).randbytes(100_003)
    assert compute_entropy_profile(data) == _compute_entropy_profile_reference(data)


@pytest.mark.parametrize("length", [0, 1, 31, 32, 33])
def test_profile_short_inputs(length):
    data = bytes(range(length))
    assert compute_entropy_profile(data) == _compute_entropy_profile_reference(data)


@pytest.mark.parametrize("seed,window,step", CASES)
@pytest.mark.parametrize("threshold,min_width", [(7.5, 32), (4.5, 32), (2.0, 1), (0.0, 0)])
def test_high_entropy_regions_identical(seed, window, step, threshold, min_width):
    data = _mixed_dump(seed)
    new = compute_entropy_profile(data, window=window, step=step)
    ref = _compute_entropy_profile_reference(data, window=window, step=step)
    got = find_high_entropy_regions(new, threshold=threshold, min_width=min_width)
    want = _find_high_entropy_regions_reference(ref, threshold=threshold, min_width=min_width)
    assert got == want
    assert [tuple(map(type, r)) for r in got] == [tuple(map(type, r)) for r in want]
    # Plain-list input still goes through the iterative path, same answer.
    assert find_high_entropy_regions(ref, threshold=threshold, min_width=min_width) == want


def test_high_entropy_regions_single_point_profile():
    p = EntropyProfile(np.array([10]), np.array([8.0]))
    assert find_high_entropy_regions(p, 7.5, 1) == \
        _find_high_entropy_regions_reference([(10, 8.0)], 7.5, 1)


@pytest.mark.parametrize("seed", range(4))
def test_change_point_identical_for_list_and_profile(seed):
    data = _mixed_dump(seed)
    algo = ChangePointAlgorithm()
    new = compute_entropy_profile(data, window=32, step=16)
    ref = _compute_entropy_profile_reference(data, window=32, step=16)
    cps_new = algo._cusum_change_points(new)
    assert cps_new == algo._cusum_change_points(ref)
    got = algo._extract_plateaus(data, new, cps_new, 4.5, [32, 48], 32)
    want = algo._extract_plateaus(data, ref, cps_new, 4.5, [32, 48], 32)
    assert got == want


def test_pick_anchor_matches_first_max():
    rng = np.random.default_rng(3)
    for _ in range(20):
        region = rng.integers(0, rng.integers(2, 257), 512, dtype=np.uint8)
        ref = _compute_entropy_profile_reference(region.tobytes(), window=32, step=32)
        want = max(ref, key=lambda p: p[1])[0] if ref else 0
        assert coordinate_refine._pick_anchor(region, 32) == want


# --- memory ---------------------------------------------------------------

def _traced_peak(fn):
    tracemalloc.start()
    try:
        result = fn()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    del result
    return peak


def test_profile_memory_below_one_fifth_of_list():
    data = random.Random(5).randbytes(8 * 1024 * 1024)
    new_peak = _traced_peak(lambda: compute_entropy_profile(data, window=32, step=1))
    old_peak = _traced_peak(
        lambda: _compute_entropy_profile_reference(data, window=32, step=1))
    assert new_peak * 5 < old_peak, (new_peak, old_peak)
