"""Tests for core.variance shared module."""

import sys
from array import array
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core.variance import (
    ByteClass, DEFAULT_THRESHOLDS, INVARIANT_MAX, STRUCTURAL_MAX, POINTER_MAX,
    VarianceThresholds,
    class_mask, compute_variance, classify_variance,
    find_contiguous_runs, count_classifications, normalize_byte_classes,
    WelfordVariance,
)


def test_add_dump_slabbing_matches_whole_array(monkeypatch):
    """Slabbed add_dump is bit-identical to the whole-array update even when the
    slab boundary splits the byte range. (Welford is compared to Welford — the
    online recurrence differs from a two-pass np.var by float32 rounding, so the
    invariant is slab-vs-whole, not slab-vs-np.var.)
    """
    from memdiver.core import variance as var_mod

    dumps = [
        bytes([1, 2, 3, 4, 5, 6, 7]),
        bytes([9, 8, 7, 6, 5, 4, 3]),
        bytes([0, 255, 128, 64, 32, 16, 8]),
    ]

    def _fold(chunk):
        monkeypatch.setattr(var_mod, "CHUNK_BYTES", chunk)
        w = WelfordVariance(7)
        for d in dumps:
            w.add_dump(d)
        return w

    whole = _fold(1 << 20)   # single slab
    slabbed = _fold(3)       # slabs: [0,3) [3,6) [6,7)

    assert np.array_equal(whole.variance(), slabbed.variance())
    w_mean, w_m2, _ = whole.state_arrays()
    s_mean, s_m2, _ = slabbed.state_arrays()
    assert np.array_equal(w_mean, s_mean)
    assert np.array_equal(w_m2, s_m2)


def test_compute_variance_identical():
    data = bytes(range(256))
    buffers = [data, data, data]
    var = compute_variance(buffers, len(data))
    assert all(v == 0.0 for v in var)


def test_compute_variance_different():
    buf_a = b"\x00" * 10
    buf_b = b"\xff" * 10
    var = compute_variance([buf_a, buf_b], 10)
    # Var of [0, 255] = ((0-127.5)^2 + (255-127.5)^2)/2 = 16256.25
    assert all(abs(v - 16256.25) < 0.01 for v in var)


def test_compute_variance_empty():
    assert len(compute_variance([], 0)) == 0
    assert len(compute_variance([b"abc"], 0)) == 0


def test_classify_variance_thresholds():
    var = array("d", [0.0, 100.0, 200.0, 200.1, 3000.0, 3000.1])
    cls = classify_variance(var)
    assert cls[0] == ByteClass.INVARIANT      # 0.0
    assert cls[1] == ByteClass.STRUCTURAL     # 100.0 <= 200
    assert cls[2] == ByteClass.STRUCTURAL     # 200.0 <= 200
    assert cls[3] == ByteClass.POINTER        # 200.1 <= 3000
    assert cls[4] == ByteClass.POINTER        # 3000.0 <= 3000
    assert cls[5] == ByteClass.KEY_CANDIDATE  # 3000.1 > 3000


def test_find_contiguous_runs():
    cls = array("B", [0, 0, 3, 3, 3, 0, 3, 3])
    runs = find_contiguous_runs(cls, ByteClass.KEY_CANDIDATE)
    assert runs == [(2, 5), (6, 8)]


def test_find_contiguous_runs_empty():
    cls = array("B", [0, 0, 0])
    assert find_contiguous_runs(cls, ByteClass.KEY_CANDIDATE) == []


def test_count_classifications():
    cls = array("B", [0, 0, 1, 2, 3, 3])
    counts = count_classifications(cls)
    assert counts["invariant"] == 2
    assert counts["structural"] == 1
    assert counts["pointer"] == 1
    assert counts["key_candidate"] == 2


def test_byte_class_int_comparison():
    assert ByteClass.INVARIANT == 0
    assert ByteClass.KEY_CANDIDATE == 3


def test_chunked_matches_numpy_var():
    """Chunked two-pass must agree bit-for-bit with a full-stack np.var."""
    rng = np.random.default_rng(42)
    buffers = [rng.integers(0, 256, size=1 << 16, dtype=np.uint8).tobytes()
               for _ in range(7)]
    small = compute_variance(buffers, 1 << 16, chunk_bytes=4096)
    large = compute_variance(buffers, 1 << 16, chunk_bytes=1 << 16)
    mat = np.stack([np.frombuffer(b, dtype=np.uint8) for b in buffers]).astype(np.float32)
    expected = np.var(mat, axis=0)
    assert np.array_equal(small, expected)
    assert np.array_equal(large, expected)


def test_welford_matches_numpy_var():
    rng = np.random.default_rng(7)
    size = 8192
    buffers = [rng.integers(0, 256, size=size, dtype=np.uint8).tobytes()
               for _ in range(11)]
    w = WelfordVariance(size)
    for buf in buffers:
        w.add_dump(buf)
    mat = np.stack([np.frombuffer(b, dtype=np.uint8) for b in buffers]).astype(np.float32)
    expected = np.var(mat, axis=0)
    # Welford vs two-pass: rounding differences at most a few ULP.
    assert np.allclose(w.variance(), expected, rtol=1e-4, atol=1e-3)
    assert w.num_dumps == 11


def test_welford_incremental_equals_batch():
    rng = np.random.default_rng(13)
    size = 4096
    buffers = [rng.integers(0, 256, size=size, dtype=np.uint8).tobytes()
               for _ in range(5)]
    incremental = WelfordVariance(size)
    for buf in buffers:
        incremental.add_dump(buf)
    batch = compute_variance(buffers, size)
    assert np.allclose(incremental.variance(), batch, rtol=1e-4, atol=1e-3)


def test_welford_reset_and_from_state():
    w = WelfordVariance(16)
    w.add_dump(b"\x01" * 16)
    w.add_dump(b"\x03" * 16)
    mean, m2, n = w.state_arrays()
    rebuilt = WelfordVariance.from_state(mean.copy(), m2.copy(), n)
    assert rebuilt.num_dumps == 2
    assert np.array_equal(rebuilt.variance(), w.variance())
    w.reset()
    assert w.num_dumps == 0
    assert np.all(w.variance() == 0)


# ---------------------------------------------------------------------------
# Configurable class boundaries (A2)
# ---------------------------------------------------------------------------

# One value per band plus both sides of every boundary, so a shifted threshold
# cannot pass by accident.
_BOUNDARY_PROBE = [0.0, 0.5, 200.0, 200.1, 3000.0, 3000.1]
_BOUNDARY_EXPECTED = [
    ByteClass.INVARIANT,
    ByteClass.STRUCTURAL,
    ByteClass.STRUCTURAL,
    ByteClass.POINTER,
    ByteClass.POINTER,
    ByteClass.KEY_CANDIDATE,
]


def test_default_thresholds_are_todays_constants():
    assert DEFAULT_THRESHOLDS == (INVARIANT_MAX, STRUCTURAL_MAX, POINTER_MAX)
    assert DEFAULT_THRESHOLDS == (0.0, 200.0, 3000.0)


def test_classify_variance_default_boundaries_unchanged():
    """Omitted thresholds must reproduce the historical hard-coded bands."""
    result = classify_variance(np.array(_BOUNDARY_PROBE, dtype=np.float32))
    assert list(result) == _BOUNDARY_EXPECTED


def test_classify_variance_explicit_defaults_match_omitted():
    probe = np.array(_BOUNDARY_PROBE, dtype=np.float32)
    assert np.array_equal(
        classify_variance(probe), classify_variance(probe, DEFAULT_THRESHOLDS)
    )


def test_classify_variance_custom_thresholds_reclassify():
    """Widening the bands moves bytes down a class, and only that."""
    probe = np.array(_BOUNDARY_PROBE, dtype=np.float32)
    wide = VarianceThresholds(invariant_max=0.5, structural_max=3000.0,
                              pointer_max=1e9)
    result = classify_variance(probe, wide)
    assert list(result) == [
        ByteClass.INVARIANT,     # 0.0   <= 0.5
        ByteClass.INVARIANT,     # 0.5   <= 0.5
        ByteClass.STRUCTURAL,    # 200.0 <= 3000
        ByteClass.STRUCTURAL,
        ByteClass.STRUCTURAL,    # 3000.0 <= 3000
        ByteClass.POINTER,       # 3000.1 <= 1e9
    ]


def test_classify_variance_tight_thresholds_promote():
    probe = np.array(_BOUNDARY_PROBE, dtype=np.float32)
    tight = VarianceThresholds(invariant_max=0.0, structural_max=0.4,
                               pointer_max=199.0)
    result = classify_variance(probe, tight)
    assert list(result) == [
        ByteClass.INVARIANT,        # 0.0
        ByteClass.POINTER,          # 0.5   > 0.4, <= 199
        ByteClass.KEY_CANDIDATE,    # 200.0 > 199 — POINTER by default
        ByteClass.KEY_CANDIDATE,
        ByteClass.KEY_CANDIDATE,
        ByteClass.KEY_CANDIDATE,
    ]


def test_thresholds_reject_unordered_bands():
    with pytest.raises(ValueError, match="non-decreasing"):
        classify_variance(np.zeros(4, dtype=np.float32),
                          VarianceThresholds(0.0, 3000.0, 200.0))


def test_thresholds_reject_negative_invariant_max():
    with pytest.raises(ValueError, match="invariant_max"):
        VarianceThresholds(invariant_max=-1.0).validate()


# ---------------------------------------------------------------------------
# Class query helpers
# ---------------------------------------------------------------------------


def test_normalize_byte_classes_accepts_single_and_iterable():
    assert normalize_byte_classes(ByteClass.POINTER) == (ByteClass.POINTER,)
    assert normalize_byte_classes(2) == (ByteClass.POINTER,)
    assert normalize_byte_classes([ByteClass.KEY_CANDIDATE, ByteClass.POINTER]) == (
        ByteClass.POINTER, ByteClass.KEY_CANDIDATE,
    )


def test_normalize_byte_classes_dedupes_and_rejects_empty():
    assert normalize_byte_classes([1, 1, 1]) == (ByteClass.STRUCTURAL,)
    with pytest.raises(ValueError, match="at least one"):
        normalize_byte_classes([])


def test_normalize_byte_classes_rejects_unknown_code():
    with pytest.raises(ValueError):
        normalize_byte_classes(9)


def test_class_mask_selects_union_of_classes():
    codes = np.array([0, 1, 2, 3, 2], dtype=np.uint8)
    mask = class_mask(codes, (ByteClass.POINTER, ByteClass.KEY_CANDIDATE))
    assert list(mask) == [False, False, True, True, True]


def test_class_mask_accepts_stdlib_array():
    codes = array("B", [0, 3, 3, 0])
    mask = class_mask(codes, (ByteClass.KEY_CANDIDATE,))
    assert list(mask) == [False, True, True, False]
