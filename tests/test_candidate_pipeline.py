"""Tests for engine.candidate_pipeline — search-space reduction."""

import numpy as np
import pytest

from engine.candidate_pipeline import (
    MIN_N_FOR_VARIANCE,
    ReductionResult,
    reduce_search_space,
)


def _synth_dump(size: int, key_offset: int, key_length: int, seed: int = 42):
    rng = np.random.default_rng(seed)
    data = bytearray(size)
    key = rng.integers(0, 256, key_length, dtype=np.uint8).tobytes()
    data[key_offset:key_offset + key_length] = key
    variance = np.zeros(size, dtype=np.float32)
    variance[key_offset:key_offset + key_length] = 15000.0
    return bytes(data), variance


def test_finds_planted_key_at_n_threshold():
    data, variance = _synth_dump(1024, 256, 32)
    result = reduce_search_space(variance, data, num_dumps=5)
    assert isinstance(result, ReductionResult)
    assert not result.fallback_entropy_only
    assert len(result.regions) == 1
    assert result.regions[0].offset == 256
    assert result.regions[0].length == 32
    assert result.stages.high_entropy == 32


def test_n_below_threshold_falls_back_to_entropy_only():
    data, variance = _synth_dump(1024, 256, 32)
    result = reduce_search_space(variance, data, num_dumps=1)
    assert result.fallback_entropy_only
    assert result.num_dumps < MIN_N_FOR_VARIANCE
    assert result.stages.variance == len(variance)


def test_unreachable_entropy_threshold_raises():
    data, variance = _synth_dump(1024, 256, 32)
    with pytest.raises(ValueError, match="log2"):
        reduce_search_space(
            variance, data, num_dumps=5,
            entropy_window=32, entropy_threshold=6.0,
        )


def test_variance_size_mismatch_raises():
    data = b"\x00" * 512
    variance = np.zeros(1024, dtype=np.float32)
    with pytest.raises(ValueError, match="reference dump shorter"):
        reduce_search_space(variance, data, num_dumps=5)


def test_serializes_round_trip():
    data, variance = _synth_dump(1024, 256, 32)
    result = reduce_search_space(variance, data, num_dumps=5)
    d = result.to_dict()
    assert d["N"] == 5
    assert d["fallback_entropy_only"] is False
    assert d["stages"]["total_bytes"] == 1024
    assert len(d["regions"]) == 1
    assert d["regions"][0]["offset"] == 256
    assert d["thresholds"]["alignment"] == 8


def test_empty_dump():
    variance = np.array([], dtype=np.float32)
    result = reduce_search_space(variance, b"", num_dumps=5)
    assert result.regions == []
    assert result.stages.total_bytes == 0
