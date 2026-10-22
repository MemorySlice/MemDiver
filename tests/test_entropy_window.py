"""Fast sliding-window entropy primitives (``core/entropy_window``).

``entropy_from_window_rows`` must equal ``entropy_from_freq_batch`` bit for
bit; ``sliding_entropy_estimate`` must stay within ``ESTIMATE_TOLERANCE``.
"""
import math
import random

import numpy as np
import pytest
from numpy.lib.stride_tricks import sliding_window_view

from memdiver.core.entropy import entropy_from_freq, entropy_from_freq_batch, entropy_term_lut
from memdiver.core.entropy_window import (
    ESTIMATE_TOLERANCE,
    entropy_from_window_rows,
    fixed_point_bits,
    sliding_entropy_estimate,
    supports_estimate,
)

WINDOWS = [1, 2, 3, 16, 32, 48, 64, 255, 256, 300]


def _histograms(rows: np.ndarray) -> np.ndarray:
    counts = np.zeros((rows.shape[0], 256), dtype=np.int64)
    np.add.at(counts, (np.arange(rows.shape[0])[:, None], rows), 1)
    return counts


def _inputs():
    rng = random.Random(5)
    return {
        "random": rng.randbytes(3000),
        "zeros": bytes(700),
        "ascii": b"session key material 0123456789 " * 60,
        "low_alphabet": bytes(rng.randrange(4) for _ in range(2000)),
        "uniform_blocks": b"".join(bytes(rng.sample(range(256), k)) * 3
                                   for k in (16, 23, 32, 48, 64, 128)),
        "all_bytes": bytes(range(256)) * 3,
    }


def test_entropy_term_lut_matches_scalar_terms():
    for total in (1, 7, 32, 300):
        lut = entropy_term_lut(total)
        assert lut[0] == 0.0 and lut.shape == (total + 1,)
        for count in range(1, total + 1):
            p = count / total
            assert lut[count] == p * math.log2(p)


@pytest.mark.parametrize("name", sorted(_inputs()))
@pytest.mark.parametrize("window", WINDOWS)
def test_window_rows_bit_identical_to_freq_batch(name, window):
    values = np.frombuffer(_inputs()[name], dtype=np.uint8)
    if values.shape[0] < window:
        pytest.skip("input shorter than window")
    rows = sliding_window_view(values, window)
    expected = entropy_from_freq_batch(_histograms(rows), window)
    got = entropy_from_window_rows(rows, window)
    assert np.array_equal(got, expected)
    assert not np.signbit(got).any()  # +0.0, never -0.0, like the reference


def test_window_rows_scalar_spot_check_and_empty():
    rows = np.frombuffer(bytes(range(32)) + bytes(32) + b"ab" * 16, np.uint8).reshape(3, 32)
    got = entropy_from_window_rows(rows, 32)
    for row, value in zip(rows, got):
        assert value == entropy_from_freq(list(np.bincount(row, minlength=256)), 32)
    assert got[1] == 0.0 and not np.signbit(got[1])
    assert entropy_from_window_rows(np.empty((0, 8), np.uint8), 8).shape == (0,)


@pytest.mark.parametrize("name", sorted(_inputs()))
@pytest.mark.parametrize("window", WINDOWS)
def test_estimate_within_tolerance(name, window):
    values = np.frombuffer(_inputs()[name], dtype=np.uint8)
    estimate = sliding_entropy_estimate(values, window)
    if values.shape[0] < window:
        assert estimate.shape == (0,)
        return
    rows = sliding_window_view(values, window)
    exact = entropy_from_freq_batch(_histograms(rows), window)
    assert estimate.shape == exact.shape
    assert np.abs(estimate - exact).max() < ESTIMATE_TOLERANCE / 1000


def test_estimate_single_window_and_segment_independence():
    values = np.frombuffer(random.Random(3).randbytes(500), dtype=np.uint8)
    full = sliding_entropy_estimate(values, 32)
    assert np.array_equal(sliding_entropy_estimate(values[100:132], 32), full[100:101])
    assert np.array_equal(sliding_entropy_estimate(values[100:300], 32), full[100:269])


def test_fixed_point_bits_and_support():
    assert fixed_point_bits(0) is None and not supports_estimate(0)
    assert fixed_point_bits(32) == 44 and supports_estimate(1)
    assert supports_estimate(1 << 16)
    assert not supports_estimate(1 << 22)
    with pytest.raises(ValueError):
        sliding_entropy_estimate(np.zeros(10, np.uint8), 1 << 22)
