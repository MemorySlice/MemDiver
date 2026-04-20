"""Tests for core.entropy module.

Covers entropy_from_freq, shannon_entropy, compute_entropy_profile,
and find_high_entropy_regions with edge cases and typical inputs.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.entropy import (
    entropy_from_freq,
    shannon_entropy,
    compute_entropy_profile,
    find_high_entropy_regions,
)


def test_entropy_from_freq_zero_total():
    """Zero total returns 0.0 entropy."""
    freq = [0] * 256
    assert entropy_from_freq(freq, 0) == 0.0


def test_entropy_from_freq_uniform():
    """Uniform distribution over all 256 byte values yields 8.0 bits."""
    freq = [1] * 256
    result = entropy_from_freq(freq, 256)
    assert abs(result - 8.0) < 1e-9


def test_entropy_from_freq_single_value():
    """All counts in one bin yields 0.0 entropy (no uncertainty)."""
    freq = [0] * 256
    freq[42] = 100
    assert entropy_from_freq(freq, 100) == 0.0


def test_shannon_entropy_empty():
    """Empty byte string yields 0.0 entropy."""
    assert shannon_entropy(b"") == 0.0


def test_shannon_entropy_uniform_byte():
    """Repeated single byte value yields 0.0 entropy."""
    assert shannon_entropy(b"\x42" * 1000) == 0.0


def test_shannon_entropy_random():
    """Random bytes should produce entropy approximately between 7.0 and 8.0."""
    data = os.urandom(1024)
    result = shannon_entropy(data)
    assert 7.0 <= result <= 8.0


def test_compute_entropy_profile_short_data():
    """Data shorter than window size returns empty profile."""
    data = b"\x00" * 16
    result = compute_entropy_profile(data, window=32, step=1)
    assert result == []


def test_compute_entropy_profile_step_1():
    """100 zero bytes with window=32, step=1 produces 69 profile entries."""
    data = b"\x00" * 100
    profile = compute_entropy_profile(data, window=32, step=1)
    expected_length = 100 - 32 + 1  # 69
    assert len(profile) == expected_length
    # All zeros should have 0.0 entropy everywhere
    for offset, entropy in profile:
        assert entropy == 0.0


def test_compute_entropy_profile_step_16():
    """256 bytes with window=32, step=16: check length and offset alignment."""
    data = b"\x00" * 256
    profile = compute_entropy_profile(data, window=32, step=16)
    # Positions: 0, 16, 32, ..., up to 256-32=224 -> 0,16,...,224 = 15 entries
    expected_length = len(range(0, 256 - 32 + 1, 16))
    assert len(profile) == expected_length
    # All offsets should be multiples of 16
    for offset, _ in profile:
        assert offset % 16 == 0


def test_find_high_entropy_no_regions():
    """All-zero data produces no high-entropy regions."""
    profile = [(i, 0.0) for i in range(100)]
    result = find_high_entropy_regions(profile, threshold=7.5, min_width=32)
    assert result == []


def test_find_high_entropy_min_width_filter():
    """Region narrower than min_width is filtered out."""
    # Create a short high-entropy spike of 10 offsets, then low
    profile = []
    for i in range(100):
        if 20 <= i < 30:
            profile.append((i, 7.8))
        else:
            profile.append((i, 1.0))
    # Region spans offset 20 to 30 = width 10, less than min_width=32
    result = find_high_entropy_regions(profile, threshold=7.5, min_width=32)
    assert result == []
