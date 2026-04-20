"""Tests for core.region_analysis module."""

import os
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.region_analysis import (
    RegionReport,
    analyze_region,
    find_pattern,
    parse_hex_pattern,
)


def test_analyze_region_zeros():
    """All-zero data should produce low entropy."""
    data = b"\x00" * 256
    report = analyze_region(data, offset=128)
    assert report.entropy_level == "low"
    assert report.entropy < 2.0
    assert report.byte_value == 0


def test_analyze_region_random():
    """Pseudorandom data should produce high or random entropy."""
    # Use all 256 byte values repeated to get near-max entropy.
    data = bytes(range(256)) * 4
    report = analyze_region(data, offset=128, window=64)
    assert report.entropy_level in ("high", "random")
    assert report.entropy >= 5.0


def test_analyze_region_with_variance():
    """Variance at offset should be reported and classified."""
    data = b"\x00" * 256
    variance = [0.0] * 256
    variance[128] = 75.0
    report = analyze_region(data, offset=128, variance=variance)
    assert report.variance_at_offset == 75.0
    assert report.variance_class == "medium"


def test_analyze_region_with_hits():
    """Hits covering the offset should appear in matching_secrets."""
    data = b"\xaa" * 256
    hit = SimpleNamespace(offset=100, length=50)
    report = analyze_region(data, offset=120, hits=[hit])
    assert len(report.matching_secrets) == 1
    assert report.matching_secrets[0] is hit


def test_analyze_region_hit_miss():
    """Hit that does not cover the offset should not match."""
    data = b"\xbb" * 256
    hit = SimpleNamespace(offset=200, length=10)
    report = analyze_region(data, offset=50, hits=[hit])
    assert len(report.matching_secrets) == 0


def test_find_pattern_found():
    """Single occurrence should return one offset."""
    data = b"hello world"
    offsets = find_pattern(data, b"world")
    assert offsets == [6]


def test_find_pattern_not_found():
    """No match should return empty list."""
    data = b"hello world"
    offsets = find_pattern(data, b"xyz")
    assert offsets == []


def test_find_pattern_multiple():
    """Multiple occurrences should all be returned."""
    data = b"abcabcabc"
    offsets = find_pattern(data, b"abc")
    assert offsets == [0, 3, 6]


def test_find_pattern_max_results():
    """Results should be capped at max_results."""
    data = b"aaaa"
    offsets = find_pattern(data, b"a", max_results=2)
    assert len(offsets) == 2


def test_parse_hex_pattern_spaces():
    """Space-separated hex should parse correctly."""
    result = parse_hex_pattern("48 65 6c")
    assert result == b"Hel"


def test_parse_hex_pattern_no_spaces():
    """Continuous hex should parse correctly."""
    result = parse_hex_pattern("deadbeef")
    assert result == b"\xde\xad\xbe\xef"


def test_parse_hex_pattern_invalid():
    """Invalid hex should return None."""
    result = parse_hex_pattern("not hex!")
    assert result is None


def test_parse_hex_pattern_empty():
    """Empty string should return None."""
    result = parse_hex_pattern("")
    assert result is None
