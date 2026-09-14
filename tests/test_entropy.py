"""Tests for core.entropy module.

Covers entropy_from_freq, shannon_entropy, compute_entropy_profile,
and find_high_entropy_regions with edge cases and typical inputs.
"""
import math
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.app.tools_inspect import (
    MAX_ENTROPY_PROFILE_POSITIONS,
    _bounded_entropy_step,
)
from memdiver.core.entropy import (
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


def test_find_high_entropy_trailing_region_exclusive_end():
    """Trailing region uses the same exclusive-end convention as interior ones.

    A high-entropy run that reaches the end of the profile must report
    region_end = last_offset + step (exclusive), matching how an interior
    close uses the first below-threshold offset as an exclusive end. With the
    old inclusive convention (region_end = last_offset) the width was one step
    short, which could drop a trailing region the interior convention keeps.
    """
    # step=1: offsets 0..49 high entropy, runs to the end of the profile.
    profile = [(i, 7.8) for i in range(50)]
    result = find_high_entropy_regions(profile, threshold=7.5, min_width=32)
    assert len(result) == 1
    start, end, _ = result[0]
    assert start == 0
    # last_offset is 49, step is 1 -> exclusive end 50.
    assert end == 50


def test_find_high_entropy_trailing_region_respects_step():
    """Trailing exclusive-end honors the profile step spacing."""
    # step=16: offsets 0,16,...,496. Last in-region start 496 -> end 512.
    profile = [(i, 7.8) for i in range(0, 512, 16)]
    result = find_high_entropy_regions(profile, threshold=7.5, min_width=32)
    assert len(result) == 1
    start, end, _ = result[0]
    assert start == 0
    assert end == 496 + 16


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


def _shannon_reference(data: bytes) -> float:
    """The pure-Python implementation `shannon_entropy` replaced.

    Kept here, in the test, as the oracle: the point of the change was speed,
    so the only thing that must not move is the answer.
    """
    total = len(data)
    if total == 0:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    return entropy_from_freq(freq, total)


def test_shannon_entropy_matches_the_scalar_reference():
    """Vectorising must not change the number, only how long it takes."""
    cases = [
        b"",
        b"\x00",
        b"A" * 1000,
        bytes(range(256)),
        bytes(range(256)) * 37,
        os.urandom(200_000),
        b"\x00" * 100_000 + os.urandom(100_000),
    ]
    for data in cases:
        assert shannon_entropy(data) == pytest.approx(
            _shannon_reference(data), abs=1e-12
        ), f"diverged on {len(data)} bytes"


def test_shannon_entropy_handles_a_bytearray():
    """`read_range` is typed as returning bytes, but callers pass buffers too."""
    payload = bytearray(os.urandom(4096))
    assert shannon_entropy(payload) == pytest.approx(
        _shannon_reference(bytes(payload)), abs=1e-12
    )


def test_bounded_entropy_step_leaves_ordinary_dumps_alone():
    """Below the cap the requested step is used verbatim — no silent coarsening."""
    for size in (0, 1, 4096, 1 << 20, 4 * 1024 * 1024):
        assert _bounded_entropy_step(size, 32, 16) == 16


def test_bounded_entropy_step_bounds_the_position_count():
    """Above the cap the step widens just far enough, and never further."""
    for size in (8 * 1024 * 1024, 64 * 1024 * 1024, 220_079_200):
        step = _bounded_entropy_step(size, 32, 16)
        positions = size - 32 + 1
        visited = (positions + step - 1) // step
        assert visited <= MAX_ENTROPY_PROFILE_POSITIONS
        assert step > 16, "a dump this size must have been widened"
        # One step narrower would have blown the cap — i.e. not over-coarsened.
        narrower = (positions + step - 2) // (step - 1)
        assert narrower > MAX_ENTROPY_PROFILE_POSITIONS


def test_bounded_entropy_step_never_returns_zero():
    """A caller-supplied step of 0 or less must not produce a division by zero."""
    for bad in (0, -1, -100):
        assert _bounded_entropy_step(1 << 30, 32, bad) >= 1


def test_widening_the_step_preserves_high_entropy_coverage():
    """The cap trades resolution for cost — it must not lose the regions.

    Random blocks are planted in low-entropy filler; the widened step must still
    find them, covering essentially the same bytes. A 32-byte window cannot
    exceed log2(32) = 5.0 bits/byte, so the threshold here is one that is
    actually reachable (see `test_default_threshold_is_unreachable_for_window_32`).
    """
    filler = bytearray(b"\x41\x42\x43\x44" * ((8 * 1024 * 1024) // 4))
    planted = [(1_000_000, 300_000), (5_000_000, 500_000)]
    for start, length in planted:
        filler[start:start + length] = os.urandom(length)
    data = bytes(filler)

    step = _bounded_entropy_step(len(data), 32, 16)
    assert step > 16

    def coverage(profile_step: int) -> int:
        profile = compute_entropy_profile(data, window=32, step=profile_step)
        regions = find_high_entropy_regions(profile, threshold=4.5)
        return sum(end - start for start, end, _ in regions)

    planted_bytes = sum(length for _, length in planted)
    widened = coverage(step)
    # Each planted region has two edges, and a windowed profile can place each
    # edge up to one window plus one step away from the true boundary: the
    # window straddles the transition, and the walk only samples every `step`.
    tolerance = (32 + step) * 2 * len(planted)
    assert abs(widened - planted_bytes) <= tolerance
    # And the widened profile must agree with the fine one, which is the actual
    # claim: resolution was traded, coverage was not.
    assert widened == pytest.approx(coverage(16), rel=0.02)


def test_default_threshold_is_unreachable_for_window_32():
    """Documents a PRE-EXISTING defect, deliberately left unchanged here.

    `entropy_result` defaults to window=32 and threshold=7.5, but a 32-sample
    window holds at most 32 distinct values, so its entropy cannot exceed
    log2(32) = 5.0 bits/byte. `high_entropy_regions` is therefore always empty
    with the API defaults, on every dump, and always has been.

    Changing the default threshold or window changes user-visible output and is
    a product decision, not a side effect of the performance work this test
    accompanies. This test pins the current behaviour so the fix is deliberate
    when it comes.
    """
    data = os.urandom(200_000)
    profile = compute_entropy_profile(data, window=32, step=16)
    assert max(e for _, e in profile) <= math.log2(32)
    assert find_high_entropy_regions(profile, threshold=7.5) == []
