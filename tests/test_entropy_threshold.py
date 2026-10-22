"""Window-aware default entropy threshold (core.entropy) and its consumers."""

import math
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.algorithms.unknown_key.entropy_scan import EntropyScanAlgorithm  # noqa: E402
from memdiver.app.entropy_payload import region_min_span, resolve_threshold  # noqa: E402
from memdiver.core.entropy import (  # noqa: E402
    DEFAULT_ENTROPY_WINDOW,
    REFERENCE_ENTROPY_THRESHOLD,
    compute_entropy_profile,
    default_entropy_threshold,
    find_high_entropy_regions,
    max_window_entropy,
    random_window_entropy,
    threshold_is_reachable,
)


def test_default_window_threshold_is_entropy_scan_default():
    assert default_entropy_threshold() == 4.5
    assert default_entropy_threshold(DEFAULT_ENTROPY_WINDOW) == REFERENCE_ENTROPY_THRESHOLD
    assert EntropyScanAlgorithm.DEFAULT_THRESHOLD == default_entropy_threshold(32)


@pytest.mark.parametrize("window,expected", [
    (1, 0.0), (2, 1.0), (16, 4.0), (32, 5.0), (64, 6.0), (256, 8.0), (4096, 8.0)])
def test_max_window_entropy(window, expected):
    assert max_window_entropy(window) == expected


def test_max_window_entropy_is_attained_by_distinct_bytes():
    for window in (8, 32, 200, 256):
        profile = compute_entropy_profile(bytes(range(window)), window, 1)
        assert math.isclose(profile[0][1], max_window_entropy(window), abs_tol=1e-12)


@pytest.mark.parametrize("window", [2, 8, 16, 32, 48, 64, 128, 256, 1024])
def test_random_window_entropy_matches_simulation(window):
    data = np.random.default_rng(window).integers(0, 256, 1 << 17, dtype=np.uint8).tobytes()
    mean = compute_entropy_profile(data, window, 5).values.mean()
    assert abs(mean - random_window_entropy(window)) < 0.01


@pytest.mark.parametrize("window", [8, 16, 32, 48, 64, 128, 256, 512, 1024])
def test_default_threshold_is_reachable_and_random_keys_pass(window):
    threshold = default_entropy_threshold(window)
    assert 0 < threshold < max_window_entropy(window)
    data = np.random.default_rng(7).integers(0, 256, 1 << 16, dtype=np.uint8).tobytes()
    values = compute_entropy_profile(data, window, 3).values
    assert (values >= threshold).mean() > 0.99


def test_default_threshold_is_monotone_in_window():
    values = [default_entropy_threshold(w) for w in (2, 4, 8, 16, 32, 64, 256, 1024)]
    assert values == sorted(values)


def test_former_default_was_unreachable_below_182_bytes():
    assert not threshold_is_reachable(7.5, 32)
    assert not threshold_is_reachable(7.5, 181)
    assert threshold_is_reachable(7.5, 182)


def test_find_regions_default_threshold_is_window_aware():
    data = bytes(64) + bytes(np.random.default_rng(1).integers(0, 256, 64, dtype=np.uint8)) + bytes(64)
    profile = compute_entropy_profile(data, 32, 1)
    assert find_high_entropy_regions(profile, min_width=1) == \
        find_high_entropy_regions(profile, 4.5, 1)
    assert find_high_entropy_regions(profile, min_width=1)  # the key is found
    assert find_high_entropy_regions(profile, 7.5, 1) == []  # explicit keeps meaning


def test_resolve_threshold_default_and_explicit():
    default = resolve_threshold(32, None)
    assert default["threshold"] == 4.5 and default["threshold_source"] == "default"
    assert default["threshold_reachable"] and default["warnings"] == []
    assert default["max_entropy"] == 5.0
    explicit = resolve_threshold(32, 7.5)
    assert explicit["threshold"] == 7.5 and explicit["threshold_source"] == "explicit"
    assert not explicit["threshold_reachable"]
    assert explicit["warnings"] == ["threshold_unreachable"]


@pytest.mark.parametrize("window,step,expected", [
    (32, 1, 1), (32, 16, 16), (16, 1, 17), (16, 3, 19), (64, 1, 0), (64, 16, 0)])
def test_region_min_span_covers_32_bytes(window, step, expected):
    assert region_min_span(window, step) == expected
    # A run of r points covers (r - 1) * step + window bytes and spans r * step.
    for points in range(1, 8):
        covered = (points - 1) * step + window
        assert (points * step >= expected) == (covered >= 32)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
