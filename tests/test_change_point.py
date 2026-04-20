"""Tests for the CUSUM change-point detection algorithm.

Validates edge cases (empty data, zero data), embedded random block
detection, custom parameter propagation, and the internal _cusum_change_points
helper on a flat entropy profile.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from algorithms.unknown_key.change_point import ChangePointAlgorithm
from algorithms.base import AnalysisContext


def test_empty_data():
    """Empty input produces zero confidence and no matches."""
    algo = ChangePointAlgorithm()
    context = AnalysisContext(library="test", tls_version="13", phase="pre_abort")
    result = algo.run(b"", context)
    assert result.confidence == 0.0
    assert result.matches == []


def test_zero_data_no_matches():
    """Uniform zero bytes have zero entropy everywhere -- no high-entropy plateaus."""
    algo = ChangePointAlgorithm()
    context = AnalysisContext(library="test", tls_version="13", phase="pre_abort")
    result = algo.run(b"\x00" * 1024, context)
    assert result.confidence == 0.0
    assert result.matches == []
    assert result.metadata["change_points_detected"] == 0


def test_embedded_random_block():
    """A 32-byte random block surrounded by zeros should trigger change points.

    The CUSUM algorithm detects the entropy transition at the boundary of
    the random block.  With a lowered entropy_threshold and step=1, at least
    some change points should be detected near offset 200.
    """
    algo = ChangePointAlgorithm()
    random_block = os.urandom(32)
    data = b"\x00" * 200 + random_block + b"\x00" * 200
    context = AnalysisContext(
        library="test",
        tls_version="13",
        phase="pre_abort",
        extra={
            "entropy_threshold": 3.0,
            "step": 1,
        },
    )
    result = algo.run(data, context)
    # The gradient CUSUM should detect at least one transition (up or down)
    # at the boundary of the random block.
    assert result.metadata["change_points_detected"] > 0


def test_custom_parameters():
    """Custom parameters from context.extra are reflected in result metadata."""
    algo = ChangePointAlgorithm()
    context = AnalysisContext(
        library="test",
        tls_version="13",
        phase="pre_abort",
        extra={
            "window": 64,
            "cusum_threshold": 1.0,
            "drift": 0.1,
            "plateau_widths": [32],
            "step": 8,
            "entropy_threshold": 5.0,
        },
    )
    result = algo.run(b"\x00" * 256, context)
    assert result.metadata["window"] == 64
    assert result.metadata["cusum_threshold"] == 1.0
    assert result.metadata["drift"] == 0.1
    assert result.metadata["plateau_widths"] == [32]
    assert result.metadata["step"] == 8
    assert result.metadata["entropy_threshold"] == 5.0


def test_static_profile_no_cusum():
    """A flat entropy profile (constant value) has zero gradient -- no change points."""
    flat_profile = [(0, 5.0), (1, 5.0), (2, 5.0)]
    change_points = ChangePointAlgorithm._cusum_change_points(flat_profile)
    assert change_points == []
