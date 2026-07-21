"""Unit tests for the dependency-injection seams that decouple I/O from logic.

These exercise the pure, in-memory paths introduced for testability:

* ``DifferentialAlgorithm._variance_from_buffers`` computes cross-run variance
  from already-loaded byte buffers, with no file access.
* ``PatternMatchAlgorithm(patterns=...)`` accepts injected pattern definitions,
  skipping the disk load performed by the default no-arg constructor.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.algorithms.base import AnalysisContext
from memdiver.algorithms.unknown_key.differential import DifferentialAlgorithm
from memdiver.algorithms.unknown_key.pattern_match import PatternMatchAlgorithm


# ---------------------------------------------------------------------------
# DifferentialAlgorithm._variance_from_buffers (pure variance seam)
# ---------------------------------------------------------------------------

def test_variance_from_buffers_identical_is_zero():
    """Identical buffers have zero variance at every position."""
    buffers = [b"\x41" * 16] * 3
    variance = DifferentialAlgorithm._variance_from_buffers(buffers)
    assert len(variance) == 16
    assert all(v == 0.0 for v in variance)


def test_variance_from_buffers_detects_variation():
    """A single varying byte position produces non-zero variance there only."""
    buffers = [
        b"\x00\x00\x00\x00",
        b"\x00\xff\x00\x00",
        b"\x00\x80\x00\x00",
    ]
    variance = DifferentialAlgorithm._variance_from_buffers(buffers)
    assert len(variance) == 4
    assert variance[0] == 0.0
    assert variance[1] > 0.0
    assert variance[2] == 0.0
    assert variance[3] == 0.0


def test_variance_from_buffers_truncates_to_shortest():
    """Buffers of unequal length are truncated to the shortest before reduction."""
    buffers = [b"\x00" * 4, b"\x00" * 8, b"\x00" * 6]
    variance = DifferentialAlgorithm._variance_from_buffers(buffers)
    assert len(variance) == 4


def test_variance_from_buffers_empty_inputs():
    """Empty buffer list and zero-length buffers yield an empty result."""
    assert len(DifferentialAlgorithm._variance_from_buffers([])) == 0
    assert len(DifferentialAlgorithm._variance_from_buffers([b"", b""])) == 0


def test_variance_from_buffers_matches_file_path(tmp_path):
    """Injected-buffer path returns the same variance as the file-reading path."""
    data = [b"\x00\x11\x22\x33", b"\x00\xaa\x22\x99", b"\x00\x55\x22\x10"]
    paths = []
    for i, blob in enumerate(data):
        p = tmp_path / f"dump_{i}.bin"
        p.write_bytes(blob)
        paths.append(p)

    from_files = DifferentialAlgorithm._compute_variance(paths)
    from_buffers = DifferentialAlgorithm._variance_from_buffers(data)
    assert list(from_files) == list(from_buffers)


# ---------------------------------------------------------------------------
# PatternMatchAlgorithm(patterns=...) (injected-patterns seam)
# ---------------------------------------------------------------------------

def test_pattern_match_injected_patterns_used():
    """Injected patterns populate the algorithm without touching disk."""
    injected = [{
        "name": "injected_pattern",
        "applicable_to": {},
        "key_spec": {"length": 32, "entropy_min": 3.0},
        "pattern": {"before": [], "after": []},
    }]
    algo = PatternMatchAlgorithm(patterns=injected)
    assert algo._patterns == injected


def test_pattern_match_injected_empty_list():
    """Injecting an empty list produces no patterns and confidence 0.0."""
    algo = PatternMatchAlgorithm(patterns=[])
    assert algo._patterns == []
    ctx = AnalysisContext(library="openssl", tls_version="13", phase="pre_abort")
    result = algo.run(b"\x00" * 256, ctx)
    assert result.confidence == 0.0
    assert len(result.matches) == 0


def test_pattern_match_injected_list_is_copied():
    """The injected list is copied so caller mutations do not leak in."""
    source = [{
        "name": "p",
        "applicable_to": {},
        "key_spec": {"length": 32},
        "pattern": {"before": [], "after": []},
    }]
    algo = PatternMatchAlgorithm(patterns=source)
    source.append({"name": "added_later"})
    assert len(algo._patterns) == 1


def test_pattern_match_default_still_loads_from_disk():
    """No-arg construction loads the shipped JSON patterns as before."""
    algo = PatternMatchAlgorithm()
    assert len(algo._patterns) > 0
    assert all("key_spec" in p for p in algo._patterns)
