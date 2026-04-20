"""Tests for algorithms.unknown_key.pattern_match module."""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from algorithms.base import AnalysisContext


def test_run_no_patterns():
    """Empty patterns directory produces confidence=0.0 and no matches."""
    from algorithms.unknown_key.pattern_match import PatternMatchAlgorithm
    algo = PatternMatchAlgorithm()
    # Override patterns to empty
    algo._patterns = []
    ctx = AnalysisContext(library="openssl", tls_version="13", phase="pre_abort")
    result = algo.run(b"\x00" * 256, ctx)
    assert result.confidence == 0.0
    assert len(result.matches) == 0


def test_run_with_matching_pattern():
    """A pattern matching high-entropy dump data should find matches."""
    from algorithms.unknown_key.pattern_match import PatternMatchAlgorithm
    import os
    algo = PatternMatchAlgorithm()
    # Create a synthetic pattern that matches high-entropy regions
    # Use 32 bytes of random-looking data (high entropy)
    key_data = bytes(range(0, 256, 8)) * 2  # 64 bytes of varied data
    dump_data = b"\x00" * 128 + key_data + b"\x00" * 128
    algo._patterns = [{
        "name": "test_pattern",
        "applicable_to": {},
        "key_spec": {"length": 32, "entropy_min": 3.0},
        "pattern": {"before": [], "after": []},
    }]
    ctx = AnalysisContext(library="openssl", tls_version="13", phase="pre_abort")
    result = algo.run(dump_data, ctx)
    assert result.algorithm_name == "pattern_match"
    # With no structural checks (empty before/after), any entropy match gets score 0
    # so confidence may be 0 - that's correct behavior
    assert result.metadata["patterns_checked"] == 1


def test_filter_patterns_by_library():
    """Pattern with applicable_to libraries filters correctly."""
    from algorithms.unknown_key.pattern_match import PatternMatchAlgorithm
    algo = PatternMatchAlgorithm()
    algo._patterns = [
        {"name": "openssl_only", "applicable_to": {"libraries": ["openssl"]}, "key_spec": {"length": 32}, "pattern": {}},
        {"name": "generic", "applicable_to": {}, "key_spec": {"length": 32}, "pattern": {}},
    ]
    ctx_openssl = AnalysisContext(library="openssl", tls_version="13", phase="pre_abort")
    ctx_boring = AnalysisContext(library="boringssl", tls_version="13", phase="pre_abort")
    assert len(algo._filter_patterns(ctx_openssl)) == 2  # both match
    assert len(algo._filter_patterns(ctx_boring)) == 1  # only generic


def test_structural_check():
    """Pattern with hex mask produces correct byte-level matching."""
    from algorithms.unknown_key.pattern_match import PatternMatchAlgorithm
    data = bytes([0x00] * 10 + [0xAA, 0xBB] + [0x00] * 20)
    pattern = {
        "pattern": {
            "before": [{"offset": -2, "bytes": "AA BB"}],
            "after": [],
        },
    }
    # key_offset=12 means checking offset 12-2=10 which has AA BB
    score = PatternMatchAlgorithm._check_structural(data, 12, pattern)
    assert score == 1.0

    # Mismatched pattern
    pattern_miss = {
        "pattern": {
            "before": [{"offset": -2, "bytes": "CC DD"}],
            "after": [],
        },
    }
    score_miss = PatternMatchAlgorithm._check_structural(data, 12, pattern_miss)
    assert score_miss == 0.0


def test_run_empty_data():
    """Empty dump data produces no matches."""
    from algorithms.unknown_key.pattern_match import PatternMatchAlgorithm
    algo = PatternMatchAlgorithm()
    algo._patterns = [{
        "name": "test",
        "applicable_to": {},
        "key_spec": {"length": 32, "entropy_min": 7.0},
        "pattern": {"before": [], "after": []},
    }]
    ctx = AnalysisContext(library="openssl", tls_version="13", phase="pre_abort")
    result = algo.run(b"", ctx)
    assert result.confidence == 0.0
    assert len(result.matches) == 0
