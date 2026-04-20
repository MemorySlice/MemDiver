"""Tests for algorithm modules."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from algorithms.base import AnalysisContext, Match
from algorithms.known_key.exact_match import ExactMatchAlgorithm
from algorithms.unknown_key.entropy_scan import EntropyScanAlgorithm
from core.models import TLSSecret


def test_exact_match_finds_key():
    key = b"\x42" * 32
    dump = b"\x00" * 100 + key + b"\x00" * 100
    secret = TLSSecret("CLIENT_RANDOM", b"\x00" * 32, key)
    ctx = AnalysisContext(library="test", tls_version="12", phase="pre_abort", secrets=[secret])
    algo = ExactMatchAlgorithm()
    result = algo.run(dump, ctx)
    assert result.confidence == 1.0
    assert len(result.matches) == 1
    assert result.matches[0].offset == 100


def test_exact_match_no_key():
    dump = b"\x00" * 200
    secret = TLSSecret("CLIENT_RANDOM", b"\x00" * 32, b"\xFF" * 32)
    ctx = AnalysisContext(library="test", tls_version="12", phase="pre_abort", secrets=[secret])
    algo = ExactMatchAlgorithm()
    result = algo.run(dump, ctx)
    assert result.confidence == 0.0
    assert len(result.matches) == 0


def test_entropy_scan_finds_random():
    import os
    random_key = os.urandom(32)
    dump = b"\x00" * 200 + random_key + b"\x00" * 200
    ctx = AnalysisContext(library="test", tls_version="13", phase="pre_abort",
                          extra={"window_sizes": [32], "entropy_threshold": 3.0})
    algo = EntropyScanAlgorithm()
    result = algo.run(dump, ctx)
    # Should find the random key as a high-entropy region
    found_offsets = [m.offset for m in result.matches]
    assert any(abs(o - 200) <= 2 for o in found_offsets), f"Expected match near offset 200, got {found_offsets}"


def test_entropy_scan_empty():
    dump = b"\x00" * 100
    ctx = AnalysisContext(library="test", tls_version="13", phase="pre_abort")
    algo = EntropyScanAlgorithm()
    result = algo.run(dump, ctx)
    assert len(result.matches) == 0
