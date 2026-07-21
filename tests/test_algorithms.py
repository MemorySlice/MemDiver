"""Tests for algorithm modules."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.algorithms.base import AnalysisContext, BaseAlgorithm, Match
from memdiver.algorithms.known_key.exact_match import ExactMatchAlgorithm
from memdiver.algorithms.unknown_key.entropy_scan import EntropyScanAlgorithm
from memdiver.core.models import TLSSecret


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


def test_exact_match_empty_secret_yields_no_matches():
    """An empty secret_value must not match every offset (hang/blowout)."""
    dump = b"\x00" * 500
    secret = TLSSecret("CLIENT_RANDOM", b"\x00" * 32, b"")
    ctx = AnalysisContext(library="test", tls_version="12", phase="pre_abort", secrets=[secret])
    algo = ExactMatchAlgorithm()
    result = algo.run(dump, ctx)
    assert result.matches == []


def test_exact_match_empty_secret_does_not_block_real_one():
    """A valid secret must still match even if another secret is empty."""
    key = b"\x42" * 32
    dump = b"\x00" * 100 + key + b"\x00" * 100
    empty = TLSSecret("CLIENT_RANDOM", b"\x00" * 32, b"")
    real = TLSSecret("SERVER_RANDOM", b"\x00" * 32, key)
    ctx = AnalysisContext(library="test", tls_version="12", phase="pre_abort",
                          secrets=[empty, real])
    algo = ExactMatchAlgorithm()
    result = algo.run(dump, ctx)
    assert len(result.matches) == 1
    assert result.matches[0].offset == 100


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


def test_merge_overlapping_non_adjacent_overlap():
    """A later match overlapping an earlier (non-adjacent) kept match must be
    merged, not survive and inflate the count.

    Layout: a wide high-confidence interval [0, 50) is kept; a second interval
    [10, 30) is fully contained and must be dropped; a third interval [20, 40)
    overlaps the first kept interval but does NOT overlap the most recently
    inspected one ([10, 30) is discarded), yet still lies inside the cluster.
    The buggy implementation compared only against ``merged[-1]`` and would
    have wrongly retained the third interval.
    """
    matches = [
        Match(offset=0, length=50, confidence=0.9, label="a"),
        Match(offset=10, length=20, confidence=0.5, label="b"),
        Match(offset=20, length=20, confidence=0.4, label="c"),
    ]
    merged = EntropyScanAlgorithm._merge_overlapping(matches)
    assert len(merged) == 1
    assert merged[0].offset == 0 and merged[0].length == 50


def test_merge_overlapping_keeps_disjoint():
    """Non-overlapping intervals are all preserved."""
    matches = [
        Match(offset=0, length=32, confidence=0.6, label="a"),
        Match(offset=100, length=32, confidence=0.6, label="b"),
        Match(offset=200, length=32, confidence=0.6, label="c"),
    ]
    merged = EntropyScanAlgorithm._merge_overlapping(matches)
    assert [m.offset for m in merged] == [0, 100, 200]


def test_merge_overlapping_keeps_higher_confidence():
    """Among overlapping intervals the higher-confidence one is kept."""
    matches = [
        Match(offset=0, length=32, confidence=0.3, label="lo"),
        Match(offset=5, length=32, confidence=0.8, label="hi"),
    ]
    merged = EntropyScanAlgorithm._merge_overlapping(matches)
    assert len(merged) == 1
    assert merged[0].label == "hi"


def test_registry_discover_skips_failing_algorithm(monkeypatch):
    """One algorithm whose __init__ raises must not abort discovery of others.

    Simulates pkgutil/importlib yielding a module that exposes a healthy and a
    broken BaseAlgorithm subclass; the registry should register the healthy one
    and skip the broken one rather than aborting the whole walk.
    """
    import types
    import memdiver.algorithms.registry as registry_mod

    class GoodAlgo(BaseAlgorithm):
        name = "good_test_algo"
        def run(self, dump_data, context):  # pragma: no cover - not invoked
            raise NotImplementedError

    class BrokenAlgo(BaseAlgorithm):
        name = "broken_test_algo"
        def __init__(self):
            raise RuntimeError("boom")
        def run(self, dump_data, context):  # pragma: no cover - not invoked
            raise NotImplementedError

    fake_mod = types.ModuleType("memdiver.algorithms.unknown_key._fake_test_mod")
    fake_mod.GoodAlgo = GoodAlgo
    fake_mod.BrokenAlgo = BrokenAlgo

    def fake_walk_packages(path=None, prefix=""):
        if prefix == "memdiver.algorithms.unknown_key.":
            yield (None, "memdiver.algorithms.unknown_key._fake_test_mod", False)

    def fake_import_module(name):
        if name == "memdiver.algorithms.unknown_key._fake_test_mod":
            return fake_mod
        if name.startswith("memdiver.algorithms."):
            return types.ModuleType(name)
        raise ImportError(name)

    monkeypatch.setattr(registry_mod.pkgutil, "walk_packages", fake_walk_packages)
    monkeypatch.setattr(registry_mod.importlib, "import_module", fake_import_module)
    # Only the unknown_key subdir needs to "exist" for this test.
    monkeypatch.setattr(registry_mod.Path, "is_dir", lambda self: self.name == "unknown_key")

    reg = registry_mod.AlgorithmRegistry()
    reg.discover()

    assert "good_test_algo" in reg.names
    assert "broken_test_algo" not in reg.names
