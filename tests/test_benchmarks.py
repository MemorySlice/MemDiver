"""Performance benchmarks for Phase B optimizations.

These tests verify correctness AND measure speedup of numpy variance
and Aho-Corasick search vs the original pure-Python implementations.
Not run in CI by default (use: pytest tests/test_benchmarks.py -v).
"""

from __future__ import annotations

import os
import time

import numpy as np
import pytest

from core.variance import ByteClass, compute_variance, classify_variance


# --- Variance benchmarks ---


def _generate_dump_buffers(n_dumps: int, size: int) -> list[bytes]:
    """Generate synthetic dump buffers with mixed byte patterns."""
    rng = np.random.default_rng(42)
    return [rng.integers(0, 256, size=size, dtype=np.uint8).tobytes() for _ in range(n_dumps)]


def test_variance_correctness_small():
    """Verify numpy variance matches expected values on small input."""
    buf_a = bytes([10, 20, 30, 40])
    buf_b = bytes([10, 20, 30, 40])  # identical
    result = compute_variance([buf_a, buf_b], 4)
    assert len(result) == 4
    assert all(v == 0.0 for v in result), "Identical buffers should have zero variance"


def test_variance_correctness_different():
    """Verify variance is nonzero for differing buffers."""
    buf_a = bytes([0, 0, 0, 0])
    buf_b = bytes([255, 255, 255, 255])
    result = compute_variance([buf_a, buf_b], 4)
    assert all(v > 0 for v in result), "Different buffers should have positive variance"


def test_classify_variance_correctness():
    """Verify classification boundaries."""
    variance = np.array([0.0, 100.0, 1000.0, 5000.0], dtype=np.float32)
    classes = classify_variance(variance)
    assert classes[0] == ByteClass.INVARIANT
    assert classes[1] == ByteClass.STRUCTURAL
    assert classes[2] == ByteClass.POINTER
    assert classes[3] == ByteClass.KEY_CANDIDATE


def test_variance_performance():
    """Benchmark: numpy variance on 1MB buffers (5 dumps)."""
    buffers = _generate_dump_buffers(5, 1_000_000)
    start = time.perf_counter()
    result = compute_variance(buffers, 1_000_000)
    elapsed = time.perf_counter() - start
    assert len(result) == 1_000_000
    # Should complete in well under 1 second with numpy
    assert elapsed < 2.0, f"Variance on 5x1MB took {elapsed:.2f}s (expected <2s)"


def test_classify_performance():
    """Benchmark: classify 1M-element variance array."""
    variance = np.random.default_rng(42).uniform(0, 10000, 1_000_000).astype(np.float32)
    start = time.perf_counter()
    classes = classify_variance(variance)
    elapsed = time.perf_counter() - start
    assert len(classes) == 1_000_000
    assert elapsed < 0.5, f"Classification of 1M elements took {elapsed:.2f}s"


# --- Aho-Corasick benchmarks ---


def test_aho_corasick_available():
    """Verify pyahocorasick is installed."""
    import ahocorasick
    assert hasattr(ahocorasick, "Automaton")


def test_search_correctness():
    """Verify Aho-Corasick search finds all expected hits."""
    from core.models import CryptoSecret
    from engine.correlator import SearchCorrelator

    # Plant known secrets in synthetic data
    data = bytearray(1000)
    secret_bytes = bytes.fromhex("deadbeefcafebabe")
    data[100:100 + len(secret_bytes)] = secret_bytes
    data[500:500 + len(secret_bytes)] = secret_bytes

    secrets = [CryptoSecret(
        secret_type="test_key",
        identifier=b"\x00" * 32,
        secret_value=secret_bytes,
        protocol="test",
    )]

    correlator = SearchCorrelator()
    hits = correlator.search_all(
        type("FakeDump", (), {"read_all": lambda self: bytes(data), "path": "test.dump"})(),
        secrets, library="test", phase="test", run_id=0,
    )
    assert len(hits) == 2
    assert hits[0].offset == 100
    assert hits[1].offset == 500


def test_search_performance():
    """Benchmark: search 1MB data for 20 secrets."""
    from core.models import CryptoSecret
    from engine.correlator import SearchCorrelator

    rng = np.random.default_rng(42)
    data = rng.integers(0, 256, size=1_000_000, dtype=np.uint8).tobytes()

    secrets = [
        CryptoSecret(
            secret_type=f"key_{i}",
            identifier=rng.integers(0, 256, size=32, dtype=np.uint8).tobytes(),
            secret_value=rng.integers(0, 256, size=32, dtype=np.uint8).tobytes(),
            protocol="test",
        )
        for i in range(20)
    ]

    correlator = SearchCorrelator()
    source = type("S", (), {"read_all": lambda self: data, "path": "bench.dump"})()

    start = time.perf_counter()
    hits = correlator.search_all(source, secrets, library="bench", phase="test", run_id=0)
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0, f"Search 1MB with 20 secrets took {elapsed:.2f}s"
