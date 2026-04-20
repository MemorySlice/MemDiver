"""Tests for engine.diff_store module - DiffStore differential analysis."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.diff_store import DiffStore
from engine.results import SecretHit

try:
    import polars
    HAS_POLARS = True
except ImportError:
    HAS_POLARS = False


def _hit(secret_type="CLIENT_RANDOM", offset=100, length=32, library="openssl",
         phase="pre_abort", run_id=1, confidence=1.0):
    """Create a SecretHit with sensible defaults for testing."""
    return SecretHit(
        secret_type=secret_type, offset=offset, length=length,
        dump_path=Path("/tmp/test.dump"), library=library,
        phase=phase, run_id=run_id, confidence=confidence,
    )


def test_empty_store_stats():
    """A fresh DiffStore should report zero total hits."""
    store = DiffStore()
    stats = store.summary_stats()
    assert stats["total_hits"] == 0


def test_ingest_single_hit():
    """Ingesting one hit should increase total_hits to 1."""
    store = DiffStore()
    store.ingest_hits([_hit()])
    stats = store.summary_stats()
    assert stats["total_hits"] == 1


def test_ingest_multiple_hits():
    """Ingesting three different hits should report total_hits == 3."""
    store = DiffStore()
    hits = [
        _hit(secret_type="CLIENT_RANDOM", offset=100, run_id=1),
        _hit(secret_type="SERVER_HANDSHAKE_TRAFFIC_SECRET", offset=200, run_id=2),
        _hit(secret_type="CLIENT_HANDSHAKE_TRAFFIC_SECRET", offset=300, run_id=3),
    ]
    store.ingest_hits(hits)
    stats = store.summary_stats()
    assert stats["total_hits"] == 3


def test_cross_dump_variance_empty():
    """An empty store should return an empty variance dict."""
    store = DiffStore()
    result = store.cross_dump_variance()
    assert result == {}


def test_filter_key_candidates_min_count():
    """Offsets appearing in >= min_count runs should be retained; single-run offsets filtered out."""
    store = DiffStore()
    hits = [
        # Same offset from two different runs -> should pass min_count=2
        _hit(offset=100, run_id=1),
        _hit(offset=100, run_id=2),
        # Single-run offset -> should be filtered out
        _hit(offset=200, run_id=3),
    ]
    store.ingest_hits(hits)

    result = store.filter_key_candidates(min_count=2)
    assert len(result) == 1
    assert result[0]["offset"] == 100
    assert result[0]["run_count"] == 2


def test_polars_guard():
    """Verify summary_stats includes counts regardless of polars availability."""
    store = DiffStore()
    store.ingest_hits([_hit()])
    stats = store.summary_stats()

    assert "unique_offsets" in stats
    assert "unique_libraries" in stats
    assert "secret_types" in stats
    assert stats["total_hits"] == 1
    if not HAS_POLARS:
        assert stats.get("polars") is False


# --- Fallback path tests (force HAS_POLARS=False) ---


def test_fallback_cross_dump_variance():
    """Stdlib fallback computes per-offset variance correctly."""
    import engine.diff_store as ds_mod
    orig = ds_mod.HAS_POLARS
    try:
        ds_mod.HAS_POLARS = False
        store = DiffStore()
        store.ingest_hits([
            _hit(offset=100, confidence=1.0, run_id=1),
            _hit(offset=100, confidence=0.5, run_id=2),
            _hit(offset=200, confidence=1.0, run_id=3),
        ])
        result = store.cross_dump_variance()
        assert 100 in result
        assert 200 in result
        # variance of [1.0, 0.5] = 0.125 (sample variance)
        assert abs(result[100] - 0.125) < 1e-9
        # single value → variance = 0
        assert result[200] == 0.0
    finally:
        ds_mod.HAS_POLARS = orig


def test_fallback_filter_candidates():
    """Stdlib fallback filters by run count correctly."""
    import engine.diff_store as ds_mod
    orig = ds_mod.HAS_POLARS
    try:
        ds_mod.HAS_POLARS = False
        store = DiffStore()
        store.ingest_hits([
            _hit(offset=100, run_id=1),
            _hit(offset=100, run_id=2),
            _hit(offset=200, run_id=3),
        ])
        result = store.filter_key_candidates(min_count=2)
        assert len(result) == 1
        assert result[0]["offset"] == 100
        assert result[0]["run_count"] == 2
    finally:
        ds_mod.HAS_POLARS = orig


def test_fallback_summary_stats():
    """Stdlib fallback includes unique_offsets, unique_libraries, secret_types."""
    import engine.diff_store as ds_mod
    orig = ds_mod.HAS_POLARS
    try:
        ds_mod.HAS_POLARS = False
        store = DiffStore()
        store.ingest_hits([
            _hit(offset=100, library="openssl", secret_type="A", run_id=1),
            _hit(offset=200, library="boringssl", secret_type="B", run_id=2),
        ])
        stats = store.summary_stats()
        assert stats["total_hits"] == 2
        assert stats["unique_offsets"] == 2
        assert stats["unique_libraries"] == 2
        assert stats["secret_types"] == 2
        assert stats["polars"] is False
    finally:
        ds_mod.HAS_POLARS = orig
