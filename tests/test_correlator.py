"""Tests for engine.correlator module."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import TLSSecret
from engine.correlator import SearchCorrelator


def _make_dump(data):
    f = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
    f.write(data)
    f.close()
    return Path(f.name)


def test_search_all_finds_key():
    key = b"\xAB" * 32
    data = b"\x00" * 100 + key + b"\x00" * 100
    path = _make_dump(data)
    secret = TLSSecret("TEST_SECRET", b"\x00" * 32, key)
    corr = SearchCorrelator()
    hits = corr.search_all(path, [secret], library="test", phase="pre_abort", run_id=1)
    assert len(hits) == 1
    assert hits[0].offset == 100
    assert hits[0].secret_type == "TEST_SECRET"


def test_search_all_no_match():
    data = b"\x00" * 200
    path = _make_dump(data)
    secret = TLSSecret("MISS", b"\x00" * 32, b"\xFF" * 32)
    corr = SearchCorrelator()
    hits = corr.search_all(path, [secret])
    assert len(hits) == 0


def test_search_static_unfiltered():
    key = b"\xBB" * 32
    data = b"\x00" * 50 + key + b"\x00" * 50
    secret = TLSSecret("KEY", b"\x00" * 32, key)
    corr = SearchCorrelator()
    matches = corr.search_static(data, [secret])
    assert len(matches) == 1
    assert matches[0].offset == 50
