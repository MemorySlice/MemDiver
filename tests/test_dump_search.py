"""Tests for core.dump_search module."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.dump_search import DumpSearcher
from core.models import TLSSecret


def _make_dump(data: bytes) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
    f.write(data)
    f.close()
    return Path(f.name)


def test_find_all_single():
    data = b"\x00" * 100 + b"\xAA" * 32 + b"\x00" * 100
    path = _make_dump(data)
    searcher = DumpSearcher(path)
    searcher.load()
    offsets = searcher.find_all(b"\xAA" * 32)
    assert offsets == [100]


def test_find_all_multiple():
    needle = b"\xBB" * 4
    data = needle + b"\x00" * 10 + needle
    path = _make_dump(data)
    searcher = DumpSearcher(path)
    searcher.load()
    offsets = searcher.find_all(needle)
    assert offsets == [0, 14]


def test_find_all_not_found():
    data = b"\x00" * 100
    path = _make_dump(data)
    searcher = DumpSearcher(path)
    searcher.load()
    assert searcher.find_all(b"\xFF" * 8) == []


def test_search_secrets():
    key = b"\x01\x02\x03\x04" * 8  # 32 bytes
    data = b"\x00" * 50 + key + b"\x00" * 50
    path = _make_dump(data)
    searcher = DumpSearcher(path)
    secret = TLSSecret("TEST", b"\x00" * 32, key)
    occurrences = searcher.search_secrets([secret], ctx=16)
    assert len(occurrences) == 1
    assert occurrences[0].offset == 50
    assert occurrences[0].key_bytes == key


def test_extract_context():
    data = b"\xAA" * 16 + b"\xBB" * 8 + b"\xCC" * 16
    path = _make_dump(data)
    searcher = DumpSearcher(path)
    searcher.load()
    before, key, after = searcher.extract_context(16, 8, ctx=16)
    assert before == b"\xAA" * 16
    assert key == b"\xBB" * 8
    assert after == b"\xCC" * 16
