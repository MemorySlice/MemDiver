"""Tests for architect.static_checker module - StaticChecker byte analysis."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from architect.static_checker import StaticChecker


def _make_dump(data: bytes) -> Path:
    """Write data to a temporary dump file and return its path."""
    f = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
    f.write(data)
    f.close()
    return Path(f.name)


def test_check_empty_paths():
    """An empty paths list should return empty mask and empty bytes."""
    mask, ref = StaticChecker.check([], offset=0, length=10)
    assert mask == []
    assert ref == b""


def test_check_single_dump():
    """A single dump should have all bytes marked as static."""
    path = _make_dump(b"\x41\x42\x43\x44\x45")
    try:
        mask, ref = StaticChecker.check([path], offset=0, length=5)
        assert all(mask)
        assert ref == b"\x41\x42\x43\x44\x45"
        assert len(mask) == 5
    finally:
        os.unlink(path)


def test_check_identical_dumps():
    """Two identical dumps should produce an all-True static mask."""
    data = b"\xAA\xBB\xCC\xDD"
    p1 = _make_dump(data)
    p2 = _make_dump(data)
    try:
        mask, ref = StaticChecker.check([p1, p2], offset=0, length=4)
        assert all(mask)
        assert ref == data
    finally:
        os.unlink(p1)
        os.unlink(p2)


def test_check_different_dumps():
    """Two dumps differing at known offsets should have False at those positions."""
    data1 = b"\x41\x42\x43\x44"
    data2 = b"\x41\xFF\x43\xFF"
    p1 = _make_dump(data1)
    p2 = _make_dump(data2)
    try:
        mask, ref = StaticChecker.check([p1, p2], offset=0, length=4)
        assert mask[0] is True   # same byte
        assert mask[1] is False  # differs
        assert mask[2] is True   # same byte
        assert mask[3] is False  # differs
        assert ref == data1
    finally:
        os.unlink(p1)
        os.unlink(p2)


def test_static_ratio():
    """static_ratio with 2 True and 2 False should return 0.5."""
    ratio = StaticChecker.static_ratio([True, True, False, False])
    assert ratio == 0.5
