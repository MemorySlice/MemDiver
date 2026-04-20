"""Tests for ui.components.bookmark_store."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ui.components.bookmark_store import BookmarkStore


def test_add_bookmark():
    store = BookmarkStore()
    bm = store.add(100, length=4, label="key")
    assert bm.offset == 100
    assert bm.length == 4
    assert bm.label == "key"
    assert len(store.bookmarks) == 1


def test_remove_bookmark():
    store = BookmarkStore()
    store.add(50)
    assert store.remove(50) is True
    assert store.remove(50) is False
    assert len(store.bookmarks) == 0


def test_get_at():
    store = BookmarkStore()
    store.add(200, label="secret")
    assert store.get_at(200) is not None
    assert store.get_at(200).label == "secret"
    assert store.get_at(999) is None


def test_get_in_range():
    store = BookmarkStore()
    store.add(10)
    store.add(20)
    store.add(30)
    result = store.get_in_range(15, 35)
    assert len(result) == 2
    offsets = {b.offset for b in result}
    assert offsets == {20, 30}


def test_replace_at_same_offset():
    store = BookmarkStore()
    store.add(100, label="old")
    store.add(100, label="new")
    assert len(store.bookmarks) == 1
    assert store.get_at(100).label == "new"


def test_to_highlight_offsets():
    store = BookmarkStore()
    store.add(10, length=3)
    assert store.to_highlight_offsets() == {10, 11, 12}


def test_clear():
    store = BookmarkStore()
    store.add(1)
    store.add(2)
    store.clear()
    assert len(store.bookmarks) == 0
