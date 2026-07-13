"""Tests for the hex navigator view."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class _MockWidget:
    """Minimal widget mock with a .value attribute."""

    def __init__(self, value=None, **kwargs):
        self.value = value


class _MockUI:
    def slider(self, **kw):
        return _MockWidget(value=kw.get("value", 0))

    def text(self, **kw):
        return _MockWidget(value=kw.get("value", ""))

    def number(self, **kw):
        return _MockWidget(value=kw.get("value", 0))

    def button(self, **kw):
        return _MockWidget(value=kw.get("value", 0))


class _MockMo:
    """Minimal marimo mock."""

    ui = _MockUI()

    class Html:
        def __init__(self, html):
            self.html = html

    @staticmethod
    def md(text):
        return text


from ui.views.hex_navigator import (
    create_hex_controls, render_hex_navigator, _search_dump,
)
from ui.components.bookmark_store import BookmarkStore


def test_create_hex_controls_keys():
    """create_hex_controls returns dict with expected widget keys."""
    mo = _MockMo()
    controls = create_hex_controls(mo, dump_size=4096)
    expected = {
        "page", "offset_input", "jump_btn", "search_input",
        "search_btn", "inspect_offset", "bookmark_label", "bookmark_btn",
    }
    assert set(controls.keys()) == expected


def test_render_hex_navigator_basic():
    """render_hex_navigator returns Html without crashing."""
    mo = _MockMo()
    data = bytes(range(256)) * 4  # 1024 bytes
    controls = create_hex_controls(mo, dump_size=len(data))
    result = render_hex_navigator(mo, data, controls)
    assert isinstance(result, _MockMo.Html)
    assert "Page 1/" in result.html
    assert "1024 bytes" in result.html


def test_render_hex_navigator_with_bookmarks():
    """render_hex_navigator merges bookmark offsets into highlights."""
    mo = _MockMo()
    data = b"\x00" * 512
    controls = create_hex_controls(mo, dump_size=len(data))
    store = BookmarkStore()
    store.add(offset=16, length=4, label="test")
    result = render_hex_navigator(mo, data, controls, bookmarks=store)
    assert isinstance(result, _MockMo.Html)
    # Bookmark legend entry should appear
    assert "Bookmark" in result.html


def test_search_ascii_term_that_is_also_hex_finds_ascii():
    """An ASCII term that is also valid hex ('cafe') still matches ASCII bytes."""
    # "cafe" as literal ASCII is at offset 4; the hex bytes 0xCA 0xFE do not occur.
    data = b"xxxxcafe-and-more"
    pattern, offsets = _search_dump(data, "cafe")
    assert 4 in offsets  # literal ASCII match must not be dropped


def test_search_merges_ascii_and_hex_interpretations():
    """For a hex-and-ASCII ambiguous term, both interpretations are merged."""
    # ASCII "cafe" at offset 0; raw hex bytes 0xCA 0xFE at offset 10.
    data = b"cafe______\xca\xfe___"
    pattern, offsets = _search_dump(data, "cafe")
    assert 0 in offsets   # ASCII interpretation
    assert 10 in offsets  # hex interpretation
    assert offsets == sorted(offsets)  # merged + sorted


def test_search_0x_prefix_forces_hex():
    """A '0x' prefix forces hex-byte interpretation, ignoring ASCII reading."""
    # ASCII "cafe" at offset 0 must NOT match; only hex bytes 0xCA 0xFE at 10.
    data = b"cafe______\xca\xfe___"
    pattern, offsets = _search_dump(data, "0xcafe")
    assert offsets == [10]
    assert pattern == b"\xca\xfe"


def test_search_0x_prefix_invalid_hex_returns_empty():
    """Invalid hex after '0x' yields no matches rather than guessing ASCII."""
    pattern, offsets = _search_dump(b"zzcafezz", "0xzz")
    assert offsets == []


def test_search_pure_ascii_non_hex_term():
    """A non-hex ASCII term is searched as literal ASCII."""
    data = b"hello world hello"
    pattern, offsets = _search_dump(data, "hello")
    assert offsets == [0, 12]
    assert pattern == b"hello"


def test_search_empty_returns_empty():
    """Blank search term returns no pattern and no offsets."""
    assert _search_dump(b"data", "   ") == (b"", [])
