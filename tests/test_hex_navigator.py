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


from ui.views.hex_navigator import create_hex_controls, render_hex_navigator
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
