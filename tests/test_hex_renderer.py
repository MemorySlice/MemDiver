"""Tests for the shared hex rendering helpers.

Covers the ASCII-column padding fix (short final lines must keep the closing
pipe aligned with full rows) and the extracted shared offset-column helper
reused by the differential / two-panel views.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ui.components.hex_renderer import render_hex_line, render_offset_column


def _strip_tags(html: str) -> str:
    """Remove HTML tags so visible-character alignment can be measured."""
    return re.sub(r"<[^>]+>", "", html)


def test_short_line_ascii_block_keeps_closing_pipe_aligned():
    """A short final line pads its ASCII block so the closing '|' aligns."""
    full = _strip_tags(render_hex_line(bytes(range(16)), 0))
    short = _strip_tags(render_hex_line(b"AB", 0))
    assert full.rindex("|") == short.rindex("|")


def test_short_line_pads_ascii_with_spaces():
    """The ASCII block of a 2-byte line is padded by (bytes_per_row - 2)."""
    short = _strip_tags(render_hex_line(b"AB", 0))
    opening = short.index("|")
    closing = short.rindex("|")
    # Between the pipes: 2 ASCII chars + 14 padding spaces = 16 chars.
    assert closing - opening - 1 == 16


def test_render_offset_column_matches_inline_format():
    """The extracted helper produces the canonical 8-hex-digit offset column."""
    assert render_offset_column(0) == (
        '<span style="color:#808080">00000000</span>  '
    )
    assert "0000ff00" in render_offset_column(0xFF00)


def test_render_hex_line_uses_shared_offset_column():
    """render_hex_line emits the same offset prefix as render_offset_column."""
    line = render_hex_line(b"AB", 0x10)
    assert line.startswith(render_offset_column(0x10))
