"""Tests for the side-by-side hex comparison view.

Focus: for unequal-length dumps on a high page, the two panels start at
different offsets, so the info banner must report both per-panel offsets
and a positional diff count rather than a single misleading offset.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ui.views.hex_comparison import render_hex_comparison


class _FakeHtml:
    """Minimal stand-in for mo.Html that just records its HTML string."""

    def __init__(self, html: str):
        self.html = html


class _FakeMo:
    Html = _FakeHtml


def _info_text(html: str) -> str:
    """Strip tags so the info banner text can be asserted on."""
    return re.sub(r"<[^>]+>", "", html)


def test_unequal_dumps_report_both_panel_offsets():
    """On a page where panels start at different offsets, both are shown."""
    bytes_per_row = 16
    rows_per_page = 2
    page_bytes = bytes_per_row * rows_per_page  # 32

    # Dump A long enough to reach page 1 (offset 32); dump B too short, so it
    # clamps to a different start offset -> the offsets genuinely differ.
    dump_a = bytes(range(256)) * 1
    dump_b = bytes(48)

    controls = {
        "page": type("S", (), {"value": 1})(),
        "highlight_diffs": type("S", (), {"value": True})(),
    }

    result = render_hex_comparison(
        _FakeMo(), dump_a, dump_b, controls=controls,
        bytes_per_row=bytes_per_row, rows_per_page=rows_per_page,
    )
    text = _info_text(result.html)
    # Both panel offsets appear and the count is labelled positional.
    assert "A 0x" in text and "B 0x" in text
    assert "positional" in text


def test_identical_dumps_report_zero_diffs():
    """Identical dumps yield zero differing bytes in the banner."""
    data = bytes(range(64))
    controls = {
        "page": type("S", (), {"value": 0})(),
        "highlight_diffs": type("S", (), {"value": True})(),
    }
    result = render_hex_comparison(
        _FakeMo(), data, data, controls=controls,
        bytes_per_row=16, rows_per_page=2,
    )
    text = _info_text(result.html)
    assert "0 differing bytes" in text
