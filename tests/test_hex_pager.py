"""Tests for ui.components.hex_pager pagination utilities."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ui.components.hex_pager import compute_page, offset_to_page, total_pages


def test_compute_page_first():
    start, end = compute_page(4096, 0)
    assert start == 0
    assert end == 1024


def test_compute_page_second():
    start, end = compute_page(4096, 1)
    assert start == 1024
    assert end == 2048


def test_compute_page_last():
    """Page beyond dump_size is clamped."""
    start, end = compute_page(1500, 2)
    assert end <= 1500
    assert start <= end


def test_total_pages():
    assert total_pages(512) == 1


def test_total_pages_multi():
    assert total_pages(2048) == 2


def test_offset_to_page():
    assert offset_to_page(1500) == 1
