"""Tests for msl/page_map.py — PageStateMap decoder."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from msl.enums import PageState
from msl.page_map import (
    PageInterval,
    count_captured_pages,
    decode_page_intervals,
    decode_page_state_map,
    iter_captured_ranges,
)


def test_decode_all_captured():
    """4 pages all CAPTURED = byte 0b00_00_00_00 = 0x00."""
    states = decode_page_state_map(b"\x00", 4)
    assert states == [PageState.CAPTURED] * 4


def test_decode_mixed_states():
    """Byte 0b00_01_10_00 = pages: CAP, FAIL, UNMAP, CAP."""
    byte_val = (0b00 << 6) | (0b01 << 4) | (0b10 << 2) | 0b00
    states = decode_page_state_map(bytes([byte_val]), 4)
    assert states[0] == PageState.CAPTURED
    assert states[1] == PageState.FAILED
    assert states[2] == PageState.UNMAPPED
    assert states[3] == PageState.CAPTURED


def test_decode_partial_byte():
    """Only 2 pages from a byte."""
    states = decode_page_state_map(b"\x00", 2)
    assert len(states) == 2
    assert all(s == PageState.CAPTURED for s in states)


def test_decode_empty():
    states = decode_page_state_map(b"", 0)
    assert states == []


def test_decode_truncated_data():
    """More pages than data available — defaults to FAILED."""
    states = decode_page_state_map(b"\x00", 8)
    assert len(states) == 8
    assert states[0] == PageState.CAPTURED  # from byte 0
    assert states[4] == PageState.FAILED  # beyond data


def test_iter_single_contiguous_run():
    """All pages captured = one contiguous range."""
    states = [PageState.CAPTURED] * 4
    page_data = b"\xAA" * 16  # 4 pages * 4 bytes each
    ranges = list(iter_captured_ranges(states, page_data, 0x1000, 4))
    assert len(ranges) == 1
    vaddr, length, data = ranges[0]
    assert vaddr == 0x1000
    assert length == 16
    assert bytes(data) == b"\xAA" * 16


def test_iter_gap_splits_ranges():
    """CAP, FAIL, CAP = two separate ranges."""
    states = [PageState.CAPTURED, PageState.FAILED, PageState.CAPTURED]
    page_data = b"\xAA" * 4 + b"\xBB" * 4  # only 2 captured pages
    ranges = list(iter_captured_ranges(states, page_data, 0x1000, 4))
    assert len(ranges) == 2
    assert ranges[0][0] == 0x1000  # first page
    assert bytes(ranges[0][2]) == b"\xAA" * 4
    assert ranges[1][0] == 0x1008  # third page (0x1000 + 2*4)
    assert bytes(ranges[1][2]) == b"\xBB" * 4


def test_iter_empty():
    ranges = list(iter_captured_ranges([], b"", 0, 4096))
    assert ranges == []


def test_iter_all_failed():
    states = [PageState.FAILED, PageState.FAILED]
    ranges = list(iter_captured_ranges(states, b"", 0x1000, 4))
    assert ranges == []


def test_count_captured():
    states = [PageState.CAPTURED, PageState.FAILED, PageState.CAPTURED]
    assert count_captured_pages(states) == 2


def test_count_none_captured():
    states = [PageState.FAILED, PageState.UNMAPPED]
    assert count_captured_pages(states) == 0


# -- PageInterval (RLE) tests --

def test_intervals_all_captured_fast_path():
    """All-zero bitmap = single CAPTURED interval."""
    intervals = decode_page_intervals(b"\x00\x00", 8)
    assert len(intervals) == 1
    assert intervals[0] == PageInterval(0, 8, PageState.CAPTURED)


def test_intervals_mixed():
    """CAP, FAIL, UNMAP, CAP = 4 intervals."""
    byte_val = (0b00 << 6) | (0b01 << 4) | (0b10 << 2) | 0b00
    intervals = decode_page_intervals(bytes([byte_val]), 4)
    assert len(intervals) == 4
    assert intervals[0].state == PageState.CAPTURED
    assert intervals[1].state == PageState.FAILED
    assert intervals[2].state == PageState.UNMAPPED
    assert intervals[3].state == PageState.CAPTURED


def test_intervals_consecutive_same_state():
    """4 captured pages = 1 interval, not 4."""
    intervals = decode_page_intervals(b"\x00", 4)
    assert len(intervals) == 1
    assert intervals[0].count == 4


def test_intervals_empty():
    assert decode_page_intervals(b"", 0) == []


def test_count_from_intervals():
    intervals = [
        PageInterval(0, 100, PageState.CAPTURED),
        PageInterval(100, 1, PageState.FAILED),
        PageInterval(101, 50, PageState.CAPTURED),
    ]
    assert count_captured_pages(intervals) == 150


def test_iter_from_intervals():
    """iter_captured_ranges works with interval input."""
    intervals = [
        PageInterval(0, 2, PageState.CAPTURED),
        PageInterval(2, 1, PageState.FAILED),
        PageInterval(3, 1, PageState.CAPTURED),
    ]
    page_data = b"\xAA" * 8 + b"\xBB" * 4  # 3 captured pages * 4 bytes
    ranges = list(iter_captured_ranges(intervals, page_data, 0x1000, 4))
    assert len(ranges) == 2
    assert ranges[0][0] == 0x1000  # first 2 pages
    assert bytes(ranges[0][2]) == b"\xAA" * 8
    assert ranges[1][0] == 0x100C  # page 3
    assert bytes(ranges[1][2]) == b"\xBB" * 4
