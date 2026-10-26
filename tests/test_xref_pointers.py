"""Tests for engine.xref_pointers: coverage-explicit pointer scan."""

import struct

import pytest

from memdiver.engine import xref_pointers as xp
from memdiver.engine.xref_pointers import find_pointers_to


class FakeSource:
    format_name = "msl"

    def __init__(self, runs):
        self._runs = runs  # [(va, bytes)]

    def captured_runs(self):
        out, flat = [], 0
        for va, data in self._runs:
            out.append((va, len(data), flat))
            flat += len(data)
        return tuple(out)

    def read_range(self, offset, length, view="vas"):
        return b"".join(d for _, d in self._runs)[offset:offset + length]


class RawFake:
    format_name = "raw"


def q(*vals):
    return b"".join(struct.pack("<Q", v) for v in vals)


def make():
    a = q(0, 0x5010, 0, 0x9999) + q(0x5000)            # VA 0x1000..0x1028
    b = q(0x5020, 0)                                    # VA 0x3000..0x3010
    return FakeSource([(0x1000, a), (0x3000, b)])


def test_finds_and_deltas():
    scan = find_pointers_to(make(), 0x5000, 0x5100)
    assert [(r.holder_va, r.target_delta) for r in scan.refs] == [
        (0x1008, 0x10), (0x1020, 0), (0x3000, 0x20)]


def test_coverage_numbers():
    scan = find_pointers_to(make(), 0x5000, 0x5100)
    assert (scan.scanned_bytes, scan.scanned_runs) == (0x28 + 0x10, 2)
    assert scan.skipped_bytes == 0x3000 - 0x1028
    assert not scan.truncated


def test_pointer_at_run_boundary():
    src = FakeSource([(0x1000, q(0, 0x5000))])
    assert [r.holder_va for r in find_pointers_to(src, 0x5000, 0x5001).refs] == [0x1008]


def test_word_spanning_two_runs_not_reported():
    value = struct.pack("<Q", 0x5000)
    src = FakeSource([(0x1000, b"\0" * 4 + value[:4]), (0x1008, value[4:] + b"\0" * 4)])
    assert find_pointers_to(src, 0x5000, 0x5001, alignment=1).refs == []


def test_alignment():
    word = struct.pack("<Q", 0x5000)
    src = FakeSource([(0x1000, b"\0" * 3 + word + b"\0" * 5)])
    assert find_pointers_to(src, 0x5000, 0x5001, alignment=8).refs == []
    refs = find_pointers_to(src, 0x5000, 0x5001, alignment=1).refs
    assert [r.holder_va for r in refs] == [0x1003]


def test_exclude():
    scan = find_pointers_to(make(), 0x5000, 0x5100, exclude=(0x1000, 0x1010))
    assert [r.holder_va for r in scan.refs] == [0x1020, 0x3000]


def test_max_refs_truncates():
    scan = find_pointers_to(make(), 0x5000, 0x5100, max_refs=2)
    assert scan.truncated and len(scan.refs) == 2


def test_slab_border_not_missed_nor_doubled(monkeypatch):
    monkeypatch.setattr(xp, "SLAB_BYTES", 16)
    word = struct.pack("<Q", 0x5000)
    src = FakeSource([(0x1000, b"\0" * 12 + word + b"\0" * 16)])
    refs = find_pointers_to(src, 0x5000, 0x5001, alignment=1).refs
    assert [r.holder_va for r in refs] == [0x100C]


def test_raw_source_refused():
    with pytest.raises(ValueError, match="VA"):
        find_pointers_to(RawFake(), 1, 2)


def test_refs_are_va_sorted_when_alignment_below_word_size():
    word = struct.pack("<Q", 0x5000)
    # holders at 0x1001 (phase 1) and 0x1010 (phase 0): phase order != VA order
    src = FakeSource([(0x1000, b"\0" + word + b"\0" * 7 + word)])
    refs = find_pointers_to(src, 0x5000, 0x5001, alignment=1).refs
    assert [r.holder_va for r in refs] == sorted(r.holder_va for r in refs) == [0x1001, 0x1010]


def test_max_refs_keeps_the_lowest_va_holders():
    word = struct.pack("<Q", 0x5000)
    src = FakeSource([(0x1000, word + b"\0" * 1 + word + b"\0" * 7 + word)])
    scan = find_pointers_to(src, 0x5000, 0x5001, alignment=1, max_refs=2)
    assert scan.truncated
    assert [r.holder_va for r in scan.refs] == [0x1000, 0x1009]
