"""Tests for core/image/run_index.py: RunIndex merge, pieces, coverage, VA <-> VAS."""

import pytest

from memdiver.core.image.run_index import LayerRun, RunIndex, RunState
from memdiver.core.location import GapReason

C, F, N = RunState.CAPTURED, RunState.FAILED, RunState.NOT_RESIDENT


def _index():
    """captured [0x1000,0x3000) | not_resident [0x3000,0x4000) | captured [0x5000,0x6000) | failed [0x6000,0x7000)."""
    return RunIndex([
        LayerRun(0x5000, 0x1000, C), LayerRun(0x1000, 0x2000, C),
        LayerRun(0x6000, 0x1000, F), LayerRun(0x3000, 0x1000, N),
    ])


# ------------------------------------------------------------------ merge

def test_adjacent_same_state_runs_merge():
    idx = RunIndex([LayerRun(0, 10, C), LayerRun(10, 5, C)])
    assert idx.runs == (LayerRun(0, 15, C),)


def test_adjacent_different_state_runs_do_not_merge():
    idx = RunIndex([LayerRun(0, 10, C), LayerRun(10, 5, F)])
    assert [r.state for r in idx.runs] == [C, F]


def test_non_adjacent_same_state_runs_do_not_merge():
    idx = RunIndex([LayerRun(0, 10, C), LayerRun(11, 5, C)])
    assert len(idx.runs) == 2


def test_overlapping_runs_raise():
    with pytest.raises(ValueError, match="overlapping"):
        RunIndex([LayerRun(0, 10, C), LayerRun(9, 5, F)])


def test_zero_length_runs_are_dropped():
    idx = RunIndex([LayerRun(5, 0, C), LayerRun(0, 4, C)])
    assert idx.runs == (LayerRun(0, 4, C),)


def test_unsorted_input_is_sorted():
    assert [r.start for r in _index().runs] == [0x1000, 0x3000, 0x5000, 0x6000]


def test_empty_index_has_zero_sizes():
    idx = RunIndex([])
    assert (idx.span_start, idx.span_size, idx.vas_size) == (0, 0, 0)
    assert idx.captured == ()


def test_span_and_vas_sizes():
    idx = _index()
    assert idx.span_start == 0x1000
    assert idx.span_size == 0x6000
    assert idx.vas_size == 0x3000


# ----------------------------------------------------------------- pieces

def test_pieces_partition_range_with_unmapped_before_between_after():
    idx = _index()
    got = list(idx.pieces(0x800, 0x7000))
    assert got == [
        (0x800, 0x800, None), (0x1000, 0x2000, C), (0x3000, 0x1000, N),
        (0x4000, 0x1000, None), (0x5000, 0x1000, C), (0x6000, 0x1000, F),
        (0x7000, 0x800, None),
    ]
    assert sum(n for _, n, _ in got) == 0x7000


def test_pieces_inside_one_run_is_a_single_piece():
    assert list(_index().pieces(0x1500, 0x100)) == [(0x1500, 0x100, C)]


def test_pieces_fully_unmapped_range():
    assert list(_index().pieces(0x100, 0x10)) == [(0x100, 0x10, None)]
    assert list(_index().pieces(0x9000, 0x10)) == [(0x9000, 0x10, None)]


def test_pieces_of_empty_index_is_all_unmapped():
    assert list(RunIndex([]).pieces(0, 8)) == [(0, 8, None)]


@pytest.mark.parametrize("start, length", [(0, 0x10000), (0x2FF0, 0x2020), (0x5FFF, 2)])
def test_pieces_lengths_sum_to_requested_and_are_contiguous(start, length):
    got = list(_index().pieces(start, length))
    assert sum(n for _, n, _ in got) == length
    cursor = start
    for s, n, _ in got:
        assert s == cursor
        cursor += n


# --------------------------------------------------------------- coverage

def test_coverage_of_captured_range_is_complete():
    cov = _index().coverage(0x1000, 0x2000)
    assert cov.complete and cov.gaps == ()


def test_coverage_reasons_per_state():
    cov = _index().coverage(0x2000, 0x5000)  # 0x2000..0x7000
    reasons = {(g.start, g.length): g.reason for g in cov.gaps}
    assert reasons == {
        (0x3000, 0x1000): GapReason.NOT_RESIDENT,
        (0x4000, 0x1000): GapReason.UNMAPPED,
        (0x6000, 0x1000): GapReason.FAILED,
    }
    assert cov.captured == 0x2000 - 0x1000 + 0x1000  # 0x1000 + 0x1000


def test_coverage_outside_all_runs_is_unmapped():
    cov = _index().coverage(0x100, 0x10)
    assert [g.reason for g in cov.gaps] == [GapReason.UNMAPPED]
    assert cov.captured == 0


# ------------------------------------------------------------- VA <-> VAS

def test_vas_offsets_are_cumulative_over_captured_runs_only():
    got = [(c.va_start, c.length, c.vas_offset) for c in _index().captured]
    assert got == [(0x1000, 0x2000, 0), (0x5000, 0x1000, 0x2000)]


def test_vas_pieces_spanning_two_captured_runs_across_a_failed_run():
    idx = RunIndex([LayerRun(0x1000, 0x10, C), LayerRun(0x1010, 0x10, F),
                    LayerRun(0x1020, 0x10, C)])
    assert list(idx.vas_pieces(0x8, 0x10)) == [(0x1008, 0x8), (0x1020, 0x8)]


def test_vas_pieces_clamps_to_vas_size():
    idx = _index()
    got = list(idx.vas_pieces(0x2F00, 0x1000))
    assert got == [(0x5F00, 0x100)]


def test_vas_pieces_past_end_is_empty():
    assert list(_index().vas_pieces(0x3000, 4)) == []


def test_vas_of_va_and_va_of_vas_round_trip():
    idx = _index()
    for va in (0x1000, 0x2FFF, 0x5000, 0x5FFF):
        vas = idx.vas_of_va(va)
        assert vas is not None
        assert idx.va_of_vas(vas) == va


def test_vas_of_va_values():
    idx = _index()
    assert idx.vas_of_va(0x1000) == 0
    assert idx.vas_of_va(0x5010) == 0x2010


@pytest.mark.parametrize("va", [0x0, 0xFFF, 0x3000, 0x3FFF, 0x4000, 0x6000, 0x7000, 0x9000])
def test_vas_of_va_none_when_not_captured(va):
    assert _index().vas_of_va(va) is None


def test_va_of_vas_none_past_end():
    assert _index().va_of_vas(0x3000) is None
    assert RunIndex([]).va_of_vas(0) is None
