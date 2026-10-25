"""Tests for core/location.py: Location, Coverage, ReadResult (plan T1.1, rules P2/P3)."""

import pickle

import pytest

from memdiver.core.location import (
    AddressSpace,
    Coverage,
    CoverageGap,
    GapReason,
    Location,
    ReadResult,
)


# --------------------------------------------------------------- Location

def test_location_round_trips_through_dict_with_only_set_qualifiers():
    loc = Location(AddressSpace.PROCESS_VA, 0x5605659F7000, capture_id="abc", pid=22176)
    assert loc.to_dict() == {"space": "process_va", "value": 0x5605659F7000,
                             "capture_id": "abc", "pid": 22176}
    assert Location.from_dict(loc.to_dict()) == loc


@pytest.mark.parametrize("space, qualifier", [
    (AddressSpace.PROCESS_VA, "pid"),
    (AddressSpace.MODULE_REL, "module"),
    (AddressSpace.OBJECT_FIELD, "object_id"),
])
def test_location_refuses_a_space_without_its_qualifier(space, qualifier):
    with pytest.raises(ValueError, match=qualifier):
        Location(space, 0x10)


@pytest.mark.parametrize("value", [-1, 1.5, "0x10", True, None])
def test_location_refuses_non_int_or_negative_values(value):
    with pytest.raises((TypeError, ValueError)):
        Location(AddressSpace.PHYSICAL, value)


def test_location_refuses_a_bare_string_space():
    with pytest.raises(TypeError):
        Location("physical", 0)  # type: ignore[arg-type]


def test_shifted_keeps_the_coordinate_system():
    loc = Location(AddressSpace.KERNEL_VA, 0x1000, capture_id="img", view="prof")
    moved = loc.shifted(0x20)
    assert moved.value == 0x1020
    assert (moved.space, moved.capture_id, moved.view) == (loc.space, "img", "prof")


def test_location_is_hashable_and_picklable():
    loc = Location(AddressSpace.MODULE_REL, 8, module="libssl.so.3")
    assert {loc: 1}[Location(AddressSpace.MODULE_REL, 8, module="libssl.so.3")] == 1
    assert pickle.loads(pickle.dumps(loc)) == loc


# --------------------------------------------------------------- Coverage

def test_full_coverage_has_no_gaps():
    cov = Coverage.full(0x1000, 32)
    assert cov.complete and cov.captured == 32 and cov.gaps == ()
    assert list(cov.captured_ranges()) == [(0x1000, 32)]


def test_from_gaps_sorts_merges_same_reason_and_counts_captured():
    cov = Coverage.from_gaps(0, 0x4000, [
        CoverageGap(0x2000, 0x1000, GapReason.NOT_RESIDENT),
        CoverageGap(0x1000, 0x1000, GapReason.NOT_RESIDENT),
        CoverageGap(0x3000, 0x800, GapReason.FAILED),
    ])
    assert cov.gaps == (CoverageGap(0x1000, 0x2000, GapReason.NOT_RESIDENT),
                        CoverageGap(0x3000, 0x800, GapReason.FAILED))
    assert cov.captured == 0x4000 - 0x2800
    assert list(cov.captured_ranges()) == [(0, 0x1000), (0x3800, 0x800)]
    assert cov.failed_ranges == ((0x1000, 0x2000), (0x3000, 0x800))


def test_from_gaps_does_not_merge_adjacent_gaps_with_different_reasons():
    cov = Coverage.from_gaps(0, 0x2000, [CoverageGap(0, 0x1000, GapReason.FAILED),
                                         CoverageGap(0x1000, 0x1000, GapReason.UNMAPPED)])
    assert len(cov.gaps) == 2 and cov.captured == 0


def test_from_gaps_drops_empty_gaps():
    cov = Coverage.from_gaps(0, 16, [CoverageGap(4, 0, GapReason.FAILED)])
    assert cov.complete


def test_coverage_rejects_a_captured_count_that_disagrees_with_the_gaps():
    with pytest.raises(ValueError, match="captured"):
        Coverage(0, 32, 32, (CoverageGap(0, 8, GapReason.FAILED),))


@pytest.mark.parametrize("gaps", [
    (CoverageGap(30, 8, GapReason.FAILED),),                                  # past the end
    (CoverageGap(8, 8, GapReason.FAILED), CoverageGap(12, 4, GapReason.FAILED)),  # overlap
    (CoverageGap(16, 4, GapReason.FAILED), CoverageGap(0, 4, GapReason.FAILED)),  # unsorted
])
def test_coverage_rejects_malformed_gaps(gaps):
    with pytest.raises(ValueError):
        Coverage(0, 32, 32 - sum(g.length for g in gaps), gaps)


def test_coverage_round_trips_through_dict():
    cov = Coverage.from_gaps(0x100, 0x40, [CoverageGap(0x110, 0x10, GapReason.NOT_CAPTURED)])
    assert Coverage.from_dict(cov.to_dict()) == cov
    assert cov.to_dict()["gaps"] == [{"start": 0x110, "length": 0x10, "reason": "not_captured"}]


# --------------------------------------------------------------- ReadResult

def _partial_read():
    loc = Location(AddressSpace.PHYSICAL, 0x100, capture_id="img")
    cov = Coverage.from_gaps(0x100, 8, [CoverageGap(0x102, 4, GapReason.FAILED)])
    return ReadResult(loc, b"\xaa\xbb\x00\x00\x00\x00\xcc\xdd", cov)


def test_segments_yield_only_captured_bytes():
    assert list(_partial_read().segments()) == [(0x100, b"\xaa\xbb"), (0x106, b"\xcc\xdd")]


def test_to_dict_never_serializes_filler_bytes():
    out = _partial_read().to_dict()
    assert out["segments"] == [{"start": 0x100, "hex": "aabb"}, {"start": 0x106, "hex": "ccdd"}]
    assert "00000000" not in str(out)


def test_read_result_round_trips_with_a_visible_filler():
    rebuilt = ReadResult.from_dict(_partial_read().to_dict(), filler=0xEE)
    assert rebuilt.data == b"\xaa\xbb\xee\xee\xee\xee\xcc\xdd"
    assert rebuilt.coverage == _partial_read().coverage


def test_read_result_rejects_data_of_the_wrong_length():
    loc = Location(AddressSpace.PHYSICAL, 0)
    with pytest.raises(ValueError, match="bytes"):
        ReadResult(loc, b"\x00" * 3, Coverage.full(0, 4))


def test_read_result_rejects_a_location_that_is_not_the_coverage_start():
    loc = Location(AddressSpace.PHYSICAL, 4)
    with pytest.raises(ValueError, match="coverage.start"):
        ReadResult(loc, b"\x00" * 4, Coverage.full(0, 4))
