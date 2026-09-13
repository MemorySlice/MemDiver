"""Slab <-> VA window projection on ConsensusVector.

The consensus indexes a concatenated slab of the pages every dump had in
common, so a slab index is not a position in any dump. ``class_window_va``
has always mapped VA -> slab; these cover the INVERSE (``slab_to_va``) and
the full ``WindowProjection`` that carries both directions plus the gaps.

Most cases use the hand-built layout from ``test_consensus_va_mapping`` (no
fixture I/O); ``test_multidelta_*`` uses a real two-region MSL pair, because
the one property a single-scalar-per-dump design cannot satisfy — two aligned
regions shifting by DIFFERENT amounts — only shows up on real alignment.
"""

import contextlib
from pathlib import Path

import numpy as np
import pytest

from memdiver.core.dump_source import open_dump
from memdiver.engine.consensus import (
    AlignedSegment,
    ConsensusVector,
    WindowProjection,
)
from tests.fixtures.generate_msl_aslr_fixtures import generate_aslr_msl_pair
from tests.test_consensus_va_mapping import _vector


# --- helpers ---------------------------------------------------------------


def _spans(proj: WindowProjection):
    """Every (offset, length) span of a projection, segments and gaps alike."""
    return sorted(
        [(s.window_offset, s.length) for s in proj.segments] + list(proj.gaps),
    )


def _gap_offsets(proj: WindowProjection) -> set:
    return {i for (off, run) in proj.gaps for i in range(off, off + run)}


@pytest.fixture
def aslr_pair_extra(tmp_path):
    """Real consensus over the two-region (``extra_region=True``) ASLR pair."""
    run1, run2 = generate_aslr_msl_pair(extra_region=True)
    (tmp_path / "run_1.msl").write_bytes(run1)
    (tmp_path / "run_2.msl").write_bytes(run2)
    with contextlib.ExitStack() as stack:
        sources = [
            stack.enter_context(open_dump(tmp_path / f"run_{i}.msl"))
            for i in (1, 2)
        ]
        cm = ConsensusVector()
        cm.build_from_sources(sources)
        yield cm


# --- T2: slab -> VA round trip --------------------------------------------


def test_slab_to_va_round_trips_through_class_window_va():
    """Every slab byte's VA must map back to that byte's class, in every dump."""
    cm = _vector()
    classes = list(np.asarray(cm.classifications).tolist())
    for (slab, page_size, vaddrs) in cm.msl_layout:
        for dump_index in range(len(vaddrs)):
            for n in range(1, page_size + 1):
                va = cm.slab_to_va(dump_index, slab)
                assert va == vaddrs[dump_index]
                assert cm.class_window_va(dump_index, va, n) == classes[slab:slab + n]


def test_slab_to_va_mid_page():
    cm = _vector()
    assert cm.slab_to_va(0, 2) == 0x1002
    assert cm.slab_to_va(1, 2) == 0x5002
    assert cm.slab_to_va(0, 5) == 0x2001
    assert cm.slab_to_va(1, 5) == 0x6001


def test_slab_to_va_refuses_rather_than_guesses():
    cm = _vector()
    assert cm.slab_to_va(0, 8) == -1, "past the end of the slab"
    assert cm.slab_to_va(0, 10_000) == -1
    assert cm.slab_to_va(0, -1) == -1
    assert cm.slab_to_va(2, 0) == -1, "dump index past the layout's dumps"
    assert cm.slab_to_va(-1, 0) == -1

    raw = ConsensusVector()  # raw build: msl_layout is None
    assert raw.msl_layout is None
    assert raw.slab_to_va(0, 0) == -1


# --- T3: gaps match the VA-mapping contract byte for byte ------------------


def test_projection_gaps_match_class_window_va():
    cm = _vector()
    proj = cm.project_va_window(0, 0x1000, 8)
    # Byte-identical to test_class_window_marks_gaps.
    assert list(proj.classes) == [0, 0, 1, 3, -1, -1, -1, -1]
    assert proj.gaps == ((4, 4),)
    assert len(proj.segments) == 1
    seg = proj.segments[0]
    assert (seg.window_offset, seg.length, seg.slab_offset) == (0, 4, 0)
    assert seg.vas == (0x1000, 0x5000)
    assert proj.anchor_index == 0
    assert proj.start == 0x1000
    assert proj.covered == 4


def test_projection_classes_equal_class_window_va_everywhere():
    cm = _vector()
    for dump_index in (0, 1):
        for va in (0x0FFC, 0x1000, 0x1002, 0x2000, 0x5000, 0x9000):
            for length in (0, 1, 4, 8, 16):
                proj = cm.project_va_window(dump_index, va, length)
                assert list(proj.classes) == cm.class_window_va(
                    dump_index, va, length,
                )


# --- T4: the partition property -------------------------------------------

_WINDOWS = [
    (0, 0x0000, 16),     # entirely before the aligned span
    (0, 0x0FF8, 16),     # straddles the start
    (0, 0x1000, 4),      # exactly one page
    (0, 0x1002, 4),      # partial start, then a gap
    (0, 0x1000, 8),      # two pages with a gap between
    (0, 0x1000, 0x1010), # spans the gap and both pages
    (0, 0x2002, 16),     # straddles the end
    (0, 0x9000, 8),      # entirely after the aligned span
    (1, 0x5000, 4),
    (1, 0x5002, 0x1004),
    (1, 0x6000, 32),
    (7, 0x1000, 8),      # dump index with no layout entry at all
]


@pytest.mark.parametrize("dump_index,va,length", _WINDOWS)
def test_segments_and_gaps_partition_the_window(dump_index, va, length):
    cm = _vector()
    proj = cm.project_va_window(dump_index, va, length)

    spans = _spans(proj)
    cursor = 0
    for offset, run in spans:
        assert offset == cursor, f"{spans} is not contiguous from 0"
        assert run > 0
        cursor += run
    assert cursor == length
    assert len(proj.classes) == length
    assert proj.covered + sum(run for _o, run in proj.gaps) == length

    gap_bytes = _gap_offsets(proj)
    for i, code in enumerate(proj.classes):
        assert (code == -1) is (i in gap_bytes), (
            f"byte {i}: class {code} disagrees with gap membership"
        )


def test_window_projection_rejects_a_non_partition():
    """The invariant is asserted, not merely documented."""
    with pytest.raises(AssertionError):
        WindowProjection(
            anchor_index=0, start=0, length=8,
            segments=(AlignedSegment(0, 4, 0, 0, (0x1000,)),),
            gaps=(),  # bytes 4..8 accounted for by nothing
            classes=tuple([0] * 8),
        )


# --- T_slab: slab-anchored projection --------------------------------------


def test_project_slab_window_is_dense_and_agrees_with_slab_to_va():
    cm = _vector()
    proj = cm.project_slab_window(0, 8)
    assert proj.anchor_index == -1
    assert proj.start == 0
    assert proj.gaps == (), "the slab is dense; a whole-slab window has no gap"
    assert proj.covered == 8
    assert list(proj.classes) == list(np.asarray(cm.classifications).tolist())
    assert len(proj.segments) == 2
    for seg in proj.segments:
        for d, va in enumerate(seg.vas):
            assert va == cm.slab_to_va(d, seg.slab_offset)


def test_project_slab_window_partial_rows_have_no_gaps():
    cm = _vector()
    proj = cm.project_slab_window(2, 4)
    assert proj.gaps == ()
    assert list(proj.classes) == [1, 3, 2, 2]
    assert [(s.window_offset, s.length, s.slab_offset) for s in proj.segments] == [
        (0, 2, 2), (2, 2, 4),
    ]
    assert proj.segments[0].vas == (0x1002, 0x5002)
    assert proj.segments[1].vas == (0x2000, 0x6000)


def test_project_slab_window_past_the_slab_end_is_a_gap_not_a_guess():
    cm = _vector()
    proj = cm.project_slab_window(6, 6)
    assert proj.covered == 2
    assert proj.gaps == ((2, 4),)
    assert list(proj.classes) == [0, 0, -1, -1, -1, -1]


def test_project_slab_window_on_a_raw_build_is_all_gap():
    raw = ConsensusVector()
    proj = raw.project_slab_window(0, 4)
    assert proj.segments == ()
    assert proj.gaps == ((0, 4),)
    assert list(proj.classes) == [-1, -1, -1, -1]


# --- T_multidelta: two regions, two different shifts -----------------------


def test_multidelta_fixture_has_two_regions_with_different_shifts(aslr_pair_extra):
    """The fixture's whole point: one VA delta per dump is not enough."""
    layout = aslr_pair_extra.msl_layout
    assert len(layout) == 2
    deltas = [vaddrs[1] - vaddrs[0] for (_slab, _ps, vaddrs) in layout]
    assert deltas[0] != deltas[1]
    assert deltas == [0x1000, 0x10000000]


def test_multidelta_projection_carries_per_segment_vas(aslr_pair_extra):
    cm = aslr_pair_extra
    (slab_a, ps_a, vas_a), (slab_b, ps_b, vas_b) = cm.msl_layout
    assert (slab_a, slab_b) == (0, ps_a), "heap page follows the extra region"

    proj = cm.project_slab_window(slab_a, ps_a + ps_b)
    assert proj.gaps == ()
    assert len(proj.segments) == 2
    first, second = proj.segments
    assert first.vas == tuple(vas_a)
    assert second.vas == tuple(vas_b)
    assert (first.vas[1] - first.vas[0]) != (second.vas[1] - second.vas[0])


def test_multidelta_round_trips_from_either_dumps_va(aslr_pair_extra):
    cm = aslr_pair_extra
    classes = list(np.asarray(cm.classifications).tolist())
    for (slab, page_size, vaddrs) in cm.msl_layout:
        for dump_index, va in enumerate(vaddrs):
            assert cm.slab_to_va(dump_index, slab) == va
            window = cm.class_window_va(dump_index, va, 128)
            assert window == classes[slab:slab + 128]


def test_multidelta_dump_index_for_path_finds_both_runs(aslr_pair_extra, tmp_path):
    cm = aslr_pair_extra
    assert cm.dump_index_for_path(str(tmp_path / "run_1.msl")) == 0
    assert cm.dump_index_for_path(str(tmp_path / "run_2.msl")) == 1


# --- defect (a): duplicate va_start rows -----------------------------------


def _overlapping_vector():
    """Two layout rows that resolve to the SAME VA in dump 0.

    Real cause: overlapping modules — ``core.region_align.build_module_lookup``
    logs exactly this. The wide row is listed first and the narrow one second,
    so a ``bisect_right`` that does not back up onto the first duplicate starts
    the walk on the narrow row and never sees the wide one's tail.
    """
    cm = ConsensusVector()
    cm._classifications = np.array([1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 0, 0], dtype=np.uint8)
    cm.msl_layout = [
        (0, 8, [0x1000, 0x5000]),   # wide row
        (8, 4, [0x1000, 0x9000]),   # narrow row at the SAME dump-0 VA
    ]
    cm.dump_paths = ["/run/a.msl", "/run/b.msl"]
    cm._va_index_cache = {}
    cm._slab_starts_cache = None
    return cm


def test_duplicate_va_start_rows_are_all_walked():
    cm = _overlapping_vector()
    # Narrow row wins its 4 bytes (it is walked last); the wide row must still
    # supply bytes 4..8. Before the (va_start, slab_offset) sort + cursor
    # back-up those four bytes read as -1.
    assert cm.class_window_va(0, 0x1000, 8) == [3, 3, 0, 0, 2, 2, 2, 2]


def test_duplicate_va_start_projection_reports_both_segments():
    cm = _overlapping_vector()
    proj = cm.project_va_window(0, 0x1000, 8)
    assert proj.gaps == ()
    # The narrow row is walked last and wins the first 4 bytes; the wide row
    # keeps the tail it alone covers. Segments describe that FINAL ownership,
    # so they stay disjoint even though the layout rows overlap.
    assert [s.layout_row for s in proj.segments] == [1, 0]
    assert [s.slab_offset for s in proj.segments] == [8, 4]
    assert [(s.window_offset, s.length) for s in proj.segments] == [(0, 4), (4, 4)]
    assert proj.segments[0].vas == (0x1000, 0x9000)
    assert proj.segments[1].vas == (0x1004, 0x5004)


def test_va_index_is_ordered_by_va_then_slab():
    cm = _overlapping_vector()
    assert cm._va_index_for(0) == [(0x1000, 0, 8), (0x1000, 8, 4)]


# --- defect (b): dump_index_for_path did not resolve -----------------------


def test_dump_index_for_path_resolves_dot_dot(tmp_path):
    """``/a/sub/../b.msl`` names the dump the build stored as ``/a/b.msl``."""
    (tmp_path / "sub").mkdir()
    a = tmp_path / "a.msl"
    a.write_bytes(b"")
    cm = ConsensusVector()
    cm.dump_paths = [str(a), str(tmp_path / "b.msl")]
    indirect = tmp_path / "sub" / ".." / "a.msl"
    assert Path(indirect) != a, "pathlib cannot collapse '..' on its own"
    assert cm.dump_index_for_path(str(indirect)) == 0


def test_dump_index_for_path_resolves_a_symlinked_parent(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    dump = real / "a.msl"
    dump.write_bytes(b"")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    cm = ConsensusVector()
    cm.dump_paths = [str(dump)]
    assert cm.dump_index_for_path(str(link / "a.msl")) == 0


def test_dump_index_for_path_still_rejects_a_stranger(tmp_path):
    cm = ConsensusVector()
    cm.dump_paths = [str(tmp_path / "a.msl")]
    assert cm.dump_index_for_path(str(tmp_path / "elsewhere.msl")) == -1
    assert cm.dump_index_for_path("") == -1
