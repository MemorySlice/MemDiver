"""Per-dump page-state runs on the aligned window (``dumps[].page_states``).

Each pane of the side-by-side view is tinted with ITS OWN dump's MSL page
states (spec §7), delivered in WINDOW INDEX space — the space ``bytes_valid``
is in — so the client never does VA arithmetic for a peer. Pinned here:

* runs are ``[offset, length, state]``, window-relative, ascending, merged;
* only FAILED / NOT_RESIDENT / UNMAPPED (explicit, and inter-region gaps
  inside the VA span) — CAPTURED never appears;
* bytes with no correspondence in a dump are never tinted for that dump;
* raw / flat coordinates and non-``.msl`` dumps carry no runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app import page_state_runs  # noqa: E402
from memdiver.app.key_material import open_dump_source  # noqa: E402
from memdiver.app.tools_consensus import (  # noqa: E402
    COORDINATE_ALIGNED,
    _read_dump_window,
    _vas_run_table,
    aligned_window_from_vector,
)
from memdiver.engine.consensus import AlignedSegment, WindowProjection  # noqa: E402
from memdiver.engine.consensus_service import build_consensus  # noqa: E402
from memdiver.msl.enums import PageState  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402
from tests.fixtures.generate_msl_fixtures import PAGE_SIZE  # noqa: E402

C, F, U, N = (PageState.CAPTURED, PageState.FAILED,
              PageState.UNMAPPED, PageState.NOT_RESIDENT)
REGION_A = 0x10000
REGION_B = 0x20000
HALF = PAGE_SIZE // 2


def _write_msl(path: Path, states, fill: int) -> str:
    """One mixed-state region at REGION_A plus a captured page at REGION_B.

    The second region opens an inter-region gap ``[REGION_A + 5 pages,
    REGION_B)`` inside the VA span, which the single view calls UNMAPPED.
    """
    writer = MslWriter(str(path), pid=7, imported=False)
    writer.add_process_identity(exe_path="/proc")
    captured = sum(1 for s in states if s == C)
    writer.add_memory_region(
        REGION_A, bytes([fill]) * PAGE_SIZE * captured, page_states=states)
    writer.add_memory_region(REGION_B, b"\x42" * PAGE_SIZE, page_states=[C])
    writer.add_end_of_capture()
    writer.write()
    return str(path)


@pytest.fixture
def mixed_pair(tmp_path):
    """X: C F F U U   Y: C N C C C — different states at the same VAs."""
    x = _write_msl(tmp_path / "x.msl", [C, F, F, U, U], 0xA1)
    y = _write_msl(tmp_path / "y.msl", [C, N, C, C, C], 0xB2)
    return x, y


def _window(paths, va_start: int, length: int, vas=None):
    """Read ONE VA-linear segment at ``va_start`` in every dump, per dump."""
    segment = AlignedSegment(
        window_offset=0, length=length, slab_offset=0, layout_row=0,
        vas=tuple(vas or [va_start] * len(paths)),
    )
    projection = WindowProjection(
        anchor_index=0, start=va_start, length=length,
        segments=(segment,), gaps=(), classes=tuple([0] * length),
    )
    blocks = []
    for index, path in enumerate(paths):
        with open_dump_source(path, {}) as source:
            block, _buf, _valid = _read_dump_window(
                source, path, projection, index, length, COORDINATE_ALIGNED,
                True, _vas_run_table(source),
            )
        blocks.append(block)
    return blocks


def _states(blocks):
    return [block["page_states"] for block in blocks]


def test_two_dumps_get_their_own_states_in_the_same_window(mixed_pair):
    x, y = _window(mixed_pair, REGION_A, 5 * PAGE_SIZE)
    assert x["page_states"] == [
        [PAGE_SIZE, 2 * PAGE_SIZE, "FAILED"],
        [3 * PAGE_SIZE, 2 * PAGE_SIZE, "UNMAPPED"],
    ]
    assert y["page_states"] == [[PAGE_SIZE, PAGE_SIZE, "NOT_RESIDENT"]]


def test_window_starting_mid_region_is_window_relative(mixed_pair):
    x, y = _window(mixed_pair, REGION_A + HALF, 2 * PAGE_SIZE)
    # Window covers VA [A+0.5p, A+2.5p): half a captured page, then FAILED.
    assert x["page_states"] == [[HALF, 3 * HALF, "FAILED"]]
    assert y["page_states"] == [[HALF, PAGE_SIZE, "NOT_RESIDENT"]]
    assert x["bytes_valid"] == [[0, HALF]]


def test_explicit_unmapped_merges_with_the_inter_region_gap(mixed_pair):
    x, y = _window(mixed_pair, REGION_A + 3 * PAGE_SIZE, 4 * PAGE_SIZE)
    # Explicit UNMAPPED pages 3-4, then the gap past the region: ONE run.
    assert x["page_states"] == [[0, 4 * PAGE_SIZE, "UNMAPPED"]]
    # Y captured pages 3-4; only the gap behind them is UNMAPPED.
    assert y["page_states"] == [[2 * PAGE_SIZE, 2 * PAGE_SIZE, "UNMAPPED"]]


def test_captured_is_never_reported_and_never_overlaps_bytes_valid(mixed_pair):
    for block in _window(mixed_pair, REGION_A, 5 * PAGE_SIZE):
        states = {run[2] for run in block["page_states"]}
        assert states <= {"FAILED", "UNMAPPED", "NOT_RESIDENT"}
        tinted = {i for o, n, _s in block["page_states"] for i in range(o, o + n)}
        valid = {i for o, n in block["bytes_valid"] for i in range(o, o + n)}
        assert not tinted & valid


def test_a_peer_with_no_correspondence_is_not_tinted(mixed_pair):
    """A segment whose peer VA is -1 has no correspondence: no runs at all."""
    x, y = _window(mixed_pair, REGION_A, 5 * PAGE_SIZE, vas=[REGION_A, -1])
    assert x["page_states"]
    assert y["page_states"] == []
    assert y["bytes_valid"] == []


def test_include_bytes_false_still_reports_states(mixed_pair):
    window = aligned_window_from_vector(
        build_consensus(list(mixed_pair)), anchor_path=mixed_pair[0],
        anchor_view="va", offset=0, length=2 * PAGE_SIZE, include_bytes=False,
    )
    assert window["dumps"][0]["page_states"] == [
        [PAGE_SIZE, PAGE_SIZE, "FAILED"]]


def test_end_to_end_anchor_pane_is_tinted_through_gaps(mixed_pair):
    """Rows exist only where every dump captured, so the anchor's FAILED
    pages sit in ``gaps``; the anchor (VA-linear) still gets them tinted."""
    consensus = build_consensus(list(mixed_pair))
    window = aligned_window_from_vector(
        consensus, anchor_path=mixed_pair[0], anchor_view="va",
        offset=HALF, length=4 * PAGE_SIZE,
    )
    anchor, peer = window["dumps"]
    # VA [A+0.5p, A+4.5p): half captured, FAILED p1-p2, UNMAPPED p3-p4.5.
    assert anchor["page_states"] == [
        [HALF, 2 * PAGE_SIZE, "FAILED"],
        [HALF + 2 * PAGE_SIZE, PAGE_SIZE + HALF, "UNMAPPED"],
    ]
    # The peer's NOT_RESIDENT page is NOT in correspondence (it is a gap).
    peer_tinted = {i for o, n, _s in peer["page_states"] for i in range(o, o + n)}
    gap = {i for o, n in window["gaps"] for i in range(o, o + n)}
    assert not peer_tinted & gap


def test_raw_file_coordinate_has_no_runs(mixed_pair):
    window = aligned_window_from_vector(
        None, dumps=list(mixed_pair), anchor_path=mixed_pair[0],
        anchor_view="vas", offset=0, length=4096,
    )
    assert all(block["page_states"] == [] for block in window["dumps"])


def test_non_msl_dump_has_no_runs(tmp_path):
    a = tmp_path / "a.dump"
    b = tmp_path / "b.dump"
    a.write_bytes(bytes(range(256)) * 16)
    b.write_bytes(bytes(range(256)) * 16)
    window = aligned_window_from_vector(
        build_consensus([str(a), str(b)]), anchor_path=str(a),
        anchor_view="raw", offset=0, length=1024,
    )
    assert [block["page_states"] for block in window["dumps"]] == [[], []]


def test_state_table_is_built_once_per_reader(mixed_pair, monkeypatch):
    calls = []
    real = page_state_runs.build_state_table

    def counting(regions):
        calls.append(1)
        return real(regions)

    monkeypatch.setattr(page_state_runs, "build_state_table", counting)
    with open_dump_source(mixed_pair[0], {}) as source:
        reader = source.get_reader()
        first = page_state_runs.cached_state_table(reader)
        second = page_state_runs.cached_state_table(reader)
    assert first is second
    assert len(calls) == 1


def test_merge_runs_joins_only_adjacent_same_state():
    merged = page_state_runs.merge_runs([
        [8, 4, "FAILED"], [0, 4, "FAILED"], [4, 4, "FAILED"],
        [12, 2, "UNMAPPED"], [20, 1, "UNMAPPED"],
    ])
    assert merged == [[0, 12, "FAILED"], [12, 2, "UNMAPPED"], [20, 1, "UNMAPPED"]]
