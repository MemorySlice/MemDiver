"""Aligned-window producer + route: the N-dump differential read.

Invariant W1 is what every test here is ultimately pinning. For every dump
``d`` and every ``i`` in ``[0, length)``, ``dumps[d].bytes[i]`` is the byte
``d`` holds at the address the consensus put in correspondence with the
anchor's byte at ``offset + i``. Where no correspondence exists: ``i`` falls in
a ``gaps`` run, ``classes[i] == -1``, ``bytes[i] == 0x00``, and ``i`` is
outside every ``bytes_valid`` run.

The flagship (T1) is deliberately NON-VACUOUS: it asserts run 2's bytes are
the SECRET of run 2 and not the page filler (``0xFE``) and not zeros. A
producer that read the peer at the anchor's own offset would return the filler
and a producer that read an unmapped VA would return zeros, so both broken
implementations fail loudly rather than "look plausible".
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from memdiver.api.main import create_app  # noqa: E402
from memdiver.api.services.consensus_session import ConsensusSessionManager  # noqa: E402
from memdiver.app.composition import build_tool_session  # noqa: E402
from memdiver.app.tools_consensus import (  # noqa: E402
    COORDINATE_ALIGNED,
    MAX_WINDOW_TOTAL_BYTES,
    _project_window,
    aligned_window_from_vector,
    aligned_window_result,
)
from memdiver.core.service_errors import CapabilityError  # noqa: E402
from memdiver.engine.consensus import MAX_CONSENSUS_WINDOW  # noqa: E402
from memdiver.engine.consensus_service import build_consensus  # noqa: E402
from tests.fixtures.generate_msl_fixtures import PAGE_SIZE  # noqa: E402
from tests.test_consensus_alignment import _write_core  # noqa: E402
from tests.fixtures.generate_msl_aslr_fixtures import (  # noqa: E402
    EXTRA_BASE_RUN1,
    HEAP_BASE_RUN1,
    HEAP_BASE_RUN2,
    SECRET_OFFSET_IN_PAGE,
    SECRET_VALUES_BY_RUN,
    generate_aslr_msl_pair,
)

#: The secret's absolute VA in run 1, and run 1's VA-view span start. The extra
#: region sorts FIRST, so the span starts at IT, not at the heap — which is the
#: whole reason a single scalar "VA delta per dump" cannot describe this pair.
SECRET_VA_RUN1 = HEAP_BASE_RUN1 + SECRET_OFFSET_IN_PAGE
VA_SPAN_START_RUN1 = EXTRA_BASE_RUN1
#: Slab coordinates measured off the built layout: row 0 is the extra region
#: (run-to-run delta 0x1000), row 1 is the heap page (delta 0x10000000).
SLAB_HEAP_PAGE = 4096
SLAB_SECRET = SLAB_HEAP_PAGE + SECRET_OFFSET_IN_PAGE
SLAB_TOTAL = 8192
HEAP_DELTA = 0x10000000
EXTRA_DELTA = 0x1000


@pytest.fixture
def aslr_pair(tmp_path):
    """Two ASLR-shifted ``.msl`` runs with TWO differently-shifted regions."""
    run1, run2 = generate_aslr_msl_pair(extra_region=True)
    p1 = tmp_path / "run_1.msl"
    p2 = tmp_path / "run_2.msl"
    p1.write_bytes(run1)
    p2.write_bytes(run2)
    return str(p1), str(p2)


@pytest.fixture
def aslr_consensus(aslr_pair):
    return build_consensus(list(aslr_pair)), aslr_pair


@pytest.fixture
def flat_pair(tmp_path):
    """Two plain ``.dump`` files — a flat (``file_offset``) build."""
    p1 = tmp_path / "a.dump"
    p2 = tmp_path / "b.dump"
    p1.write_bytes(bytes(range(256)) * 4)
    p2.write_bytes(bytes(range(256)) * 4)
    return str(p1), str(p2)


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture(autouse=True)
def _fresh_manager(monkeypatch):
    """Per-test consensus manager so ids never leak between tests."""
    import memdiver.api.services.consensus_session as mod

    manager = ConsensusSessionManager()
    monkeypatch.setattr(mod, "_default_manager", manager)
    yield manager


def _bytes_of(block) -> bytes:
    assert block["bytes"] is not None
    return base64.b64decode(block["bytes"])


# ---------------------------------------------------------------------------
# T1 — the flagship. Real ASLR, real secrets, non-vacuous.
# ---------------------------------------------------------------------------


def test_t1_window_reads_each_run_secret_at_its_own_address(aslr_consensus):
    """Anchor on run 1's secret VA; run 2 must yield RUN 2's secret.

    Every assertion below is a different broken implementation:
    ``!= 0xFE * 32`` fails a producer that applied the anchor's offset to the
    peer (it would land in run 2's page filler); ``!= 0x00 * 32`` fails one
    that read an unmapped VA; the ``0x10000000`` delta fails one that assumed
    the pair's ONE shift is the extra region's ``0x1000``.
    """
    consensus, (p1, _p2) = aslr_consensus
    offset = SECRET_VA_RUN1 - VA_SPAN_START_RUN1

    window = aligned_window_from_vector(
        consensus, anchor_path=p1, anchor_view="va", offset=offset, length=32,
    )

    assert window["classified"] is True
    assert window["alignment"]["method"] == "module_offset"
    assert window["length"] == 32
    assert window["truncated"] is False
    assert window["gaps"] == []
    assert len(window["classes"]) == 32

    assert _bytes_of(window["dumps"][0]) == SECRET_VALUES_BY_RUN[1]
    assert _bytes_of(window["dumps"][1]) == SECRET_VALUES_BY_RUN[2]
    assert _bytes_of(window["dumps"][1]) != b"\xFE" * 32  # not the page filler
    assert _bytes_of(window["dumps"][1]) != b"\x00" * 32  # not an unmapped read

    seg = window["segments"][0]
    assert seg["slab_offset"] == SLAB_SECRET
    assert seg["dumps"][1]["va"] - seg["dumps"][0]["va"] == HEAP_DELTA
    assert seg["dumps"][1]["offset"] != seg["dumps"][0]["offset"]
    assert window["anchor"]["slab_offset"] == SLAB_SECRET


def test_t1_multi_page_window_carries_two_different_deltas(aslr_consensus):
    """A window spanning BOTH aligned pages: two segments, two deltas.

    This is the case a single per-dump peer offset gets wrong in a way that
    reads as plausible bytes — the two regions moved by ``0x1000`` and
    ``0x10000000`` between runs, so the correct answer cannot be one scalar.
    """
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, slab_offset=SLAB_HEAP_PAGE - 16, length=96,
    )

    segments = window["segments"]
    assert len(segments) == 2, segments
    deltas = [s["dumps"][1]["va"] - s["dumps"][0]["va"] for s in segments]
    assert deltas == [EXTRA_DELTA, HEAP_DELTA]
    assert deltas[0] != deltas[1]

    # W1: the bytes follow the per-segment coordinates, not one of them.
    run1 = _bytes_of(window["dumps"][0])
    run2 = _bytes_of(window["dumps"][1])
    assert run1[:16] == b"\x00" * 16          # run 1's extra-region filler
    assert run2[:16] == b"\xFE" * 16          # run 2's extra-region filler
    assert run1[16:16 + 4] == b"\x00" * 4     # heap page 0, run 1 filler
    assert run2[16:16 + 4] == b"\xFE" * 4
    assert window["dumps"][0]["bytes_valid"] == [[0, 16], [16, 80]]


def test_vas_anchor_crosses_a_run_boundary_and_reads_each_peer_secret(aslr_consensus):
    """A ``vas`` anchor spanning BOTH captured runs must not stop at the first.

    The ``"vas"`` view is the dump's captured bytes laid end to end — runs
    ``[(0x10000000, 4096) -> vas 0, (0x7fff00000000, 4096) -> vas 4096]``, so
    vas 4096 is the very next byte after vas 4095 with nothing in between. A
    window walk that resolves the anchor VA to ONE layout row and then stops
    at that row's edge reports the second run as a gap, which says "no dump
    has a byte in correspondence here" about bytes every dump captured — and
    it hides the secret, which lives in the SECOND run.

    Non-vacuous in the T1 style: run 2's bytes must be run 2's secret, not the
    ``0xFE`` page filler a peer read at the anchor's own offset would return,
    and not the zeros an unmapped-VA read would return.
    """
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, anchor_path=_paths[0], anchor_view="vas",
        offset=0, length=SLAB_TOTAL, include_bytes=True,
    )

    assert window["gaps"] == []
    segments = window["segments"]
    assert len(segments) == 2, segments
    assert (segments[0]["window_offset"], segments[0]["length"],
            segments[0]["slab_offset"]) == (0, 4096, 0)
    assert (segments[1]["window_offset"], segments[1]["length"],
            segments[1]["slab_offset"]) == (4096, 4096, SLAB_HEAP_PAGE)

    # W1: each dump's bytes at the secret's window index are ITS OWN secret.
    secret_at = SLAB_HEAP_PAGE + SECRET_OFFSET_IN_PAGE
    for position, (block, filler) in enumerate(
        zip(window["dumps"], (b"\x00", b"\xFE")),
    ):
        run = position + 1
        seen = _bytes_of(block)[secret_at:secret_at + 32]
        assert seen == SECRET_VALUES_BY_RUN[run], f"run {run}"
        assert seen != b"\x00" * 32     # not an unmapped / never-walked read
        assert seen != filler * 32      # not that run's page filler


def test_vas_anchor_starting_at_the_second_run_lands_on_that_run(aslr_consensus):
    """A ``vas`` anchor AT a run boundary starts in the run it names.

    vas 4096 is the first byte of the second captured run — the exact seam the
    run-boundary fix introduced a re-basing step for. Here the sub-walk's base
    is 0, so the VA walk and the VAS walk have always agreed; the point is that
    they must STILL agree, byte for byte, after the change. The secret lands at
    its own page offset in the window, not shifted by the seam.

    Non-vacuous in the T1 style: each dump must yield ITS OWN secret, so a
    producer that read every peer at the anchor's coordinate fails here too.
    """
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, anchor_path=_paths[0], anchor_view="vas",
        offset=4096, length=4096,
    )

    assert window["gaps"] == []
    assert [(s["window_offset"], s["length"], s["slab_offset"])
            for s in window["segments"]] == [(0, 4096, SLAB_HEAP_PAGE)]

    for position, block in enumerate(window["dumps"]):
        run = position + 1
        seen = _bytes_of(block)[
            SECRET_OFFSET_IN_PAGE:SECRET_OFFSET_IN_PAGE + 32
        ]
        assert seen == SECRET_VALUES_BY_RUN[run], f"run {run}"


def test_vas_window_past_the_last_run_is_a_gap_not_a_wrong_read(aslr_consensus):
    """Past the end of the VAS stream there is nothing — say so, don't guess.

    The dense stream is 8192 bytes (two captured runs); an 8192-byte window
    starting at 4096 therefore runs 4096 bytes off its end. The new walk
    composes one sub-walk per overlapping run, and the hazard a composition
    adds is not stopping: a piece that took the WINDOW's end instead of
    ``min(window_end, run_end)`` would walk past the stream into the page
    physically behind the heap run — which this fixture deliberately marks
    FAILED, so its filler would read back as bytes every dump held.

    The pin is that a gap stays a gap, and that it says so all three W1 ways
    at once: a ``gaps`` run, ``classes == -1``, and outside every
    ``bytes_valid`` run. The last is the one Part 1 makes true; before it,
    ``bytes_valid`` came from ``len(data)`` and would have claimed the filler.
    """
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, anchor_path=_paths[0], anchor_view="vas",
        offset=4096, length=2 * 4096,
    )

    assert [(s["window_offset"], s["length"]) for s in window["segments"]] == [
        (0, 4096),
    ]
    assert window["gaps"] == [[4096, 4096]]
    assert window["classes"][4096:] == [-1] * 4096
    assert all(c >= 0 for c in window["classes"][:4096])
    for block in window["dumps"]:
        assert _bytes_of(block)[4096:] == b"\x00" * 4096
        covered = {
            i for start, run in block["bytes_valid"] for i in range(start, start + run)
        }
        assert not covered & set(range(4096, 8192))


def test_a_vas_anchor_with_no_runs_projects_nothing_not_va_linearly(aslr_consensus):
    """An EMPTY run table must NOT fall through to the VA-linear walk.

    ``_va_is_addressable`` rejects an empty table back in ``_resolve_anchor``,
    so this is not reachable through any route today. It is pinned anyway
    because what the empty table used to fall through to was the WRONG ANSWER,
    not a missing one: ``project_va_window`` marches off the end of the first
    captured run into unmapped VA and reports bytes every dump captured as a
    gap — the exact failure ``project_vas_window`` exists to remove. "This
    anchor has no captured runs" is evidence there is nothing to walk, never
    evidence for walking it the other way, so the honest answer is an EMPTY
    projection: all gaps, every class ``-1``.
    """
    consensus, _paths = aslr_consensus
    kwargs = dict(
        coordinate=COORDINATE_ALIGNED, anchor_index=0, anchor_va=SECRET_VA_RUN1,
        start=0, length=32, n_dumps=2, flat_size=0, anchor_view="vas",
    )

    empty = _project_window(consensus, anchor_runs=(), **kwargs)
    assert empty.segments == ()
    assert empty.gaps == ((0, 32),)
    assert set(empty.classes) == {-1}

    # Non-vacuous: the VA-linear walk this no longer falls through to DOES
    # answer for the same arguments, so a regression would show as segments.
    assert consensus.project_va_window(0, SECRET_VA_RUN1, 32).segments


def test_vas_and_va_anchors_agree_inside_one_run(aslr_consensus):
    """The VAS walk must not perturb the answer the VA walk already gave.

    Inside a single captured run the two coordinates are the same line, just
    based differently, so the projection is the SAME projection — same
    segments, same classes, same bytes. This is the regression half of the
    run-boundary fix: it is easy to make crossing work by re-deriving VA->slab
    a second way, and then the two answers drift for the bytes they share.
    """
    consensus, paths = aslr_consensus
    length = 256
    vas_offset = 4096 + 64            # well inside the heap run
    va_offset = (HEAP_BASE_RUN1 + 64) - VA_SPAN_START_RUN1

    by_vas = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="vas",
        offset=vas_offset, length=length,
    )
    by_va = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="va",
        offset=va_offset, length=length,
    )

    assert by_vas["segments"] == by_va["segments"]
    assert by_vas["classes"] == by_va["classes"]
    assert by_vas["gaps"] == by_va["gaps"]
    for vas_block, va_block in zip(by_vas["dumps"], by_va["dumps"]):
        assert _bytes_of(vas_block) == _bytes_of(va_block)
        assert vas_block["bytes_valid"] == va_block["bytes_valid"]


def test_w1_gap_bytes_are_zero_unclassified_and_outside_bytes_valid(aslr_consensus):
    """The other half of W1: where there is no correspondence, say so 3 ways."""
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, slab_offset=SLAB_TOTAL - 92, length=200,
    )

    assert window["gaps"] == [[92, 108]]
    assert set(window["classes"][92:]) == {-1}
    assert all(c >= 0 for c in window["classes"][:92])
    for block in window["dumps"]:
        assert _bytes_of(block)[92:] == b"\x00" * 108
        assert block["bytes_valid"] == [[0, 92]]


def test_segments_and_gaps_partition_the_window(aslr_consensus):
    """Every byte of the window is in exactly one segment or one gap."""
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, slab_offset=SLAB_TOTAL - 64, length=256,
    )
    _assert_partition(window)


@pytest.mark.parametrize("length", [256, 8192, MAX_CONSENSUS_WINDOW])
@pytest.mark.parametrize("offset", [0, 64, 4096, 4096 + 64])
def test_a_vas_window_partitions_and_never_outruns_a_layout_row(
    aslr_consensus, offset, length,
):
    """The VAS walk keeps BOTH invariants ``_project`` is relied on for.

    The partition is what lets a client paint the window with no arithmetic of
    its own. The page ceiling is subtler and is what Part 1's safety rests on:
    ``core/region_align.py::align_dumps`` makes one layout row exactly one page
    that EVERY dump captured, so a segment no wider than a row can never
    straddle a captured/FAILED boundary in a peer — which is the only reason a
    single ``read_range`` per segment is an honest read at all. A walk that
    merged adjacent runs into one wide segment would pass the partition check
    and quietly break that.

    ``MAX_CONSENSUS_WINDOW`` is in the sweep because the CLI and MCP surfaces
    can ask for it even though the web UI chunks at 8192.
    """
    consensus, paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="vas",
        offset=offset, length=length,
    )
    assert window["length"] == length, "no clamp expected at 2 dumps"
    _assert_partition(window)
    assert all(s["length"] <= PAGE_SIZE for s in window["segments"])


def _assert_partition(window) -> None:
    """Segments + gaps are ascending, disjoint, and cover ``[0, length)``."""
    spans = sorted(
        [(s["window_offset"], s["length"]) for s in window["segments"]]
        + [tuple(g) for g in window["gaps"]]
    )
    cursor = 0
    for start, run in spans:
        assert start == cursor
        assert run > 0
        cursor += run
    assert cursor == window["length"] == len(window["classes"])


# ---------------------------------------------------------------------------
# ``bytes_valid`` is a PRESENCE claim, not a byte count
# ---------------------------------------------------------------------------


def test_bytes_valid_never_covers_backend_filler(aslr_pair):
    """``bytes_valid`` must mark only CAPTURED bytes, never the read's padding.

    ``core/dump_source.py::_read_range_va`` always hands back a buffer of the
    full requested length — captured runs copied in, FAILED/UNMAPPED/gap
    positions left ``0x00`` — and its own docstring says callers must use the
    page states, not the byte values, to tell real bytes from filler.
    ``_read_dump_window`` nevertheless derives ``bytes_valid`` from
    ``len(data)``, so every padding byte is claimed as present. That is a
    contract violation the client cannot detect: a zero inside ``bytes_valid``
    reads as "this dump really holds 0x00 here", which is the opposite of "this
    dump never captured this page".

    Unit-level on purpose: ``core/region_align.py::align_dumps`` makes one
    ``msl_layout`` row exactly one page that every dump captured, and
    ``_project`` never merges rows, so today's walk can never emit a segment
    that straddles a captured/FAILED boundary. The bug is latent, not absent —
    it goes live the moment the walk emits wider segments, which is exactly
    what the run-boundary fix does.
    """
    from memdiver.app.key_material import open_dump_source
    from memdiver.app.tools_consensus import (
        COORDINATE_ALIGNED,
        _read_dump_window,
        _vas_run_table,
    )
    from memdiver.engine.consensus import AlignedSegment, WindowProjection

    path = aslr_pair[0]
    length = 2 * 4096
    # ONE segment running from the CAPTURED heap page straight into the FAILED
    # one behind it. ``vas`` is parallel to the build order, so entry 0 is run
    # 1's heap base and entry 1 is run 2's.
    segment = AlignedSegment(
        window_offset=0, length=length, slab_offset=0, layout_row=0,
        vas=(HEAP_BASE_RUN1, HEAP_BASE_RUN2),
    )
    projection = WindowProjection(
        anchor_index=0, start=HEAP_BASE_RUN1, length=length,
        segments=(segment,), gaps=(),
        classes=tuple([0] * length),   # unread by the function under test
    )

    with open_dump_source(path, {}) as source:
        block, _buffer, _valid = _read_dump_window(
            source, path, projection, 0, length, COORDINATE_ALIGNED, True,
            _vas_run_table(source),
        )

    data = base64.b64decode(block["bytes"])
    assert data[4096:] == b"\x00" * 4096        # the FAILED page's filler
    assert block["bytes_valid"] == [[0, 4096]]  # ... and it is NOT claimed


def test_include_bytes_false_claims_no_bytes_valid(aslr_consensus):
    """No read happened, so there is nothing to claim as present.

    ``bytes_valid`` is a claim about bytes in ``bytes``; with ``bytes: None``
    there are none, and a full-length run would be a presence claim for a read
    the producer never performed. Which bytes the window COVERS is already
    carried by ``segments[]``, so nothing is lost — this is the same
    convention a LOCKED peer answers with.
    """
    consensus, paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="vas",
        offset=0, length=SLAB_TOTAL, include_bytes=False,
    )

    assert len(window["segments"]) == 2, "coverage is still reported"
    for block in window["dumps"]:
        assert block["bytes"] is None
        assert block["bytes_valid"] == []


# ---------------------------------------------------------------------------
# The same run-boundary fix on the virtual_address (gcore) path
# ---------------------------------------------------------------------------


def test_a_gcore_vas_window_crosses_a_region_boundary(tmp_path):
    """The fix is about the COORDINATE, not about ``.msl``.

    ``_navigable_view`` answers ``"vas"`` for gcore and regioned-raw captures
    too, so their windows are walked the same way and break the same way — the
    two PT_LOADs here sit 0x7EFFF0000000 apart in VA and are adjacent in the
    dense stream. A VA-linear walk over ``[4080, 4144)`` would run off the end
    of the first segment into nothing.

    ``_write_core`` is the primitive behind ``_gcore_sources`` in
    ``tests/test_consensus_alignment.py``; the window producer re-opens dumps
    by PATH, so the path is what this test needs.
    """
    low, high = 0x10000000, 0x7F0000000000
    paths = [
        str(_write_core(tmp_path, f"core{i}.core", [
            (low, bytes([fill]) * PAGE_SIZE),
            (high, bytes([fill + 1]) * PAGE_SIZE),
        ]))
        for i, fill in enumerate((0x11, 0x33))
    ]
    consensus = build_consensus(paths)
    assert consensus.alignment_report.method == "virtual_address"

    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="vas",
        offset=PAGE_SIZE - 16, length=64,
    )

    assert window["gaps"] == []
    assert [(s["window_offset"], s["length"], s["slab_offset"])
            for s in window["segments"]] == [
        (0, 16, PAGE_SIZE - 16), (16, 48, PAGE_SIZE),
    ]
    for block, fill in zip(window["dumps"], (0x11, 0x33)):
        assert block["view"] == "vas"
        assert block["bytes_valid"] == [[0, 16], [16, 48]]
        # Non-vacuous: the tail is the SECOND region's fill, not the first's
        # repeated and not the zeros an off-the-end read would give.
        assert _bytes_of(block) == bytes([fill]) * 16 + bytes([fill + 1]) * 48


# ---------------------------------------------------------------------------
# T5 — the flat (file_offset) build
# ---------------------------------------------------------------------------


def test_t5_flat_build_serves_raw_view_and_reports_file_offset(flat_pair):
    consensus = build_consensus(list(flat_pair))
    assert consensus.msl_layout is None

    window = aligned_window_from_vector(
        consensus, anchor_path=flat_pair[0], anchor_view="raw",
        offset=16, length=32,
    )
    assert window["alignment"]["method"] == "file_offset"
    assert window["classified"] is True
    assert _bytes_of(window["dumps"][0]) == bytes(range(16, 48))
    assert _bytes_of(window["dumps"][1]) == bytes(range(16, 48))
    # Real classifications, not the -1 of an unclassified window.
    assert set(window["classes"]) != {-1}


def test_t5_flat_build_refuses_a_va_anchor(flat_pair):
    consensus = build_consensus(list(flat_pair))
    with pytest.raises(CapabilityError) as excinfo:
        aligned_window_from_vector(
            consensus, anchor_path=flat_pair[0], anchor_view="va", length=32,
        )
    assert excinfo.value.status == 400


def test_t5_flat_build_va_anchor_is_400_over_http(client, flat_pair):
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(flat_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor_path": flat_pair[0], "view": "va", "length": 32,
    })
    assert response.status_code == 400, response.text


# ---------------------------------------------------------------------------
# T6 — the no-consensus fallback, LABELLED
# ---------------------------------------------------------------------------


def test_t6_unclassified_equal_sizes_has_no_warnings_and_no_zero_classes(flat_pair):
    result = aligned_window_result(
        build_tool_session(), dump_paths=list(flat_pair),
        anchor_path=flat_pair[0], anchor_view="raw", offset=0, length=64,
        classify=False,
    )
    window = result.payload
    assert window["classified"] is False
    assert window["alignment"]["method"] == "file_offset"
    assert window["alignment"]["warnings"] == []
    assert window["alignment"]["n_sources"] == 2
    assert set(window["classes"]) == {-1}
    assert 0 not in window["classes"]   # INVARIANT is a claim nobody measured
    assert _bytes_of(window["dumps"][0]) == bytes(range(64))


def test_t6_unclassified_differing_sizes_warns_and_still_never_claims_zero(tmp_path):
    short = tmp_path / "short.dump"
    long_ = tmp_path / "long.dump"
    short.write_bytes(b"\x01" * 64)
    long_.write_bytes(b"\x02" * 256)

    result = aligned_window_result(
        build_tool_session(), dump_paths=[str(short), str(long_)],
        anchor_path=str(short), anchor_view="raw", offset=0, length=128,
        classify=False,
    )
    window = result.payload
    warnings = window["alignment"]["warnings"]
    assert warnings and "without ASLR correction" in warnings[0]
    assert window["alignment"]["sizes_differed"] is True
    assert set(window["classes"]) == {-1}
    assert 0 not in window["classes"]
    # Compared only up to the shortest dump; the rest is an honest gap.
    assert window["gaps"] == [[64, 64]]
    assert _bytes_of(window["dumps"][1])[:64] == b"\x02" * 64
    assert _bytes_of(window["dumps"][1])[64:] == b"\x00" * 64


# ---------------------------------------------------------------------------
# T7 — source lifetime: the build's sources are DEAD, the window re-opens
# ---------------------------------------------------------------------------


def test_t7_window_after_post_consensus_does_not_hit_a_closed_source(
    client, aslr_pair,
):
    """Regression shape of tests/test_api_consensus.py:140.

    ``build_consensus`` closes every source before it returns and the session
    keeps only the matrix, so a window served off a stored build MUST re-open
    the dumps. Reading the stored sources would raise
    ``RuntimeError('MslDumpSource not opened')``.
    """
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    )
    assert built.status_code == 200, built.text
    consensus_id = built.json()["consensus_id"]

    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": consensus_id,
        "anchor": "slab", "slab_offset": SLAB_SECRET, "length": 32,
    })
    assert response.status_code == 200, response.text
    window = response.json()
    assert window["consensus_id"] == consensus_id
    assert base64.b64decode(window["dumps"][0]["bytes"]) == SECRET_VALUES_BY_RUN[1]
    assert base64.b64decode(window["dumps"][1]["bytes"]) == SECRET_VALUES_BY_RUN[2]


def test_t7_each_selected_dump_is_opened_exactly_once(aslr_consensus, monkeypatch):
    """One open per selected dump — including the anchor, which reads off the
    same open source rather than re-opening its own."""
    import memdiver.app.key_material as key_material_module

    opens = []
    original = key_material_module.open_dump_source

    def _counting_open(path, km):
        opens.append(str(path))
        return original(path, km)

    monkeypatch.setattr(key_material_module, "open_dump_source", _counting_open)

    consensus, (p1, p2) = aslr_consensus
    aligned_window_from_vector(
        consensus, anchor_path=p1, anchor_view="va",
        offset=SECRET_VA_RUN1 - VA_SPAN_START_RUN1, length=32,
    )
    assert sorted(opens) == sorted([p1, p2])


# ---------------------------------------------------------------------------
# T8 — a locked peer costs that peer's bytes and NOTHING else
# ---------------------------------------------------------------------------


def _write_encrypted_msl(path: Path, key: bytes, data: bytes) -> None:
    """A NATIVE (``imported=False``) encrypted ``.msl``.

    Native on purpose: an imported container takes the flat-offset fallback,
    and the locked-peer behaviour this test pins has to be proven on an ALIGNED
    build — that is the path where a missing key could otherwise take the whole
    window down.
    """
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    writer = MslWriter(
        str(path), pid=7, imported=False,
        encryption=MslEncryptionConfig(raw_key=key),
    )
    writer.add_process_identity(exe_path="/proc")
    writer.add_memory_region(0x1000, data)
    writer.add_end_of_capture()
    writer.write()


@pytest.fixture
def encrypted_pair(tmp_path):
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    first = tmp_path / "enc_a.msl"
    second = tmp_path / "enc_b.msl"
    _write_encrypted_msl(first, key, b"\xA1" * 4096)
    _write_encrypted_msl(second, key, b"\xB2" * 4096)
    return str(first), str(second), {"key": key}


def test_t8_locked_peer_is_reported_and_the_other_dump_still_returns_bytes(
    encrypted_pair,
):
    """One peer nobody has the key for must not cost every other peer's bytes.

    ``raise_if_locked`` is deliberately NOT used: it would turn one missing key
    into a dead window. The locked dump reports ``bytes: None`` plus a hint and
    the plaintext-to-us peer is served normally.
    """
    first, second, key_material = encrypted_pair
    consensus = build_consensus([first, second], key_material=key_material)
    assert consensus.msl_layout is not None

    window = aligned_window_from_vector(
        consensus, slab_offset=0, length=64,
        key_material_by_path={first: key_material},   # second: no key
    )

    unlocked, locked = window["dumps"]
    assert unlocked["key_status"]["decrypted"] is True
    assert _bytes_of(unlocked) == b"\xA1" * 64

    assert locked["bytes"] is None
    assert locked["bytes_valid"] == []
    assert locked["key_status"]["decrypted"] is False
    assert locked["key_status"]["hint"]

    # The window itself is intact: classes and segments are unaffected.
    assert len(window["classes"]) == 64
    assert window["segments"]


# ---------------------------------------------------------------------------
# T9 — caps CLAMP length; they never drop a dump
# ---------------------------------------------------------------------------


def test_t9_window_cap_clamps_length_and_keeps_every_dump(aslr_consensus):
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(consensus, slab_offset=0, length=99999)
    assert window["requested_length"] == 99999
    assert window["length"] == 16384
    assert window["truncated"] is True
    assert len(window["dumps"]) == 2


def test_t9_total_bytes_cap_clamps_length_and_keeps_every_dump(monkeypatch, aslr_consensus):
    """The N-wide cap bites by CLAMPING, never by dropping a dump.

    A silently missing dump reads as "this dump has nothing there", which is a
    different and wrong answer, so the cap is forced down to a value only the
    length can satisfy.
    """
    import memdiver.app.tools_consensus as module

    monkeypatch.setattr(module, "MAX_WINDOW_TOTAL_BYTES", 128)
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(consensus, slab_offset=0, length=512)

    assert window["requested_length"] == 512
    assert window["length"] == 64          # 128 total / 2 dumps
    assert window["truncated"] is True
    assert len(window["dumps"]) == 2
    assert len(window["classes"]) == 64
    assert MAX_WINDOW_TOTAL_BYTES == 262144   # the real ceiling is untouched


def test_t9_subset_cap_rejects_rather_than_silently_trimming(aslr_consensus):
    consensus, (p1, _p2) = aslr_consensus
    with pytest.raises(CapabilityError) as excinfo:
        aligned_window_from_vector(
            consensus, slab_offset=0, length=16, dumps=[0, 1] * 20,
        )
    assert "at most 32 dumps" in str(excinfo.value)


# ---------------------------------------------------------------------------
# T10 — end-to-end: the returned offsets are a REAL viewer target
# ---------------------------------------------------------------------------


def test_t10_segment_offsets_reread_through_hex_raw_are_byte_identical(
    client, aslr_pair,
):
    """Re-read each dump at the offset the window reported, through the
    ordinary ``/api/inspect/hex-raw`` route, and get the same bytes back.

    This is the end-to-end proof that the coordinates handed to an operator
    ("go look here") name the very bytes the window painted.
    """
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    window = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor": "slab", "slab_offset": SLAB_SECRET, "length": 32,
    }).json()

    segment = window["segments"][0]
    assert segment["length"] == 32
    for block, provenance in zip(window["dumps"], segment["dumps"]):
        reread = client.get("/api/inspect/hex-raw", params={
            "dump_path": block["dump_path"],
            "offset": provenance["offset"],
            "length": segment["length"],
            "view": block["view"],
        })
        assert reread.status_code == 200, reread.text
        assert base64.b64decode(reread.json()["bytes"]) == (
            base64.b64decode(block["bytes"])[:segment["length"]]
        )


# ---------------------------------------------------------------------------
# The `.msl` raw-view refusal (the block-header trap)
# ---------------------------------------------------------------------------


def test_raw_view_is_refused_for_an_msl_anchor(aslr_consensus):
    """``va_to_file_offset`` answers with a BLOCK HEADER's offset, so a raw
    peer read lands on real bytes at the wrong address — the exact failure
    this endpoint exists to prevent."""
    consensus, (p1, _p2) = aslr_consensus
    with pytest.raises(CapabilityError) as excinfo:
        aligned_window_from_vector(
            consensus, anchor_path=p1, anchor_view="raw", offset=0, length=32,
        )
    assert "block header" in str(excinfo.value)


def test_no_msl_peer_is_ever_read_in_raw_view(aslr_consensus):
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(consensus, slab_offset=0, length=32)
    assert [block["view"] for block in window["dumps"]] == ["va", "va"]


# ---------------------------------------------------------------------------
# HTTP surface: the request/anchor/lifecycle errors
# ---------------------------------------------------------------------------


def test_http_requires_exactly_one_of_consensus_id_or_dump_paths(client, aslr_pair):
    neither = client.post("/api/analysis/consensus/aligned-window", json={})
    assert neither.status_code == 400

    both = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": "x", "dump_paths": list(aslr_pair),
    })
    assert both.status_code == 400


def test_http_unknown_consensus_id_is_404(client):
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": "nope", "anchor": "slab", "slab_offset": 0, "length": 16,
    })
    assert response.status_code == 404


def test_http_anchor_outside_the_build_is_404(client, aslr_pair, tmp_path):
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    stranger = tmp_path / "stranger.msl"
    stranger.write_bytes(b"not in the build")
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor_path": str(stranger), "length": 16,
    })
    assert response.status_code == 404, response.text


def test_http_unfinalized_incremental_vector_is_409(client, _fresh_manager):
    """An incremental session that was never finalized has a live Welford state
    and NO classifications; serving it would claim ``classified: true`` over a
    window whose every class is -1."""
    session = _fresh_manager.begin(256)
    _fresh_manager.add_dump(session.session_id, b"\x01" * 256)
    _fresh_manager.add_dump(session.session_id, b"\x02" * 256)

    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": session.session_id,
        "anchor": "slab", "slab_offset": 0, "length": 16,
    })
    assert response.status_code == 409, response.text


def test_http_dump_paths_branch_builds_and_serves(client, aslr_pair):
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "dump_paths": list(aslr_pair),
        "anchor": "slab", "slab_offset": SLAB_SECRET, "length": 32,
    })
    assert response.status_code == 200, response.text
    window = response.json()
    assert window["consensus_id"] is None
    assert window["classified"] is True
    assert base64.b64decode(window["dumps"][1]["bytes"]) == SECRET_VALUES_BY_RUN[2]


def test_http_dump_anchor_without_anchor_path_is_400_not_a_slab_window(
    client, aslr_pair,
):
    """The regression that 28 producer-level tests could not see.

    Every other test here either calls the producer with Python kwargs or
    spells the model's own field name, so none of them crossed the HTTP
    boundary with the name the frontend actually sends. When the request field
    was ``dump_path``, an ``anchor_path`` from the client was silently dropped
    by pydantic and the route fell through to a SLAB anchor at offset 0 — a
    200 carrying real bytes from a completely different address. Asking for a
    dump anchor and being handed a slab one is worse than an error, so the
    absent field must be a 400 and must NOT be a window.
    """
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor": "dump", "view": "va",
        "offset": SECRET_VA_RUN1 - VA_SPAN_START_RUN1, "length": 32,
    })

    assert response.status_code == 400, response.text
    assert "anchor_path" in response.json()["detail"]
    # Not a 200 slab window wearing an anchor it was never asked for.
    assert "anchor" not in response.json()
    assert "dumps" not in response.json()


def test_http_slab_anchor_without_slab_offset_is_400_not_offset_zero(
    client, aslr_pair,
):
    """The same refusal on the other anchor: 0 has to be said, not assumed."""
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"], "anchor": "slab", "length": 32,
    })

    assert response.status_code == 400, response.text
    assert "slab_offset" in response.json()["detail"]
    assert "dumps" not in response.json()


def test_http_dump_anchored_window_holds_w1_end_to_end(client, aslr_pair):
    """W1 through the ROUTE, with the wire name the frontend sends.

    Anchor on run 1's secret VA over HTTP; run 2 must come back with RUN 2's
    secret. Non-vacuous the same way T1 is: ``!= 0xFE * 32`` fails a peer read
    at the anchor's own offset (run 2's page filler), ``!= 0x00 * 32`` fails an
    unmapped read, and the two blocks differing fails any implementation that
    quietly served one dump's bytes twice — including the slab-at-0 fallback
    this endpoint used to degrade into.
    """
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor": "dump", "anchor_path": aslr_pair[0], "view": "va",
        "offset": SECRET_VA_RUN1 - VA_SPAN_START_RUN1, "length": 32,
    })

    assert response.status_code == 200, response.text
    window = response.json()
    assert window["anchor"]["kind"] == "dump"
    assert window["anchor"]["dump_path"] == aslr_pair[0]
    assert window["anchor"]["slab_offset"] == SLAB_SECRET

    run1 = base64.b64decode(window["dumps"][0]["bytes"])
    run2 = base64.b64decode(window["dumps"][1]["bytes"])
    assert run1 == SECRET_VALUES_BY_RUN[1]
    assert run2 == SECRET_VALUES_BY_RUN[2]
    assert run2 != run1                 # the peer is not the anchor re-served
    assert run2 != b"\xFE" * 32         # not run 2's page filler
    assert run2 != b"\x00" * 32         # not an unmapped read


def test_http_length_over_the_cap_is_clamped_not_rejected(client, aslr_pair):
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor": "slab", "slab_offset": 0, "length": 999999,
    })
    assert response.status_code == 200, response.text
    window = response.json()
    assert window["requested_length"] == 999999
    assert window["length"] <= 16384
    assert window["truncated"] is True
    assert len(window["dumps"]) == 2


# ---------------------------------------------------------------------------
# The other surfaces
# ---------------------------------------------------------------------------


def test_cli_consensus_window_emits_the_same_window(aslr_pair, tmp_path, capsys):
    import json

    from memdiver.cli.main import build_parser

    out = tmp_path / "window.json"
    parser = build_parser()
    args = parser.parse_args([
        "consensus-window", *aslr_pair,
        "--slab-offset", str(SLAB_SECRET), "--length", "32", "-o", str(out),
    ])
    from memdiver.cli.consensus import _cmd_consensus_window

    assert _cmd_consensus_window(args) == 0
    window = json.loads(out.read_text())
    assert base64.b64decode(window["dumps"][0]["bytes"]) == SECRET_VALUES_BY_RUN[1]
    assert base64.b64decode(window["dumps"][1]["bytes"]) == SECRET_VALUES_BY_RUN[2]


def test_cli_dispatch_table_registers_consensus_window():
    """The parser knows the subcommand AND main() dispatches it."""
    import inspect as _inspect

    from memdiver.cli.main import _build_parser, main as cli_entry_point

    assert '"consensus-window": _cmd_consensus_window' in _inspect.getsource(
        cli_entry_point
    )
    args = _build_parser().parse_args(["consensus-window", "a.msl", "b.msl"])
    assert args.command == "consensus-window"


def test_mcp_aligned_window_tool_returns_the_same_window(aslr_pair):
    pytest.importorskip("mcp")
    import json

    from memdiver.mcp_server.server import create_server

    server = create_server()
    tool = {t.name: t for t in server._tool_manager.list_tools()}["aligned_window"]
    raw = tool.fn(
        dump_paths=list(aslr_pair), slab_offset=SLAB_SECRET, length=32,
    )
    window = raw if isinstance(raw, dict) else json.loads(raw)
    assert base64.b64decode(window["dumps"][1]["bytes"]) == SECRET_VALUES_BY_RUN[2]


def test_library_surface_exposes_the_producer():
    import memdiver

    assert "aligned_window_result" in memdiver.services.__all__
    assert callable(memdiver.services.aligned_window_result)


# ---------------------------------------------------------------------------
# ``variants`` — the cross-dump comparison, server-side
# ---------------------------------------------------------------------------
#
# It lives on the producer because its per-dump read loop is the ONLY place in
# the backend where all N dumps' bytes exist at once: the vector stores
# variance and classifications, not bytes, and ``build_consensus`` closes its
# sources before it returns. Computing it in the browser instead was also
# wrong in a way no client test caught — the store's reducer walked every
# CACHED dump, including ones that had since left the selection.
#
# ``variants`` is also the DISAGREEMENT answer, and the only one on the wire:
# an index is a differ iff ``variants[i] >= 2``. The boolean ``differs`` field
# this endpoint used to ship alongside it was exactly that predicate, so it was
# removed rather than kept as a second field that must always agree.
# :func:`_differ_indices` re-derives it here, so every rule the old field was
# pinned on is still pinned — on the number that now carries it.


def _differ_indices(window) -> list:
    """The window indices where the dumps DISAGREE: ``variants[i] >= 2``."""
    return [i for i, count in enumerate(window["variants"]) if count >= 2]


def _differ_runs_of(window) -> list:
    """:func:`_differ_indices` run-length encoded, ``[[start, length]]``.

    The shape the removed ``differs`` field went out in, rebuilt in the test so
    the run-level assertions below keep saying what they always said: that a
    disagreement is reported at exactly these indices and at none of their
    neighbours.
    """
    runs: list = []
    for index in _differ_indices(window):
        if runs and runs[-1][0] + runs[-1][1] == index:
            runs[-1][1] += 1
        else:
            runs.append([index, 1])
    return runs


def _differing_dumps(tmp_path, *payloads: bytes) -> list:
    """N equal-length plain ``.dump`` files — a flat (``file_offset``) build."""
    paths = []
    for index, payload in enumerate(payloads):
        path = tmp_path / f"d{index}.dump"
        path.write_bytes(payload)
        paths.append(str(path))
    return paths


def test_identical_twins_report_no_difference_and_one_variant(flat_pair):
    """The real-world acceptance case: importing an ``.msl`` makes a TWIN.

    Two byte-identical dumps must read "nothing varies" all the way across —
    no index disagreeing and every in-segment ``variants`` exactly ``1``. An
    implementation that counted absent peers, or that compared a padded read
    against a real byte, paints a fully-differing window here and the overlay
    becomes noise on the one input whose answer is known.
    """
    consensus = build_consensus(list(flat_pair))
    window = aligned_window_from_vector(
        consensus, anchor_path=flat_pair[0], anchor_view="raw",
        offset=0, length=64,
    )

    assert window["gaps"] == []
    assert _differ_indices(window) == []
    assert window["variants"] == [1] * 64
    assert len(window["variants"]) == len(window["classes"])


def test_one_disagreeing_byte_is_one_run_of_one_at_that_index(tmp_path):
    """Exactly one run, exactly one byte wide, at exactly the right index.

    Pinned as a RUN rather than as a set membership so an off-by-one — the
    classic "edges come in pairs" bug — cannot pass by reporting the
    neighbour, and so a whole-window run cannot pass either.
    """
    base = bytes(range(256))
    other = bytearray(base)
    other[17] ^= 0xFF
    paths = _differing_dumps(tmp_path, base, bytes(other))

    consensus = build_consensus(paths)
    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="raw", offset=0, length=64,
    )

    assert _differ_runs_of(window) == [[17, 1]]
    assert window["variants"][17] == 2
    assert window["variants"][16] == window["variants"][18] == 1


def test_adjacent_disagreements_coalesce_into_one_run(tmp_path):
    """Three neighbours that differ are ONE run of 3, never three runs of 1.

    A key region disagrees in long stretches, not in scattered single bytes, so
    a reader that reports the stretch as three separate findings is describing
    the same window wrongly. ``variants`` is per index and cannot itself get
    this wrong, which is the point: the run is now derived, so the property is
    pinned on the number the client actually reads rather than on a second
    encoded field that could disagree with it.
    """
    base = bytes(range(256))
    other = bytearray(base)
    for index in (10, 11, 12):
        other[index] ^= 0xFF
    paths = _differing_dumps(tmp_path, base, bytes(other))

    consensus = build_consensus(paths)
    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="raw", offset=0, length=64,
    )

    assert _differ_runs_of(window) == [[10, 3]]
    assert window["variants"][10:13] == [2, 2, 2]


def test_three_dumps_holding_three_values_report_three_variants(tmp_path):
    """``variants`` counts DISTINCT VALUES, not "someone disagrees".

    No 3-dump ``.msl`` fixture exists, so this is the smallest honest one: three
    equal-length flat dumps. A boolean "somebody disagrees" cannot tell 2 dumps
    apart from 3 at one index — which is why the wire carries the count and not
    the boolean — and a reducer that returned ``len(dumps)`` rather than the
    distinct count passes the 2-dump tests above and fails here.
    """
    base = bytearray(bytes(range(256)))
    a, b, c = bytearray(base), bytearray(base), bytearray(base)
    a[5], b[5], c[5] = 0x01, 0x02, 0x03
    a[6] = b[6] = c[6] = 0x77
    paths = _differing_dumps(tmp_path, bytes(a), bytes(b), bytes(c))

    consensus = build_consensus(paths)
    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="raw", offset=0, length=32,
    )

    assert len(window["dumps"]) == 3
    assert window["variants"][5] == 3
    assert window["variants"][6] == 1
    assert _differ_runs_of(window) == [[5, 1]]


def test_a_byte_present_in_no_dump_has_no_variant_and_no_difference(tmp_path):
    """Inside a gap nobody is present, so ``variants`` is ``0`` — never ``1``.

    ``1`` would read as "every dump agrees here", which is the most misleading
    possible answer for a stretch no dump was even compared over. Uses the
    labelled no-consensus path with differing sizes, where the tail past the
    shortest dump is an honest gap.
    """
    short = tmp_path / "short.dump"
    long_ = tmp_path / "long.dump"
    short.write_bytes(b"\x01" * 64)
    long_.write_bytes(b"\x02" * 256)

    window = aligned_window_result(
        build_tool_session(), dump_paths=[str(short), str(long_)],
        anchor_path=str(short), anchor_view="raw", offset=0, length=128,
        classify=False,
    ).payload

    assert window["gaps"] == [[64, 64]]
    assert set(window["variants"][64:]) == {0}
    # The compared head still answers normally: 0x01 vs 0x02 everywhere.
    assert window["variants"][:64] == [2] * 64
    assert _differ_runs_of(window) == [[0, 64]]


def test_a_byte_present_in_only_one_dump_is_not_a_difference(tmp_path):
    """Absence is a DIFFERENT finding from disagreement, and must stay so.

    ``present >= 2`` is the whole rule: with one dump present there is nothing
    to disagree with, and flagging it would light up every unmapped hole in
    every dump — on a real capture that is most of the address space.

    Unit-level on the reducer's inputs, the same way
    ``test_bytes_valid_never_covers_backend_filler`` is, and for the same
    reason: ``core/region_align.py::align_dumps`` DISCARDS a page that is not
    captured in every dump, so today's aligned window can never contain a
    one-sided byte. The rule is latent, not absent — it goes live the moment
    alignment keeps partially-covered rows — so it is pinned on real blocks
    read out of real containers through a hand-built projection.
    """
    from memdiver.app.key_material import open_dump_source
    from memdiver.app.tools_consensus import (
        COORDINATE_ALIGNED,
        _cross_dump_runs,
        _read_dump_window,
        _vas_run_table,
    )
    from memdiver.engine.consensus import AlignedSegment, WindowProjection
    from memdiver.msl.enums import PageState
    from memdiver.msl.writer import MslWriter

    def write(path, page_states, data):
        writer = MslWriter(str(path), pid=7, imported=False)
        writer.add_process_identity(exe_path="/proc")
        writer.add_memory_region(0x1000, data, page_states=page_states)
        writer.add_end_of_capture()
        writer.write()

    both = tmp_path / "both.msl"
    partial = tmp_path / "partial.msl"
    # Page 0 identical in both; page 1 captured ONLY by ``both``.
    write(both, [PageState.CAPTURED, PageState.CAPTURED],
          b"\xA1" * PAGE_SIZE + b"\xC3" * PAGE_SIZE)
    write(partial, [PageState.CAPTURED, PageState.FAILED], b"\xA1" * PAGE_SIZE)

    length = 2 * PAGE_SIZE
    segment = AlignedSegment(
        window_offset=0, length=length, slab_offset=0, layout_row=0,
        vas=(0x1000, 0x1000),
    )
    projection = WindowProjection(
        anchor_index=0, start=0x1000, length=length,
        segments=(segment,), gaps=(), classes=tuple([0] * length),
    )

    reads = []
    for index, path in enumerate((str(both), str(partial))):
        with open_dump_source(path, {}) as source:
            reads.append(_read_dump_window(
                source, path, projection, index, length, COORDINATE_ALIGNED, True,
                _vas_run_table(source),
            ))

    assert reads[0][0]["bytes_valid"] == [[0, length]]
    assert reads[1][0]["bytes_valid"] == [[0, PAGE_SIZE]]

    variants = _cross_dump_runs(
        [buffer for _block, buffer, _valid in reads],
        [valid for _block, _buffer, valid in reads],
        length,
    )

    # Nothing one-sided is a differ: no index reaches the ``>= 2`` that says so.
    assert max(variants) < 2
    assert variants[:PAGE_SIZE] == [1] * PAGE_SIZE   # both present, agreeing
    assert variants[PAGE_SIZE:] == [1] * PAGE_SIZE   # one present, still ONE
    assert 0 not in variants[PAGE_SIZE:], "a present byte is never 0 variants"


def test_include_bytes_false_reports_no_difference_and_no_variants(aslr_consensus):
    """No bytes were read, so there is nothing to compare.

    Same convention ``bytes_valid`` already answers with: a claim about bytes
    the producer never read would be a fabrication. ``variants`` stays
    full-length (it mirrors ``classes``) but reads all ``0`` — "nobody present"
    — rather than ``1``, which would assert agreement nobody measured.
    """
    consensus, paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="vas",
        offset=0, length=SLAB_TOTAL, include_bytes=False,
    )

    assert _differ_indices(window) == []
    assert window["variants"] == [0] * window["length"]
    assert len(window["variants"]) == len(window["classes"])


def test_a_locked_dump_contributes_neither_disagreement_nor_a_variant(
    encrypted_pair,
):
    """A peer nobody has the key for must not MANUFACTURE a disagreement.

    The two containers hold 0xA1 and 0xB2, so treating the locked dump's
    all-zero buffer as data yields a fully-differing window — a confident,
    entirely fictional finding about bytes the producer could not read. The
    locked dump is skipped outright, which leaves one comparable dump: nothing
    can differ, and every index reports the one value that IS present.
    """
    first, second, key_material = encrypted_pair
    consensus = build_consensus([first, second], key_material=key_material)

    window = aligned_window_from_vector(
        consensus, slab_offset=0, length=64,
        key_material_by_path={first: key_material},   # second: no key
    )

    assert window["dumps"][1]["bytes"] is None
    assert _differ_indices(window) == []
    assert window["variants"] == [1] * 64


def test_http_window_carries_variants(client, aslr_pair):
    """The exact request shape the N-pane viewer sends, over the wire.

    The producer is shared by four surfaces, but only the route proves the
    field survives JSON: ``variants`` the same length as ``classes``, and
    carrying the disagreement verdict the client reads off it. The two runs'
    page filler is 0x00 vs 0xFE and their secrets differ, so a real
    disagreement is present — this cannot pass vacuously on an all-agreeing
    window.
    """
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor": "dump", "anchor_path": aslr_pair[0], "view": "va",
        "offset": SECRET_VA_RUN1 - VA_SPAN_START_RUN1, "length": 32,
    })

    assert response.status_code == 200, response.text
    window = response.json()
    assert len(window["variants"]) == len(window["classes"]) == window["length"]
    assert _differ_runs_of(window) == [[0, 32]]   # the two runs' secrets disagree
    assert window["variants"] == [2] * 32
    assert all(isinstance(count, int) for count in window["variants"])
    # The boolean the client derives, never a second wire field to drift from it.
    assert "differs" not in window


def test_the_window_never_leaks_its_private_comparison_buffers(aslr_consensus):
    """No underscore-prefixed key reaches the payload, anywhere in it.

    The raw window bytes and their validity runs exist only to carry bytes
    from the read loop to the reducer. Left in a block, every response would
    ship each dump's window TWICE — once as base64 and once as a raw ``bytes``
    that FastAPI would then fail (or silently mangle) on serialisation.

    They are no longer smuggled through the block at all: ``_read_dump_window``
    RETURNS them beside it, so the type system enforces what a pop-by-
    convention could only ask for. This test is the general form of the
    invariant rather than a two-name check, so a future private field cannot
    reintroduce the leak under a different spelling.
    """
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(consensus, slab_offset=0, length=64)

    private = []

    def _walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and key.startswith("_"):
                    private.append(f"{path}.{key}")
                _walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for i, value in enumerate(node):
                _walk(value, f"{path}[{i}]")

    _walk(window, "window")
    assert private == []
    for block in window["dumps"]:
        assert "offsets" not in block


# ---------------------------------------------------------------------------
# Reducer + accessor shortcuts (performance fixes that must stay answer-neutral)
# ---------------------------------------------------------------------------


def test_one_comparable_dump_short_circuits_to_the_same_answer():
    """A single dump cannot disagree with itself.

    The general path stacks, sorts and diffs an N x length array to conclude
    that no index reaches two variants; with N = 1 that work is pure overhead.
    The short-circuit must produce what the general path produced, including
    the "present byte is never 0 variants" rule.
    """
    import numpy as np

    from memdiver.app.tools_consensus import _cross_dump_runs, _dense_valid

    buffer = bytes(range(32)) * 4
    valid = [[0, 40], [64, 32]]
    variants = _cross_dump_runs([buffer], [valid], 128)

    assert max(variants) < 2
    mask = _dense_valid(valid, 128)
    assert variants == np.where(mask, 1, 0).tolist()
    assert all(isinstance(count, int) for count in variants)
    assert len(variants) == 128


def test_no_comparable_dump_still_reports_nobody_present():
    from memdiver.app.tools_consensus import _cross_dump_runs

    assert _cross_dump_runs([], [], 8) == [0] * 8
    assert _cross_dump_runs([b"abc"], [[[0, 3]]], 0) == []


def test_va_span_start_falls_back_to_metadata_for_a_source_without_the_accessor():
    """The narrow accessor is an optimisation, not a new requirement.

    ``.msl`` sources answer directly; anything else must keep working off the
    metadata dict, and a source that names no VA span must still say ``None``
    rather than a plausible ``0``.
    """
    from memdiver.app.tools_consensus import _va_span_start

    class _DictOnly:
        def metadata(self):
            return {"format": "gcore", "va_span_start": 0x7F0000000000}

    class _NoSpan:
        def metadata(self):
            return {"format": "raw"}

    class _Narrow:
        def metadata(self):  # pragma: no cover - must never be reached
            raise AssertionError("metadata() must not be built for one key")

        def va_span_start(self):
            return 0x400000

    assert _va_span_start(_DictOnly()) == 0x7F0000000000
    assert _va_span_start(_NoSpan()) is None
    assert _va_span_start(_Narrow()) == 0x400000
    assert _va_span_start(object()) is None


def test_flat_projection_classes_survive_the_slice_assignment():
    """``classes`` must stay plain ints, clipped to what the window covers."""
    import numpy as np

    from memdiver.app.tools_consensus import _flat_projection

    projection = _flat_projection(8, 0, 5, 2, [1, 2, 3, 4, 5, 6, 7, 8])
    assert projection.classes == (1, 2, 3, 4, 5, -1, -1, -1)

    from_numpy = _flat_projection(4, 0, 4, 2, np.arange(4, dtype=np.int8))
    assert from_numpy.classes == (0, 1, 2, 3)
    assert all(type(c) is int for c in from_numpy.classes)

    assert _flat_projection(4, 0, 4, 2, None).classes == (-1, -1, -1, -1)
