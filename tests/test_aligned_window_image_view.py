"""Aligned-window panes over ``.mdview`` image views carry page states.

An image view is navigable in ``"va"`` like an ``.msl``; its FAILED /
NOT_RESIDENT runs and the UNMAPPED gaps inside its span come back as
window-index ``page_states`` with ``bytes_valid`` false over them. A kernel-like
view whose ``"va"`` was dropped (span past 2^53-1) keeps the old behaviour.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import memdiver.core.image.sources as sources
from memdiver.app import page_state_runs
from memdiver.app.key_material import open_dump_source
from memdiver.app.tools_consensus import (
    COORDINATE_ALIGNED,
    _navigable_view,
    _read_dump_window,
    _va_view_span_size,
    _vas_run_table,
)
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.engine.consensus import AlignedSegment, WindowProjection
from memdiver.msl.enums import PageState
from memdiver.msl.writer import MslWriter

C, F, N = RunState.CAPTURED, RunState.FAILED, RunState.NOT_RESIDENT
PAGE = 0x1000
BASE = 0x10000
SHA = "ab" * 32


class FakeAdapter:
    def __init__(self, runs):
        self._runs = list(runs)

    def runs(self):
        return self._runs

    def vmas(self):
        return []

    def read(self, address, length):
        return b"\x41" * length

    def describe(self):
        return {"layer": "fake"}

    def close(self):
        pass


@pytest.fixture
def make_view(tmp_path, monkeypatch):
    (tmp_path / "img.bin").write_bytes(b"\0" * 64)

    def make(runs, name="v", kind=ViewKind.PROCESS):
        extra = dict(pid=7, profile=ProfileRef("p.json")) if kind is ViewKind.PROCESS \
            else dict(profile=ProfileRef("p.json"))
        path = ViewDescriptor("img.bin", SHA, kind, **extra).write(
            tmp_path / f"{name}.mdview")
        monkeypatch.setattr(sources, "_default_adapter_factory",
                            lambda d, p: FakeAdapter(runs))
        return str(path)

    return make


# C, N, C, F, <gap 2 pages>, C
RUNS = [
    LayerRun(BASE, PAGE, C),
    LayerRun(BASE + PAGE, PAGE, N),
    LayerRun(BASE + 2 * PAGE, PAGE, C),
    LayerRun(BASE + 3 * PAGE, PAGE, F),
    LayerRun(BASE + 6 * PAGE, PAGE, C),
]


def _window(path, va_start, length):
    segment = AlignedSegment(window_offset=0, length=length, slab_offset=0,
                             layout_row=0, vas=(va_start,))
    projection = WindowProjection(
        anchor_index=0, start=va_start, length=length, segments=(segment,),
        gaps=(), classes=tuple([0] * length))
    with open_dump_source(path, {}) as source:
        block, _buf, valid = _read_dump_window(
            source, path, projection, 0, length, COORDINATE_ALIGNED, True,
            _vas_run_table(source))
    return block


def test_image_view_is_navigable_in_va(make_view):
    with open_dump_source(make_view(RUNS), {}) as source:
        assert _navigable_view(source) == "va"
        assert _va_view_span_size(source) == 7 * PAGE


def test_image_pane_reports_states_and_invalid_bytes(make_view):
    block = _window(make_view(RUNS), BASE, 7 * PAGE)
    assert block["view"] == "va"
    assert block["page_states"] == [
        [PAGE, PAGE, "NOT_RESIDENT"],
        [3 * PAGE, PAGE, "FAILED"],
        [4 * PAGE, 2 * PAGE, "UNMAPPED"],
    ]
    assert block["bytes_valid"] == [[0, PAGE], [2 * PAGE, PAGE], [6 * PAGE, PAGE]]
    tinted = {i for o, n, _s in block["page_states"] for i in range(o, o + n)}
    valid = {i for o, n in block["bytes_valid"] for i in range(o, o + n)}
    assert not tinted & valid


def test_window_is_relative_to_its_start(make_view):
    block = _window(make_view(RUNS), BASE + PAGE // 2, 3 * PAGE)
    assert block["page_states"][0] == [PAGE // 2, PAGE, "NOT_RESIDENT"]
    assert block["page_states"][1][2] == "FAILED"


def test_msl_and_image_view_mix(tmp_path, make_view):
    msl = tmp_path / "x.msl"
    writer = MslWriter(str(msl), pid=7, imported=False)
    writer.add_process_identity(exe_path="/proc")
    writer.add_memory_region(
        BASE, b"\x42" * PAGE, page_states=[PageState.CAPTURED, PageState.FAILED])
    writer.add_end_of_capture()
    writer.write()
    image = make_view(RUNS)
    seg = _window(str(msl), BASE, 2 * PAGE)
    assert seg["page_states"] == [[PAGE, PAGE, "FAILED"]]
    assert _window(image, BASE, 2 * PAGE)["page_states"] == [[PAGE, PAGE, "NOT_RESIDENT"]]


def test_image_table_is_cached_per_open_source(make_view):
    with open_dump_source(make_view(RUNS), {}) as source:
        assert page_state_runs.image_state_table(source) is \
            page_state_runs.image_state_table(source)


def test_kernel_like_view_without_va_keeps_old_behaviour(make_view):
    huge = 2 ** 60
    runs = [LayerRun(huge, PAGE, C), LayerRun(huge + PAGE, PAGE, F)]
    path = make_view(runs, name="k", kind=ViewKind.KERNEL)
    with open_dump_source(path, {}) as source:
        assert "va" not in source.SUPPORTED_VIEWS
        assert _navigable_view(source) == "raw"
        assert _va_view_span_size(source) is None
        assert not page_state_runs.has_page_states(source, "va")


def test_span_start_is_the_views_va_base(make_view):
    from memdiver.app.tools_consensus import _va_span_start

    with open_dump_source(make_view(RUNS), {}) as source:
        assert _va_span_start(source) == BASE


def test_flat_coordinate_peer_view_matches_consensus_stream(make_view):
    """Flat consensus compares ``read_all()`` ("vas"); the overlay must read the same."""
    from memdiver.app.tools_consensus import COORDINATE_FLAT, _peer_view

    with open_dump_source(make_view(RUNS), {}) as source:
        assert _peer_view(source, COORDINATE_FLAT) == "vas"
        assert source.read_range(0, 16, "vas") == source.read_all()[:16]


# ---------------------------------------------------------------------------
# End to end through POST /api/analysis/consensus/aligned-window
# ---------------------------------------------------------------------------


class FilledAdapter(FakeAdapter):
    def __init__(self, runs, fill):
        super().__init__(runs)
        self._fill = fill

    def read(self, address, length):
        return bytes([self._fill]) * length


@pytest.fixture
def make_filled(tmp_path, monkeypatch):
    (tmp_path / "img.bin").write_bytes(b"\0" * 64)
    table = {}
    monkeypatch.setattr(sources, "_default_adapter_factory",
                        lambda d, p: FilledAdapter(*table[p.name]))

    def make(runs, fill, name, kind=ViewKind.PROCESS):
        extra = dict(pid=7, profile=ProfileRef("p.json")) if kind is ViewKind.PROCESS \
            else dict(profile=ProfileRef("p.json"))
        path = ViewDescriptor("img.bin", SHA, kind, **extra).write(
            tmp_path / f"{name}.mdview")
        table[path.name] = (runs, fill)
        return str(path)

    return make


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app
    return TestClient(create_app())


def _post(client, paths, anchor, length=7 * PAGE, offset=0):
    return client.post("/api/analysis/consensus/aligned-window", json={
        "dump_paths": paths, "anchor": "dump", "anchor_path": anchor,
        "view": "va", "offset": offset, "length": length, "include_bytes": True})


def test_endpoint_two_image_views(client, make_filled):
    a = make_filled(RUNS, 0x11, "a")
    b = make_filled(RUNS, 0x22, "b")
    # The per-request payload cap is shared by the panes, so look at two windows.
    first = _post(client, [a, b], a, length=3 * PAGE, offset=0)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["anchor"]["va_span_start"] == BASE
    anchor, peer = body["dumps"]
    assert anchor["view"] == peer["view"] == "va"
    assert anchor["page_states"] == [[PAGE, PAGE, "NOT_RESIDENT"]]
    # Absent pages are not aligned rows: only captured pages are compared.
    assert anchor["bytes_valid"] == [[0, PAGE], [2 * PAGE, PAGE]]
    second = _post(client, [a, b], a, length=3 * PAGE, offset=3 * PAGE).json()
    assert second["dumps"][0]["page_states"] == [
        [0, PAGE, "FAILED"], [PAGE, 2 * PAGE, "UNMAPPED"]]
    assert second["dumps"][0]["bytes_valid"] == []


def test_endpoint_mixed_msl_and_image_view(client, make_filled, tmp_path):
    msl = tmp_path / "x.msl"
    writer = MslWriter(str(msl), pid=7, imported=False)
    writer.add_process_identity(exe_path="/proc")
    writer.add_memory_region(
        BASE, b"\x42" * 2 * PAGE, page_states=[PageState.CAPTURED, PageState.FAILED,
                                               PageState.CAPTURED])
    writer.add_end_of_capture()
    writer.write()
    image = make_filled(RUNS, 0x11, "m")
    resp = _post(client, [str(msl), image], image, length=3 * PAGE)
    assert resp.status_code == 200, resp.text
    msl_block, image_block = resp.json()["dumps"]
    # The anchor (image view) is tinted through the gap; the .msl peer only
    # where the consensus put it in correspondence, so page 1 stays untinted.
    assert image_block["page_states"] == [[PAGE, PAGE, "NOT_RESIDENT"]]
    assert msl_block["page_states"] == []
    # Page 0 and page 2 are captured in both; page 1 is absent in both.
    assert image_block["bytes_valid"] == [[0, PAGE], [2 * PAGE, PAGE]]


def test_endpoint_imported_msl_beside_its_image_view_aligns_by_va(client, make_filled, tmp_path):
    """Found in the browser: the .msl that ``image extract`` writes is IMPORTED (MSL
    spec: image-derived). Beside its own .mdview the consensus fell back to flat
    file offsets, and every side-by-side aligned-window request answered 400."""
    msl = tmp_path / "extracted.msl"
    writer = MslWriter(str(msl), pid=7, imported=True)
    writer.add_memory_region(
        BASE, b"\x42" * 2 * PAGE, page_states=[PageState.CAPTURED, PageState.FAILED,
                                               PageState.CAPTURED])
    writer.add_end_of_capture()
    writer.write()
    image = make_filled(RUNS, 0x11, "imp")
    built = client.post("/api/analysis/consensus",
                        json={"dump_paths": [image, str(msl)], "normalize": False}).json()
    assert built["alignment"]["method"] == "virtual_address", built
    resp = _post(client, [image, str(msl)], image, length=3 * PAGE)
    assert resp.status_code == 200, resp.text
    assert resp.json()["alignment"]["method"] == "virtual_address"


def test_imported_msl_pair_without_an_image_view_keeps_flat_fallback(tmp_path):
    from memdiver.engine.consensus import _aligns_by_va

    paths = []
    for name in ("a", "b"):
        path = tmp_path / f"{name}.msl"
        writer = MslWriter(str(path), pid=7, imported=True)
        writer.add_memory_region(BASE, b"\x42" * PAGE, page_states=[PageState.CAPTURED])
        writer.add_end_of_capture()
        writer.write()
        paths.append(str(path))
    with open_dump_source(paths[0], {}) as a, open_dump_source(paths[1], {}) as b:
        assert not _aligns_by_va([a, b])


def test_endpoint_kernel_view_keeps_flat_behaviour(client, make_filled):
    huge = 2 ** 60
    runs = [LayerRun(huge, PAGE, C), LayerRun(huge + PAGE, PAGE, F)]
    a = make_filled(runs, 1, "ka", ViewKind.KERNEL)
    b = make_filled(runs, 2, "kb", ViewKind.KERNEL)
    resp = _post(client, [a, b], a)
    assert resp.status_code == 400  # no aligned-VA window without va


# ---------------------------------------------------------------------------
# Real alma-9 process view (gated on MEMDIVER_IMAGE_CORPUS, like
# tests/test_image_views_real.py)
# ---------------------------------------------------------------------------

_ALMA9 = "alma-9_5.14.0-427.el9"
_CORPUS = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")


@pytest.mark.skipif(
    not (_CORPUS and all(Path(_CORPUS, f"{_ALMA9}{e}").is_file()
                         for e in (".lime", ".gt.isf.json"))),
    reason="set MEMDIVER_IMAGE_CORPUS to the pakunoda dumps/acquired dir")
def test_real_alma9_process_view_aligned_window(client, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "home"))
    corpus = Path(_CORPUS)
    profile = ProfileRef(str(corpus / f"{_ALMA9}.gt.isf.json"),
                         sha256="c9" * 32, origin="pakunoda")
    paths = [str(ViewDescriptor(
        str(corpus / f"{_ALMA9}.lime"), "c9" * 32, ViewKind.PROCESS, pid=22176,
        profile=profile).write(tmp_path / f"real{i}.mdview")) for i in (1, 2)]
    resp = _post(client, paths, paths[0], length=4 * PAGE, offset=0)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["anchor"]["va_span_start"] is not None
    anchor, peer = body["dumps"]
    assert anchor["view"] == "va"
    # The same image twice: every captured byte agrees, absent bytes stay absent.
    assert anchor["bytes"] == peer["bytes"]
    assert all(s in ("FAILED", "NOT_RESIDENT", "UNMAPPED")
               for _o, _n, s in anchor["page_states"])


def test_flat_overlay_bytes_equal_the_bytes_the_consensus_compared(make_view):
    """The overlay of a flat build reads what ``read_all()`` (the consensus input) yields,
    not the image FILE (zeros here, the adapter serves 0x41)."""
    from memdiver.app.tools_consensus import COORDINATE_FLAT

    path = make_view(RUNS)
    length = 2 * PAGE
    segment = AlignedSegment(window_offset=0, length=length, slab_offset=0,
                             layout_row=-1, vas=())
    projection = WindowProjection(anchor_index=0, start=0, length=length,
                                  segments=(segment,), gaps=(),
                                  classes=tuple([0] * length))
    with open_dump_source(path, {}) as source:
        compared = source.read_all()[:length]
        _block, data, _valid = _read_dump_window(
            source, path, projection, 0, length, COORDINATE_FLAT, True, None)
    assert compared and compared != b"\0" * length
    assert data == compared


def test_physical_view_never_aligns_by_virtual_address(make_view):
    """A physical view's "va" coordinate is a physical address: pairing it with a
    process view must not take the VA path (review finding: physical page 0x10000
    was compared with process page 0x10000)."""
    from memdiver.engine.consensus import _aligns_by_va
    phys = sources.Vol3LayerSource(Path(make_view(RUNS, "phys", ViewKind.PHYSICAL)))
    proc = sources.Vol3LayerSource(Path(make_view(RUNS, "proc")))
    for source in (phys, proc):
        source.open()
    assert proc.supports_va_alignment is True
    assert phys.supports_va_alignment is False
    assert _aligns_by_va([phys, proc]) is False
