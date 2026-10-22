"""Tests for the analysis-time region view filter (core/region_view_filter.py).

Two native ``.msl`` dumps with an ASLR shift share an image module, a writable
image page, heap-category anonymous/heap regions, a stack and a read-only
mapped file. Dump A additionally carries a READ-ONLY anonymous page (heap
category, but not writable) placed before its writable twin: without a
filter it shifts dump A's ``anon:ANONYMOUS:0x1000:<n>`` ordinals, with a
``writable_only`` heap filter it is dropped before ordinals are assigned.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from memdiver.core.dump_source import MslDumpSource, RawDumpSource, open_dump
from memdiver.core.region_align import align_dumps, build_dump_region_map
from memdiver.core.region_view_filter import (
    coerce_region_filter,
    region_filter_mask,
    region_filter_note,
    stored_region_infos,
)
from memdiver.engine.consensus_msl import (
    build_msl_consensus_result,
    build_msl_incremental,
)
from memdiver.engine.consensus_service import build_consensus
from memdiver.engine.session_store import SessionSnapshot, SessionStore
from memdiver.msl.enums import Protection, RegionType
from memdiver.msl.region_select import RegionCategory as C
from memdiver.msl.region_select import RegionSelection, parse_selection
from memdiver.msl.writer import ModuleEntrySpec, MslWriter

PAGE = 4096
R, W, X = int(Protection.READ), int(Protection.WRITE), int(Protection.EXECUTE)
HEAP_RW = RegionSelection(frozenset({C.HEAP}), writable_only=True)


def _write_dump(path: Path, shift: int, fill: int, extra_ro_anon: bool) -> Path:
    mod_base = 0x400000 + shift
    writer = MslWriter(str(path), pid=7, imported=False)
    writer.add_process_identity(exe_path="/usr/bin/demo")
    writer.add_module_list_index(
        [ModuleEntrySpec(mod_base, 0x4000, "/usr/lib/libfoo.so")])
    writer.add_memory_region(mod_base, bytes([fill]) * PAGE,
                             protection=R | X, region_type=int(RegionType.IMAGE))
    writer.add_memory_region(mod_base + 0x1000, bytes([fill + 1]) * PAGE,
                             protection=R | W, region_type=int(RegionType.IMAGE))
    if extra_ro_anon:
        writer.add_memory_region(0x10000000 + shift, b"\xEE" * PAGE,
                                 protection=R,
                                 region_type=int(RegionType.ANONYMOUS))
    writer.add_memory_region(0x20000000 + shift, bytes([fill + 2]) * PAGE,
                             protection=R | W,
                             region_type=int(RegionType.ANONYMOUS))
    writer.add_memory_region(0x30000000 + shift, bytes([fill + 3]) * 2 * PAGE,
                             protection=R | W, region_type=int(RegionType.HEAP))
    writer.add_memory_region(0x7FFF0000 + shift, bytes([fill + 4]) * PAGE,
                             protection=R | W, region_type=int(RegionType.STACK))
    writer.add_memory_region(0x50000000 + shift, bytes([fill + 5]) * PAGE,
                             protection=R,
                             region_type=int(RegionType.MAPPED_FILE))
    writer.add_end_of_capture()
    writer.write()
    return path


@pytest.fixture
def pair(tmp_path):
    a = _write_dump(tmp_path / "a.msl", 0, 0x10, extra_ro_anon=True)
    b = _write_dump(tmp_path / "b.msl", 0x100000, 0x40, extra_ro_anon=False)
    return a, b


def _open(path, region_filter=None):
    src = open_dump(path, region_filter=region_filter)
    src.open()
    return src


# -- parsing / normalisation --------------------------------------------------


def test_coerce_accepts_spec_note_and_none():
    assert coerce_region_filter(None) is None
    assert coerce_region_filter("  ") is None
    assert coerce_region_filter("heap,stack").categories == {C.HEAP, C.STACK}
    note = HEAP_RW.to_note()
    assert coerce_region_filter(note) == HEAP_RW
    assert region_filter_note("stack,heap") == "regions=heap,stack"
    assert region_filter_note("all") is None
    with pytest.raises(ValueError):
        coerce_region_filter("bogus")


# -- classification -----------------------------------------------------------


def test_stored_region_infos_classify_every_region(pair):
    with MslDumpSource(pair[0]) as src:
        infos = stored_region_infos(src.get_reader())
    cats = sorted(i.category.value for i in infos)
    assert cats == sorted(["image_code", "image_data", "heap", "heap", "heap",
                           "stack", "mapped_file"])
    image = [i for i in infos if i.category is C.IMAGE_CODE]
    assert image[0].module_path == "/usr/lib/libfoo.so"


# -- region map / alignment ---------------------------------------------------


def test_heap_filter_keeps_only_heap_keys(pair):
    sel = parse_selection("heap")
    with MslDumpSource(pair[1]) as src:
        rmap = build_dump_region_map(0, src.get_reader(), region_filter=sel)
    assert set(rmap.regions) == {"anon:ANONYMOUS:0x1000:0", "anon:HEAP:0x2000:0"}
    assert all(r.info.category is C.HEAP for r in rmap.regions.values())


def test_unfiltered_map_is_unchanged(pair):
    with MslDumpSource(pair[1]) as src:
        plain = build_dump_region_map(0, src.get_reader())
        allsel = build_dump_region_map(
            0, src.get_reader(), region_filter=RegionSelection.all())
    assert set(plain.regions) == set(allsel.regions)
    assert len(plain.regions) == 6
    assert all(r.info is None for r in plain.regions.values())


def test_excluded_regions_do_not_shift_ordinals(pair):
    a, b = pair
    with MslDumpSource(a) as sa, MslDumpSource(b) as sb:
        # Unfiltered: dump A's read-only anon page takes ordinal 0, so its
        # writable page is :1 and :0 pairs the wrong regions across dumps.
        plain_a = build_dump_region_map(0, sa.get_reader())
        assert plain_a.regions["anon:ANONYMOUS:0x1000:0"].source_base_addr \
            == 0x10000000
        maps = [build_dump_region_map(i, s.get_reader(), region_filter=HEAP_RW)
                for i, s in enumerate((sa, sb))]
    assert set(maps[0].regions) == set(maps[1].regions) == {
        "anon:ANONYMOUS:0x1000:0", "anon:HEAP:0x2000:0"}
    slices = align_dumps(maps)
    assert [s.key for s in slices] == [
        "anon:ANONYMOUS:0x1000:0", "anon:HEAP:0x2000:0", "anon:HEAP:0x2000:0"]
    anon = slices[0]
    assert anon.source_vaddrs == [0x20000000, 0x20100000]
    assert anon.data == [b"\x12" * PAGE, b"\x42" * PAGE]


def test_align_dumps_filter_narrows_prebuilt_maps(pair):
    a, b = pair
    with MslDumpSource(a) as sa, MslDumpSource(b) as sb:
        maps = [build_dump_region_map(i, s.get_reader(),
                                      region_filter=parse_selection("heap,stack"))
                for i, s in enumerate((sa, sb))]
    keys = {s.key for s in align_dumps(maps, region_filter=parse_selection("stack"))}
    assert keys == {"anon:STACK:0x1000:0"}


def test_msl_consensus_with_filter_and_incremental_parity(pair):
    a, b = pair
    with MslDumpSource(a) as sa, MslDumpSource(b) as sb:
        result = build_msl_consensus_result([sa, sb], region_filter=HEAP_RW)
        builder = build_msl_incremental([sa, sb], region_filter=HEAP_RW)
        for i in range(2):
            builder.fold_next(i)
    assert result.total_bytes == 3 * PAGE
    assert builder.total_bytes == 3 * PAGE
    assert builder.get_reference() == result.reference_bytes


def test_consensus_honours_filter_set_on_sources(pair):
    """open_dump(region_filter=...) alone is enough for the aligned path."""
    srcs = [_open(p, HEAP_RW) for p in pair]
    try:
        result = build_msl_consensus_result(srcs)
    finally:
        for s in srcs:
            s.close()
    assert result.total_bytes == 3 * PAGE


def test_build_consensus_service_forwards_filter(pair):
    full = build_consensus([str(p) for p in pair])
    heap = build_consensus([str(p) for p in pair], region_filter="heap")
    assert heap.size < full.size
    assert heap.size == 3 * PAGE  # anon :0 + 2 heap pages


# -- MslDumpSource ------------------------------------------------------------


def test_read_all_is_concatenation_of_included_runs(pair):
    with MslDumpSource(pair[0]) as unfiltered:
        infos = stored_region_infos(unfiltered.get_reader())
        full = unfiltered.read_all()
    included = sum(i.captured_bytes for i in infos if HEAP_RW.includes(i))
    src = _open(pair[0], HEAP_RW)
    try:
        data = src.read_all()
        assert len(data) == included == src.size_for("vas") == 3 * PAGE
        assert data == b"\x12" * PAGE + b"\x13" * 2 * PAGE
        assert len(full) > len(data)
        # iter_ranges / read_range / find agree with read_all.
        assert b"".join(c for _, _, c in src.iter_ranges()) == data
        assert src.read_range(PAGE, PAGE) == b"\x13" * PAGE
        assert src.find_all(b"\x10\x10\x10\x10") == []  # image page excluded
        assert src.find_first(b"\x13") == PAGE
        assert src.va_to_vas_offset(0x30000000) == PAGE
        assert src.va_to_vas_offset(0x10000000) is None
        assert [r.base_addr for r in src.included_regions()] == \
            [0x20000000, 0x30000000]
        assert src.metadata()["region_filter"] == HEAP_RW.to_note()
        # "va" view: span unchanged, excluded region reads as filler.
        assert src.read_range_valid(0, 16, view="va")[1] == []
    finally:
        src.close()


def test_set_region_filter_clears_and_all_means_none(pair):
    src = _open(pair[0], "heap")
    try:
        heap_len = len(src.read_all())
        src.set_region_filter(None)
        assert src.region_filter is None
        assert len(src.read_all()) > heap_len
        src.set_region_filter("all")
        assert src.region_filter is None
    finally:
        src.close()


def test_raw_sources_ignore_the_filter(tmp_path):
    raw = tmp_path / "x.dump"
    raw.write_bytes(b"\xAB" * 100)
    with open_dump(raw, region_filter="heap") as src:
        assert isinstance(src, RawDumpSource)
        assert len(src.read_all()) == 100


def test_raw_imported_msl_is_unclassified(tmp_path):
    from memdiver.msl.importer import import_dump

    raw = tmp_path / "x.dump"
    raw.write_bytes(b"\xAB" * PAGE)
    out = tmp_path / "x.msl"
    import_dump(raw, out)
    with MslDumpSource(out) as src:
        mask = region_filter_mask(src.get_reader(), parse_selection("heap"))
    assert mask == [False]
    with open_dump(out, region_filter="unclassified") as src:
        assert len(src.read_all()) == PAGE


def test_open_dump_rejects_unknown_category(pair):
    with pytest.raises(ValueError):
        open_dump(pair[0], region_filter="nope")


# -- session persistence ------------------------------------------------------


def test_session_roundtrip_with_and_without_field(tmp_path):
    with_filter = SessionStore.save(
        SessionSnapshot(session_name="f", region_filter="regions=heap"),
        tmp_path / "f")
    assert SessionStore.load(with_filter).region_filter == "regions=heap"
    without = SessionStore.save(SessionSnapshot(session_name="n"), tmp_path / "n")
    assert SessionStore.load(without).region_filter is None
    # A session file written before the field existed.
    legacy = tmp_path / "legacy.memdiver"
    legacy.write_bytes(gzip.compress(json.dumps(
        {"_memdiver_session": True, "schema_version": 2,
         "session_name": "legacy"}).encode()))
    assert SessionStore.load(legacy).region_filter is None


def test_session_service_normalises_filter():
    from memdiver.api.services.session_service import payload_to_snapshot

    assert payload_to_snapshot({"region_filter": "stack,heap"}).region_filter \
        == "regions=heap,stack"
    assert payload_to_snapshot({}).region_filter is None
    with pytest.raises(ValueError):
        payload_to_snapshot({"region_filter": "bogus"})


def test_tool_session_region_filter():
    from memdiver.app.session import ToolSession

    session = ToolSession()
    assert session.set_region_filter("heap") == "regions=heap"
    session.clear()
    assert session.region_filter is None


# -- REST ---------------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app

    for sub, env in [("oracles", "MEMDIVER_ORACLE_DIR"),
                     ("tasks", "MEMDIVER_TASK_ROOT"),
                     ("uploads", "MEMDIVER_UPLOAD_DIR"),
                     ("sessions", "MEMDIVER_SESSION_DIR")]:
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(env, str(tmp_path / sub))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c
    get_settings.cache_clear()


def test_rest_session_region_filter_roundtrip(client):
    resp = client.post("/api/sessions/",
                       json={"session_name": "rf", "region_filter": "heap,stack"})
    assert resp.status_code == 200, resp.text
    loaded = client.get("/api/sessions/rf").json()
    assert loaded["region_filter"] == "regions=heap,stack"

    resp = client.post("/api/sessions/",
                       json={"session_name": "none", "region_filter": None})
    assert resp.status_code == 200
    assert client.get("/api/sessions/none").json()["region_filter"] is None


def test_rest_session_rejects_unknown_category(client):
    resp = client.post("/api/sessions/",
                       json={"session_name": "bad", "region_filter": "heapz"})
    assert resp.status_code == 422


def test_rest_consensus_accepts_region_filter(client, pair):
    paths = [str(p) for p in pair]
    resp = client.post("/api/analysis/consensus",
                       json={"dump_paths": paths, "region_filter": "heap"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["region_filter"] == "regions=heap"
    bad = client.post("/api/analysis/consensus",
                      json={"dump_paths": paths, "region_filter": "x"})
    assert bad.status_code == 422


def test_pipeline_request_validates_region_filter():
    from pydantic import ValidationError

    from memdiver.api.routers.pipeline import PipelineRunRequest

    req = PipelineRunRequest(source_paths=["a.msl"], region_filter="heap")
    assert req.region_filter == "regions=heap"
    assert PipelineRunRequest(source_paths=["a.msl"]).region_filter is None
    with pytest.raises(ValidationError):
        PipelineRunRequest(source_paths=["a.msl"], region_filter="nope")


def test_tools_pipeline_consensus_echoes_filter(pair, tmp_path):
    from memdiver.app.tools_pipeline import consensus

    meta = consensus(dump_paths=[str(p) for p in pair],
                     output_dir=str(tmp_path / "out"), region_filter="heap")
    assert meta["region_filter"] == "regions=heap"
    assert meta["size"] == 3 * PAGE
    inc = consensus(dump_paths=[str(p) for p in pair],
                    output_dir=str(tmp_path / "inc"), region_filter="heap",
                    persist_welford=True)
    assert inc["region_filter"] == "regions=heap"
    assert inc["total_bytes"] == 3 * PAGE
