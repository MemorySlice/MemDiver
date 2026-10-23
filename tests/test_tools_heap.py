"""Tests for app/tools_heap.py: the six heap.* ServiceResult producers."""
from __future__ import annotations

import json
import os

import pytest

from memdiver.app import tools_heap as th
from memdiver.app.session import ToolSession
from memdiver.core.service_errors import (CapabilityError,
                                          FileNotFoundServiceError,
                                          OffsetOutOfRangeError,
                                          UnsupportedFormatError)
from memdiver.core.service_result import Resolution, ServiceResult
from memdiver.heap.analyze import clear_heap_cache
from memdiver.heap.model import ChunkState, HeapRole
from tests.fixtures import synth_heap as sh


@pytest.fixture(autouse=True)
def _fresh_cache():
    clear_heap_cache()
    yield
    clear_heap_cache()


@pytest.fixture
def session():
    return ToolSession()


@pytest.fixture
def glibc(tmp_path):
    heap = sh.glibc_heap()
    return str(sh.as_regioned_raw(tmp_path, [heap])), heap


def _payload(result: ServiceResult) -> dict:
    assert isinstance(result, ServiceResult)
    assert result.status.resolution is Resolution.OK
    json.dumps(result.payload)  # every payload is JSON-safe
    return result.payload


# -- heap.detect ------------------------------------------------------------------


def test_detect_ranks_candidates(session, glibc):
    payload = _payload(th.heap_detect_result(session, glibc[0]))
    assert payload["best"] == "ptmalloc2"
    assert payload["hinted"] is False
    assert payload["format"]
    assert payload["platform"]["pointer_size"] == 8
    kinds = [c["kind"] for c in payload["candidates"]]
    assert kinds[0] == "ptmalloc2" and "generic" in kinds
    assert payload["candidates"][0]["evidence"]


def test_detect_honours_hint(session, glibc):
    payload = _payload(th.heap_detect_result(session, glibc[0], "jemalloc"))
    assert payload["best"] == "jemalloc" and payload["hinted"] is True


# -- heap.summary -----------------------------------------------------------------


def test_summary_shape(session, glibc):
    path, heap = glibc
    payload = _payload(th.heap_summary_result(session, path))
    assert payload["allocator"] == "ptmalloc2"
    assert payload["version_hint"] == "glibc>=2.32"
    assert payload["partial"] is False and payload["heuristic"] is False
    assert payload["levels"] == ["L0", "L1", "L2", "L3"]
    assert payload["regions"][0]["name"] == "[heap]"
    assert payload["chunk_count"] == len(heap.chunks)
    assert sum(payload["counts_by_state"].values()) == len(heap.chunks)
    assert sum(payload["bytes_by_state"].values()) == sum(c.size for c in heap.chunks)
    assert sum(b["count"] for b in payload["size_histogram"]) == len(heap.chunks)
    assert payload["metadata_bytes"] == (payload["role_bytes"]["chunk_header"]
                                         + payload["role_bytes"]["allocator_meta"])
    assert payload["free_list_count"] == 2
    assert payload["coverage"]["analysis"]["chosen"] == "ptmalloc2"
    assert payload["evidence"]
    assert isinstance(payload["diagnostics"], list)


def test_summary_histogram_buckets_are_powers_of_two(session, glibc):
    histogram = _payload(th.heap_summary_result(session, glibc[0]))["size_histogram"]
    for bucket in histogram:
        assert bucket["min_size"] & (bucket["min_size"] - 1) == 0
        assert bucket["max_size"] == 2 * bucket["min_size"] - 1
    mins = [b["min_size"] for b in histogram]
    assert mins == sorted(mins)


def test_summary_flags_heuristic_fallback(session, glibc):
    payload = _payload(th.heap_summary_result(session, glibc[0], "scudo"))
    assert payload["allocator"] == "generic"
    assert payload["heuristic"] is True
    assert "fell back from scudo to generic" in payload["diagnostics"]


def test_summary_partial_allocator(session, tmp_path):
    path = str(sh.as_regioned_raw(tmp_path, [sh.jemalloc_slab()]))
    payload = _payload(th.heap_summary_result(session, path))
    assert payload["allocator"] == "jemalloc" and payload["partial"] is True


def test_summary_of_random_region_is_empty_not_an_error(session, tmp_path):
    path = str(sh.as_regioned_raw(tmp_path, [sh.random_region()]))
    payload = _payload(th.heap_summary_result(session, path))
    assert payload["chunk_count"] == 0
    assert payload["role_bytes"] == {} and payload["size_histogram"] == []


# -- heap.chunks ------------------------------------------------------------------


_ROW_KEYS = {"va", "size", "state", "header_len", "user_va", "user_len", "bin",
             "flags", "confidence", "extra", "view_offset"}


def test_chunks_rows_and_view_offsets(session, glibc):
    path, heap = glibc
    payload = _payload(th.heap_chunks_result(session, path))
    assert payload["total"] == len(heap.chunks) == len(payload["chunks"])
    for row in payload["chunks"]:
        assert _ROW_KEYS <= set(row)
        # regioned raw has one region: the vas offset is va - base.
        assert row["view_offset"] == row["va"] - heap.base_va
    raw = _payload(th.heap_chunks_result(session, path, view="raw"))
    assert [r["view_offset"] for r in raw["chunks"]] == \
        [r["view_offset"] for r in payload["chunks"]]


def test_chunks_paging(session, glibc):
    path, heap = glibc
    pages = [_payload(th.heap_chunks_result(session, path, page=p, page_size=3))
             for p in range(3)]
    assert pages[0]["pages"] == 3 and pages[0]["page_size"] == 3
    vas = [r["va"] for page in pages for r in page["chunks"]]
    assert vas == sorted(c.va for c in heap.chunks)
    beyond = _payload(th.heap_chunks_result(session, path, page=9, page_size=3))
    assert beyond["chunks"] == [] and beyond["total"] == len(heap.chunks)


def test_chunks_state_and_size_filters(session, glibc):
    path, heap = glibc
    cached = _payload(th.heap_chunks_result(session, path, state="CACHED"))
    assert cached["total"] == 3
    assert {r["state"] for r in cached["chunks"]} == {"cached"}
    sized = _payload(th.heap_chunks_result(session, path, min_size=48, max_size=80))
    assert sized["chunks"] and all(48 <= r["size"] <= 80 for r in sized["chunks"])
    assert sized["filters"]["min_size"] == 48


def test_chunks_va_and_offset_windows_agree(session, glibc):
    path, heap = glibc
    lo, hi = heap.base_va + 0x290, heap.base_va + 0x300
    by_va = _payload(th.heap_chunks_result(session, path, va_start=lo, va_end=hi))
    by_offset = _payload(th.heap_chunks_result(session, path, offset=0x290,
                                               length=0x70))
    assert by_va["chunks"] and by_va["chunks"] == by_offset["chunks"]
    for row in by_va["chunks"]:
        assert row["va"] < hi and row["va"] + row["size"] > lo


@pytest.mark.parametrize("kwargs", [
    {"state": "zombie"},
    {"view": "file"},
    {"allocator": "tcmalloc"},
    {"page": -1},
    {"page_size": 0},
    {"page_size": th.MAX_CHUNK_PAGE_SIZE + 1},
    {"va_start": 0x10, "offset": 0, "length": 8},
    {"offset": 0},
    {"offset": 0, "length": 0},
    {"va_start": 0x20, "va_end": 0x10},
])
def test_chunks_bad_input_is_capability_error(session, glibc, kwargs):
    with pytest.raises(CapabilityError):
        th.heap_chunks_result(session, glibc[0], **kwargs)


def test_chunks_unsupported_view_for_source(session, glibc):
    with pytest.raises(UnsupportedFormatError):
        th.heap_chunks_result(session, glibc[0], view="va")


def test_missing_file_is_not_found(session, tmp_path):
    missing = str(tmp_path / "nope.bin")
    for producer in (th.heap_detect_result, th.heap_summary_result,
                     th.heap_chunks_result, th.heap_free_lists_result,
                     th.heap_roles_result):
        with pytest.raises(FileNotFoundServiceError):
            producer(session, missing)


# -- heap.chunk_at ----------------------------------------------------------------


def _user_chunk(heap):
    return next(c for c in heap.chunks if c.state.value == "in_use"
                and c.header_len and c is not heap.chunks[0])


def test_chunk_at_user_byte(session, glibc):
    path, heap = glibc
    chunk = _user_chunk(heap)
    va = chunk.va + chunk.header_len + 1
    payload = _payload(th.heap_chunk_at_result(session, path, va=va))
    assert payload["found"] is True
    assert payload["chunk"]["va"] == chunk.va
    assert payload["role"] == "user_data"
    assert payload["offset_in_chunk"] == chunk.header_len + 1
    assert payload["offset_in_user"] == 1
    assert payload["prev"]["va"] < chunk.va < payload["next"]["va"]
    assert payload["prev"]["va"] + payload["prev"]["size"] == chunk.va


def test_chunk_at_header_byte(session, glibc):
    path, heap = glibc
    chunk = _user_chunk(heap)
    payload = _payload(th.heap_chunk_at_result(session, path, va=chunk.va))
    assert payload["role"] == "chunk_header"
    assert payload["offset_in_user"] is None


def test_chunk_at_tcache_link_and_meta(session, glibc):
    path, heap = glibc
    cached = next(c for c in heap.chunks if c.state.value == "cached")
    link = _payload(th.heap_chunk_at_result(
        session, path, va=cached.va + cached.header_len))
    assert link["role"] == "free_link"
    meta = _payload(th.heap_chunk_at_result(session, path, va=heap.base_va + 0x20))
    assert meta["role"] == "allocator_meta"
    assert meta["prev"] is None


def test_chunk_at_offset_matches_va(session, glibc):
    path, heap = glibc
    chunk = _user_chunk(heap)
    by_offset = _payload(th.heap_chunk_at_result(
        session, path, offset=chunk.va - heap.base_va + 4))
    by_va = _payload(th.heap_chunk_at_result(session, path, va=chunk.va + 4))
    assert by_offset == by_va
    assert by_offset["view_offset"] == chunk.va - heap.base_va + 4


def test_chunk_at_outside_every_chunk(session, glibc):
    path, heap = glibc
    payload = _payload(th.heap_chunk_at_result(session, path, va=heap.base_va - 8))
    assert payload["found"] is False and payload["chunk"] is None
    assert payload["role"] == "none"
    assert payload["prev"] is None
    assert payload["next"]["va"] == heap.chunks[0].va


@pytest.mark.parametrize("kwargs", [{}, {"va": 1, "offset": 1},
                                    {"va": 1, "view": "bogus"}])
def test_chunk_at_bad_input(session, glibc, kwargs):
    with pytest.raises(CapabilityError):
        th.heap_chunk_at_result(session, glibc[0], **kwargs)


def test_chunk_at_unmappable_offset(session, glibc):
    with pytest.raises(OffsetOutOfRangeError):
        th.heap_chunk_at_result(session, glibc[0], offset=10 * sh.PAGE)


# -- heap.free_lists --------------------------------------------------------------


def test_free_lists(session, glibc):
    path, heap = glibc
    payload = _payload(th.heap_free_lists_result(session, path))
    assert payload["allocator"] == "ptmalloc2"
    assert payload["kinds"] == ["tcache"]
    assert payload["list_count"] == 2
    assert payload["cycle_count"] == 0 and payload["corrupt_count"] == 0
    starts = {c.va for c in heap.chunks}
    for row in payload["lists"]:
        assert row["length"] == len(row["chunk_vas"])
        assert set(row["chunk_vas"]) <= starts
        assert row["decoded"] is True and row["unresolved_vas"] == []


def test_free_lists_kind_filter(session, glibc):
    payload = _payload(th.heap_free_lists_result(session, glibc[0], kind="fastbin"))
    assert payload["lists"] == [] and payload["kinds"] == ["tcache"]


def test_free_list_row_flags_unresolved_entries():
    from memdiver.heap.model import (AllocatorKind, ChunkState, FreeList,
                                     HeapChunk, HeapLayout)

    chunk = HeapChunk(0x1000, 0x20, ChunkState.CACHED, 0x10, 0x1010, 0x10)
    layout = HeapLayout(AllocatorKind.PTMALLOC2, chunks=(chunk,))
    row = th._free_list_row(layout, FreeList("tcache", 0, 0x500,
                                             (0x1000, 0x1008), cycle=True))
    assert row["corrupt"] is True and row["cycle"] is True
    assert row["unresolved_vas"] == [0x1008]


# -- .msl sources -----------------------------------------------------------------


def _write_msl(path, heap, *, encryption=None):
    from memdiver.msl.writer import MslWriter

    writer = MslWriter(str(path), pid=7, encryption=encryption)
    writer.add_memory_region(heap.base_va, heap.data)
    writer.add_end_of_capture()
    writer.write()
    return str(path)


def test_msl_dump_chunks_in_va_view(session, tmp_path):
    heap = sh.glibc_heap()
    path = _write_msl(tmp_path / "heap.msl", heap)
    payload = _payload(th.heap_chunks_result(session, path, view="va"))
    assert payload["total"] > 0
    first = payload["chunks"][0]
    assert first["view_offset"] == first["va"] - heap.base_va


def test_encrypted_msl_without_key_reports_locked(session, tmp_path):
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo
    from memdiver.msl.writer import MslEncryptionConfig

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    path = _write_msl(tmp_path / "enc.msl", sh.glibc_heap(),
                      encryption=MslEncryptionConfig(raw_key=key))

    locked = th.heap_summary_result(session, path)
    assert locked.status.resolution is Resolution.UNRESOLVED
    assert locked.status.key.decrypted is False
    assert locked.payload["chunk_count"] == 0

    keyed = th.heap_summary_result(session, path, key_file=str(keyfile))
    assert keyed.status.resolution is Resolution.OK
    assert keyed.payload["chunk_count"] > 0


# -- heap.roles -------------------------------------------------------------------

_ROLE_NAMES = {"chunk_header", "user_data", "free_link", "free_data",
               "allocator_meta", "top", "slack"}


def _assert_runs_well_formed(payload: dict) -> None:
    lo, hi = payload["offset"], payload["offset"] + payload["length"]
    runs = payload["runs"]
    for run in runs:
        assert run["role"] in _ROLE_NAMES
        assert run["length"] > 0
        assert lo <= run["offset"] and run["offset"] + run["length"] <= hi
    for prev, cur in zip(runs, runs[1:]):
        assert prev["offset"] + prev["length"] <= cur["offset"]
        touching = prev["offset"] + prev["length"] == cur["offset"]
        assert not (touching and prev["role"] == cur["role"])  # coalesced


def test_roles_shape_and_whole_heap_tiling(session, glibc):
    path, heap = glibc
    payload = _payload(th.heap_roles_result(session, path, length=sh.PAGE))
    assert set(payload) == {"allocator", "view", "offset", "length", "runs",
                            "chunk_starts", "partial", "heuristic"}
    assert (payload["allocator"], payload["view"]) == ("ptmalloc2", "vas")
    assert payload["partial"] is False and payload["heuristic"] is False
    _assert_runs_well_formed(payload)
    # the fixture's chunks tile the whole page, so roles cover every byte
    assert sum(r["length"] for r in payload["runs"]) == sh.PAGE
    assert payload["chunk_starts"] == [c.va - heap.base_va for c in heap.chunks]
    assert payload["runs"][0] == {"offset": 0, "length": heap.chunks[0].size,
                                  "role": "allocator_meta"}
    assert payload["runs"][-1]["role"] == "top"


def test_roles_agree_with_chunk_at(session, glibc):
    path, heap = glibc
    payload = _payload(th.heap_roles_result(session, path, length=sh.PAGE))
    for run in payload["runs"][:12]:
        for probe in (run["offset"], run["offset"] + run["length"] - 1):
            at = _payload(th.heap_chunk_at_result(session, path, offset=probe))
            assert at["role"] == run["role"]


def test_roles_window_is_clipped(session, glibc):
    path, heap = glibc
    cached = heap.chunks[2]  # first tcache'd chunk after one in-use chunk
    start = cached.va - heap.base_va + 4  # mid-header
    payload = _payload(th.heap_roles_result(session, path, offset=start,
                                            length=0x20))
    _assert_runs_well_formed(payload)
    assert payload["runs"][0]["offset"] == start
    assert payload["runs"][0]["role"] == "chunk_header"
    assert payload["chunk_starts"] == []
    assert sum(r["length"] for r in payload["runs"]) == 0x20


def test_roles_window_past_end_is_empty(session, glibc):
    payload = _payload(th.heap_roles_result(session, glibc[0],
                                            offset=10 * sh.PAGE, length=64))
    assert payload["runs"] == [] and payload["chunk_starts"] == []


def test_roles_split_across_non_contiguous_runs(session, tmp_path):
    """A vas window spanning a zero module and the heap: the two VA runs are
    far apart, yet each heap run lands at its own vas offset."""
    heap = sh.glibc_heap()
    module = (heap.base_va - 0x10_0000, sh.PAGE, "/usr/lib/libfoo.so")
    path = str(sh.as_regioned_raw(tmp_path, [heap], modules=[module],
                                  stem="split"))
    payload = _payload(th.heap_roles_result(session, path, allocator="ptmalloc2",
                                            offset=sh.PAGE - 0x10, length=0x40))
    _assert_runs_well_formed(payload)
    assert payload["chunk_starts"] == [sh.PAGE]
    assert payload["runs"] == [{"offset": sh.PAGE, "length": 0x30,
                                "role": "allocator_meta"}]


def test_view_role_runs_translate_each_segment():
    from memdiver.heap.model import AllocatorKind, HeapChunk, HeapLayout

    chunks = [HeapChunk(va, 0x20, ChunkState.IN_USE, 0x10, va + 0x10, 0x10)
              for va in (0x1000, 0x2000)]
    layout = HeapLayout(AllocatorKind.GENERIC, chunks=tuple(chunks))
    # view order reversed w.r.t. VA order, and adjacent in view offsets
    segments = [(0, 0x2000, 0x20), (0x20, 0x1000, 0x20)]
    runs = th._view_role_runs(layout, segments)
    assert runs == [
        {"offset": 0x00, "length": 0x10, "role": "chunk_header"},
        {"offset": 0x10, "length": 0x10, "role": "user_data"},
        {"offset": 0x20, "length": 0x10, "role": "chunk_header"},
        {"offset": 0x30, "length": 0x10, "role": "user_data"},
    ]
    assert th._view_chunk_starts(layout, segments) == [0, 0x20]


def test_coalesced_merges_same_role_across_segments():
    runs = [(0, 0x10, HeapRole.USER_DATA), (0x10, 0x10, HeapRole.USER_DATA),
            (0x18, 0x10, HeapRole.SLACK)]
    assert th._coalesced(runs) == [(0, 0x20, HeapRole.USER_DATA),
                                   (0x20, 0x8, HeapRole.SLACK)]


def test_roles_in_msl_va_view(session, tmp_path):
    heap = sh.glibc_heap()
    path = _write_msl(tmp_path / "roles.msl", heap)
    payload = _payload(th.heap_roles_result(session, path, view="va",
                                            length=sh.PAGE))
    assert payload["chunk_starts"] == [c.va - heap.base_va for c in heap.chunks]


@pytest.mark.parametrize("kwargs", [
    {"length": 0}, {"offset": -1}, {"length": th.MAX_ROLES_LENGTH + 1},
    {"view": "nonsense"}, {"allocator": "nonsense"},
])
def test_roles_bad_input_is_capability_error(session, glibc, kwargs):
    with pytest.raises(CapabilityError):
        th.heap_roles_result(session, glibc[0], **kwargs)


def test_roles_accepts_max_length(session, glibc):
    payload = _payload(th.heap_roles_result(session, glibc[0],
                                            length=th.MAX_ROLES_LENGTH))
    assert payload["length"] == th.MAX_ROLES_LENGTH
