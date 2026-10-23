"""HTTP tests for the /api/heap router (web face of the heap.* producers).

Fixtures are the hand-built glibc ``[heap]`` from ``tests/fixtures/synth_heap``
written as a regioned raw dump next to a libc mapping, so detection has both
the arena bytes and the module hint to go on.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.heap.analyze import clear_heap_cache
from memdiver.heap.model import ChunkState
from tests.fixtures import synth_heap as sh

LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
LIBC_VA = 0x7F00_0000_0000


@pytest.fixture(autouse=True)
def _fresh_cache():
    clear_heap_cache()
    yield
    clear_heap_cache()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


@pytest.fixture
def glibc(tmp_path):
    heap = sh.glibc_heap()
    path = sh.as_regioned_raw(tmp_path, [heap],
                              modules=[(LIBC_VA, sh.PAGE, LIBC)])
    return str(path), heap


def _get(client, route, **params):
    resp = client.get(f"/api/heap/{route}", params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


# -- /detect ----------------------------------------------------------------------


def test_detect_ranks_ptmalloc2_first(client, glibc):
    data = _get(client, "detect", dump_path=glibc[0])
    assert data["best"] == "ptmalloc2"
    assert data["hinted"] is False
    assert data["format"]
    assert data["candidates"][0]["kind"] == "ptmalloc2"
    assert "status" not in data


def test_detect_echoes_hint(client, glibc):
    data = _get(client, "detect", dump_path=glibc[0], allocator="jemalloc")
    assert data["best"] == "jemalloc"
    assert data["hinted"] is True


# -- /summary ---------------------------------------------------------------------


def test_summary_counts_match_fixture(client, glibc):
    path, heap = glibc
    data = _get(client, "summary", dump_path=path)
    assert data["allocator"] == "ptmalloc2"
    assert data["chunk_count"] == len(heap.chunks)
    cached = sum(1 for c in heap.chunks if c.state is ChunkState.CACHED)
    assert data["counts_by_state"]["cached"] == cached
    assert sum(b["count"] for b in data["size_histogram"]) == len(heap.chunks)
    assert data["regions"][0]["va"] == heap.base_va
    assert data["platform"]["pointer_size"] == 8
    for key in ("confidence", "partial", "heuristic", "levels", "role_bytes",
                "metadata_bytes", "free_list_count", "evidence", "coverage",
                "diagnostics", "bytes_by_state", "version_hint", "format"):
        assert key in data


# -- /chunks ----------------------------------------------------------------------


def test_chunks_full_table(client, glibc):
    path, heap = glibc
    data = _get(client, "chunks", dump_path=path)
    assert data["total"] == len(heap.chunks)
    assert [c["va"] for c in data["chunks"]] == [c.va for c in heap.chunks]
    first = data["chunks"][0]
    assert "roles" not in first
    assert first["view_offset"] is not None
    assert data["filters"]["state"] is None


def test_chunks_paging(client, glibc):
    path, heap = glibc
    page1 = _get(client, "chunks", dump_path=path, page=1, page_size=3)
    assert page1["page"] == 1 and page1["page_size"] == 3
    assert page1["pages"] == -(-len(heap.chunks) // 3)
    assert [c["va"] for c in page1["chunks"]] == [c.va for c in heap.chunks[3:6]]


def test_chunks_state_and_size_filters(client, glibc):
    path, heap = glibc
    data = _get(client, "chunks", dump_path=path, state="cached")
    expected = [c.va for c in heap.chunks if c.state is ChunkState.CACHED]
    assert [c["va"] for c in data["chunks"]] == expected
    assert data["filters"]["state"] == "cached"
    data = _get(client, "chunks", dump_path=path, min_size=0x50, max_size=0x100)
    assert all(0x50 <= c["size"] <= 0x100 for c in data["chunks"])
    assert data["total"] == sum(1 for c in heap.chunks if 0x50 <= c.size <= 0x100)


def test_chunks_va_window(client, glibc):
    path, heap = glibc
    target = heap.chunks[2]
    data = _get(client, "chunks", dump_path=path, va_start=target.va,
                va_end=target.va + 1)
    assert [c["va"] for c in data["chunks"]] == [target.va]


# -- /chunk-at --------------------------------------------------------------------


def test_chunk_at_va(client, glibc):
    path, heap = glibc
    target = heap.chunks[2]
    data = _get(client, "chunk-at", dump_path=path, va=target.va + target.header_len)
    assert data["found"] is True
    assert data["chunk"]["va"] == target.va
    assert data["offset_in_user"] == 0
    assert data["prev"]["va"] == heap.chunks[1].va
    assert data["next"]["va"] == heap.chunks[3].va


def test_chunk_at_needs_exactly_one_address(client, glibc):
    resp = client.get("/api/heap/chunk-at", params={"dump_path": glibc[0]})
    assert resp.status_code == 400
    assert resp.json()["category"] == "INVALID_INPUT"


# -- /free-lists ------------------------------------------------------------------


def test_free_lists(client, glibc):
    path, _heap = glibc
    data = _get(client, "free-lists", dump_path=path)
    assert data["allocator"] == "ptmalloc2"
    assert data["list_count"] == len(data["lists"]) > 0
    assert data["corrupt_count"] == 0
    kind = data["kinds"][0]
    only = _get(client, "free-lists", dump_path=path, kind=kind)
    assert {row["kind"] for row in only["lists"]} == {kind}
    none = _get(client, "free-lists", dump_path=path, kind="no-such-kind")
    assert none["list_count"] == 0


# -- errors -----------------------------------------------------------------------


@pytest.mark.parametrize("route,params", [
    ("detect", {"allocator": "bogus"}),
    ("summary", {"allocator": "bogus"}),
    ("chunks", {"state": "bogus"}),
    ("chunks", {"view": "bogus"}),
    ("chunks", {"page_size": 0}),
    ("chunks", {"page": -1}),
    ("chunks", {"va_start": 0x20, "va_end": 0x10}),
    ("chunks", {"va_start": 0x10, "offset": 0, "length": 4}),
    ("roles", {"length": 0}),
    ("roles", {"length": (1 << 20) + 1}),
    ("roles", {"view": "bogus"}),
    ("roles", {"offset": -1}),
])
def test_bad_params_are_400(client, glibc, route, params):
    resp = client.get(f"/api/heap/{route}",
                      params={"dump_path": glibc[0], **params})
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["category"] == "INVALID_INPUT" and body["error"]


@pytest.mark.parametrize("route,params", [
    ("chunks", {"min_size": -1}),
    ("chunk-at", {"va": "not-an-int"}),
    ("summary", {"max_chunks": 0}),
])
def test_malformed_query_is_422(client, glibc, route, params):
    resp = client.get(f"/api/heap/{route}",
                      params={"dump_path": glibc[0], **params})
    assert resp.status_code == 422


@pytest.mark.parametrize("route", ["detect", "summary", "chunks",
                                   "chunk-at", "free-lists", "roles"])
def test_missing_dump_is_404(client, tmp_path, route):
    resp = client.get(f"/api/heap/{route}",
                      params={"dump_path": str(tmp_path / "nope.bin"), "va": 0})
    assert resp.status_code == 404


def test_missing_dump_path_is_422(client):
    assert client.get("/api/heap/summary").status_code == 422


def test_bad_key_hex_is_400(client, glibc):
    resp = client.get("/api/heap/summary",
                      params={"dump_path": glibc[0], "key_hex": "zz"})
    assert resp.status_code == 400


def test_path_outside_allowed_roots_is_403(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    path = sh.as_regioned_raw(tmp_path / "outside", [sh.glibc_heap()])
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    try:
        client = TestClient(create_app())
        for route in ("detect", "summary", "chunks", "chunk-at", "free-lists"):
            resp = client.get(f"/api/heap/{route}",
                              params={"dump_path": str(path)})
            assert resp.status_code == 403, route
            assert "MEMDIVER_ALLOWED_ROOTS" in resp.json()["detail"]
    finally:
        get_settings.cache_clear()


# -- /roles -----------------------------------------------------------------------


def test_roles_window(client, glibc):
    path, heap = glibc
    payload = _get(client, "roles", dump_path=path, length=sh.PAGE)
    assert set(payload) == {"allocator", "view", "offset", "length", "runs",
                            "chunk_starts", "partial", "heuristic"}
    assert payload["allocator"] == "ptmalloc2" and payload["view"] == "vas"
    assert payload["chunk_starts"] == [c.va - heap.base_va for c in heap.chunks]
    assert sum(r["length"] for r in payload["runs"]) == sh.PAGE


def test_roles_default_window(client, glibc):
    payload = _get(client, "roles", dump_path=glibc[0])
    assert (payload["offset"], payload["length"]) == (0, 65536)
