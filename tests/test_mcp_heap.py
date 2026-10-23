"""MCP surface of the heap.* capabilities: the six ``heap_*`` tools.

Calls each registered tool in-process (``create_server()._tool_manager`` ->
``tool.fn``, as ``test_inspect_contract_mcp`` does) on a synthetic glibc heap
and pins two properties:

* parity -- the tool's JSON equals the backing ``tools_heap`` producer's
  ``.payload`` for identical arguments (the MCP wrapper adds nothing);
* the error funnel -- bad arguments come back as a structured ``{"error"}``
  body, never an exception escaping the tool.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp")

from memdiver.app import tools_heap  # noqa: E402
from memdiver.app.session import ToolSession  # noqa: E402
from memdiver.heap.analyze import clear_heap_cache  # noqa: E402
from memdiver.mcp_server.server import create_server  # noqa: E402
from tests.fixtures import synth_heap as sh  # noqa: E402

LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
LIBC_MODULE = (0x7F00_1000_0000, 0x2000, LIBC_PATH)


@pytest.fixture(autouse=True)
def _fresh_cache():
    clear_heap_cache()
    yield
    clear_heap_cache()


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in create_server()._tool_manager.list_tools()}


@pytest.fixture
def glibc(tmp_path):
    heap = sh.glibc_heap()
    path = sh.as_regioned_raw(tmp_path, [heap], modules=[LIBC_MODULE])
    return str(path), heap


def _call(tools, name: str, **kwargs) -> dict:
    return json.loads(tools[name].fn(**kwargs))


def _producer(producer, dump_path: str, **kwargs) -> dict:
    payload = producer(ToolSession(), dump_path, **kwargs).payload
    return json.loads(json.dumps(payload))


# -- parity: MCP JSON == producer payload ------------------------------------------


@pytest.mark.parametrize("tool_name, producer, kwargs", [
    ("heap_detect", tools_heap.heap_detect_result, {}),
    ("heap_detect", tools_heap.heap_detect_result, {"allocator": "jemalloc"}),
    ("heap_summary", tools_heap.heap_summary_result, {}),
    ("heap_chunks", tools_heap.heap_chunks_result, {}),
    ("heap_chunks", tools_heap.heap_chunks_result,
     {"state": "cached", "page_size": 2}),
    ("heap_free_lists", tools_heap.heap_free_lists_result, {}),
    ("heap_roles", tools_heap.heap_roles_result, {}),
    ("heap_roles", tools_heap.heap_roles_result,
     {"view": "raw", "offset": 0x2a0, "length": 0x100}),
])
def test_tool_matches_producer(tools, glibc, tool_name, producer, kwargs):
    dump_path = glibc[0]
    assert (_call(tools, tool_name, dump_path=dump_path, **kwargs)
            == _producer(producer, dump_path, **kwargs))


def test_chunk_at_matches_producer(tools, glibc):
    dump_path, heap = glibc
    target = heap.chunks[1].va + 0x20
    got = _call(tools, "heap_chunk_at", dump_path=dump_path, va=target)
    assert got == _producer(tools_heap.heap_chunk_at_result, dump_path,
                            va=target)
    assert got["found"] is True


def test_detect_reports_ptmalloc2(tools, glibc):
    payload = _call(tools, "heap_detect", dump_path=glibc[0])
    assert payload["best"] == "ptmalloc2"


def test_summary_counts_every_chunk(tools, glibc):
    dump_path, heap = glibc
    payload = _call(tools, "heap_summary", dump_path=dump_path)
    assert payload["allocator"] == "ptmalloc2"
    assert payload["chunk_count"] == len(heap.chunks)


# -- error funnel ------------------------------------------------------------------


@pytest.mark.parametrize("tool_name, kwargs", [
    ("heap_detect", {"allocator": "nonsense"}),
    ("heap_summary", {"allocator": "nonsense"}),
    ("heap_chunks", {"state": "nonsense"}),
    ("heap_chunks", {"view": "nonsense"}),
    ("heap_chunks", {"va_start": 0x1000, "offset": 0, "length": 16}),
    ("heap_chunks", {"page_size": 0}),
    ("heap_chunk_at", {}),
    ("heap_chunk_at", {"va": 0x1000, "offset": 0}),
    ("heap_free_lists", {"allocator": "nonsense"}),
    ("heap_roles", {"length": 0}),
    ("heap_roles", {"length": (1 << 20) + 1}),
    ("heap_roles", {"view": "nonsense"}),
])
def test_bad_args_funnel_to_error(tools, glibc, tool_name, kwargs):
    payload = _call(tools, tool_name, dump_path=glibc[0], **kwargs)
    assert "error" in payload


@pytest.mark.parametrize("tool_name", [
    "heap_detect", "heap_summary", "heap_chunks", "heap_free_lists",
    "heap_roles",
])
def test_missing_file_funnels_to_error(tools, tmp_path, tool_name):
    payload = _call(tools, tool_name, dump_path=str(tmp_path / "absent.bin"))
    assert "error" in payload
