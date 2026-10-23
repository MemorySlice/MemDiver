"""The ``heap.*`` capabilities on all four surfaces, one payload each.

Modelled on ``tests/test_yara_scan_surfaces.py``. Every heap capability
(detect, summary, chunks, chunk_at, free_lists, roles) is called with
IDENTICAL arguments through:

* the library -- the producer exported from ``memdiver`` / ``memdiver.services``
  (asserted to be the very ``app.tools_heap`` function the registry names);
* the CLI -- ``memdiver heap <action> ... --json`` through the real parser;
* the web API -- ``GET /api/heap/<route>`` through a FastAPI ``TestClient``;
* the MCP server -- the registered ``heap_*`` tool's function,

on one synthetic glibc dump, and the four payloads must be equal.

Normalisation: every surface emits the producer's ``ServiceResult.payload``
and nothing else (the CLI and the web drop the status block, MCP presents
the payload alone), so the only transformation applied is a JSON round trip
of the library payload: the library hands back Python objects (tuples, ints)
where the other three surfaces hand back parsed JSON (lists). No field is
dropped or rewritten -- if a surface ever adds, loses or reshapes a field,
these tests fail.

``tests/test_architecture_invariants.py`` only checks that the registry
DECLARES a surface; :func:`test_every_declared_surface_actually_exists` checks
that each one is really wired (CLI handler, HTTP route, MCP tool, library
export).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("mcp")

from fastapi.testclient import TestClient  # noqa: E402

import memdiver  # noqa: E402
from memdiver import services  # noqa: E402
from memdiver.api.config import get_settings  # noqa: E402
from memdiver.api.main import create_app  # noqa: E402
from memdiver.app import tools_heap  # noqa: E402
from memdiver.app.capabilities import CAPABILITIES  # noqa: E402
from memdiver.app.session import ToolSession  # noqa: E402
from memdiver.cli import _HEAP_HANDLERS, _build_parser, _cmd_heap  # noqa: E402
from memdiver.heap.analyze import clear_heap_cache  # noqa: E402
from memdiver.mcp_server.server import create_server  # noqa: E402
from tests.fixtures import synth_heap as sh  # noqa: E402

LIBC_MODULE = (0x7F00_1000_0000, 0x2000, "/usr/lib/x86_64-linux-gnu/libc.so.6")
HEAP = sh.glibc_heap()
#: A VA inside the first tcache'd chunk's user data (free_link bytes).
CHUNK_AT_VA = HEAP.chunks[2].va + 0x10


@dataclass(frozen=True)
class SurfaceCase:
    """One heap capability called the same way on every surface.

    ``kwargs`` are the producer keyword arguments, which double as the web
    query parameters and the MCP tool arguments (same names on all three);
    ``cli_args`` spell the same request as CLI flags.
    """

    capability: str
    producer: Callable[..., Any]
    cli_action: str
    web_route: str
    mcp_tool: str
    kwargs: Dict[str, Any] = field(default_factory=dict)
    cli_args: List[str] = field(default_factory=list)


CASES = [
    SurfaceCase("heap.detect", tools_heap.heap_detect_result, "detect",
                "detect", "heap_detect"),
    SurfaceCase("heap.summary", tools_heap.heap_summary_result, "summary",
                "summary", "heap_summary"),
    SurfaceCase("heap.chunks", tools_heap.heap_chunks_result, "chunks",
                "chunks", "heap_chunks",
                {"state": "cached", "page_size": 2},
                ["--state", "cached", "--page-size", "2"]),
    SurfaceCase("heap.chunk_at", tools_heap.heap_chunk_at_result, "at",
                "chunk-at", "heap_chunk_at",
                {"va": CHUNK_AT_VA}, ["--va", hex(CHUNK_AT_VA)]),
    SurfaceCase("heap.free_lists", tools_heap.heap_free_lists_result,
                "free-lists", "free-lists", "heap_free_lists",
                {"kind": "tcache"}, ["--kind", "tcache"]),
    SurfaceCase("heap.roles", tools_heap.heap_roles_result, "roles", "roles",
                "heap_roles", {"view": "vas", "offset": 0x280, "length": 0x200},
                ["--view", "vas", "--offset", "0x280", "--length", "0x200"]),
]
_IDS = [case.capability for case in CASES]


# -- fixtures ---------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_cache():
    clear_heap_cache()
    yield
    clear_heap_cache()


@pytest.fixture
def dump(tmp_path) -> str:
    return str(sh.as_regioned_raw(tmp_path, [HEAP], modules=[LIBC_MODULE]))


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


@pytest.fixture(scope="module")
def mcp_tools():
    return {t.name: t for t in create_server()._tool_manager.list_tools()}


# -- one call per surface ---------------------------------------------------------


def _library(case: SurfaceCase, dump_path: str) -> dict:
    """The library export; JSON round trip only (tuples -> lists)."""
    producer = getattr(memdiver, case.producer.__name__)
    payload = producer(ToolSession(), dump_path, **case.kwargs).payload
    return json.loads(json.dumps(payload))


def _cli(case: SurfaceCase, dump_path: str, capsys) -> dict:
    args = _build_parser().parse_args(
        ["heap", case.cli_action, dump_path, *case.cli_args, "--json"])
    assert _cmd_heap(args) == 0
    return json.loads(capsys.readouterr().out)


def _web(case: SurfaceCase, dump_path: str, client: TestClient) -> dict:
    resp = client.get(f"/api/heap/{case.web_route}",
                      params={"dump_path": dump_path, **case.kwargs})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _mcp(case: SurfaceCase, dump_path: str, mcp_tools) -> dict:
    return json.loads(mcp_tools[case.mcp_tool].fn(dump_path=dump_path,
                                                   **case.kwargs))


# -- parity -----------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_all_four_surfaces_return_the_same_payload(case, dump, client,
                                                   mcp_tools, capsys):
    library = _library(case, dump)
    assert "error" not in library
    assert _cli(case, dump, capsys) == library
    assert _web(case, dump, client) == library
    assert _mcp(case, dump, mcp_tools) == library


@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_payloads_are_not_trivially_empty(case, dump):
    """Guards the parity test against agreeing on an empty answer."""
    library = _library(case, dump)
    allocator = library.get("best", library.get("allocator"))
    assert allocator == "ptmalloc2"
    non_empty_field = {"heap.detect": "candidates", "heap.summary": "regions",
                       "heap.chunks": "chunks", "heap.chunk_at": "chunk",
                       "heap.free_lists": "lists", "heap.roles": "runs"}
    assert library[non_empty_field[case.capability]]


@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_all_four_surfaces_agree_on_a_missing_dump(case, tmp_path, client,
                                                   mcp_tools, capsys):
    """Errors: CLI and MCP carry the same ``error`` body; the web answers 404."""
    missing = str(tmp_path / "absent.bin")
    cli = _cli_error(case, missing, capsys)
    mcp = _mcp(case, missing, mcp_tools)
    assert "error" in cli and "error" in mcp
    assert cli["error"] == mcp["error"]
    resp = client.get(f"/api/heap/{case.web_route}",
                      params={"dump_path": missing, **case.kwargs})
    assert resp.status_code == 404


def _cli_error(case: SurfaceCase, dump_path: str, capsys) -> dict:
    args = _build_parser().parse_args(
        ["heap", case.cli_action, dump_path, *case.cli_args, "--json"])
    assert _cmd_heap(args) != 0
    return json.loads(capsys.readouterr().out)


# -- every declared surface exists -------------------------------------------------


def _heap_capabilities():
    return {c.name: c for c in CAPABILITIES if c.name.startswith("heap.")}


def test_every_heap_capability_has_a_case():
    assert set(_heap_capabilities()) == {case.capability for case in CASES}


@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_every_declared_surface_actually_exists(case, client, mcp_tools):
    capability = _heap_capabilities()[case.capability]
    name = case.producer.__name__
    assert capability.producer == f"memdiver.app.tools_heap.{name}"
    assert set(capability.surfaces) == {"library", "cli", "web", "mcp"}
    # library: exported from the package and from memdiver.services
    assert getattr(memdiver, name) is case.producer
    assert getattr(services, name) is case.producer
    assert name in memdiver.__all__ and name in services.__all__
    # cli: the action parses and dispatches to a handler
    assert case.cli_action in _HEAP_HANDLERS
    # web: the GET route is mounted on the app
    paths = {getattr(r, "path", None) for r in client.app.routes}
    assert f"/api/heap/{case.web_route}" in paths
    # mcp: the tool is registered
    assert case.mcp_tool in mcp_tools
