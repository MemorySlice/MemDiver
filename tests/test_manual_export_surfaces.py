"""P2.3 — ``manual_export_pattern`` on the web + MCP surfaces.

``manual_export_pattern`` is the exact COMPLEMENT of the auto path: *"I know
the offset, I do not have the key bytes"* — the way out of
``analyze_candidates`` or a reverse-engineering session. It was CLI-only, which
kept it parked in the completeness suite's ``EXEMPT_PRODUCERS`` and therefore
outside the parity ratchet entirely. This module covers the two surfaces that
were added to close that:

* ``POST /api/analysis/manual-export`` — the web route, the manual sibling of
  ``/auto-export``.
* the MCP ``manual_export_pattern`` tool — the sibling of ``export_pattern``.

Both are thin adapters, so each is tested for the two things an adapter can get
wrong: does the success payload arrive intact (region echoed back, pattern
rendered), and does the producer's ``CapabilityError`` reach the caller with its
OWN category/status rather than a blanket 500 / stack trace.

The producer itself is covered in ``test_mcp_new_tools.py``; the CLI branch in
``test_cli.py`` / ``test_cli_memory_relative.py``. This module deliberately does
not re-test the compute.
"""

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

from generate_aes_fixtures import (  # noqa: E402
    KEY_LENGTH,
    KEY_OFFSET,
    generate_dataset,
)

from memdiver.api.main import create_app  # noqa: E402

# Same window as the producer-level tests: anchor + planted key + anchor, so the
# region carries both static bytes (for the signature) and volatile ones (the
# key). Keeping the constants identical means a fixture change breaks both
# layers together rather than silently diverging.
_MANUAL_OFFSET = KEY_OFFSET - 16
_MANUAL_LENGTH = KEY_LENGTH + 32

_EXPORT_PAYLOAD_KEYS = {"format", "content", "pattern", "region"}
_REGION_KEYS = {"offset", "length", "key_start", "key_end"}

_ROUTE = "/api/analysis/manual-export"


@pytest.fixture(scope="module")
def aes_dumps(tmp_path_factory):
    """Raw ``.dump`` fixtures with a planted, per-run-varying AES key region."""
    out = tmp_path_factory.mktemp("manual_export_aes")
    generate_dataset(out, num_runs=6, seed=11)
    paths = sorted(out.glob("**/*.dump"))
    assert len(paths) >= 2
    return [str(p) for p in paths]


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


# ---------------------------------------------------------------------------
# Web: POST /api/analysis/manual-export
# ---------------------------------------------------------------------------


def test_route_returns_the_producer_payload(client, aes_dumps):
    """The route hands back the producer's payload verbatim, with the region
    the caller asked for echoed back — on this path ``key_start`` IS the
    supplied offset (there is no search, so the key begins at pattern 0)."""
    resp = client.post(_ROUTE, json={
        "dump_paths": aes_dumps,
        "offset": _MANUAL_OFFSET,
        "length": _MANUAL_LENGTH,
        "format": "yara",
        "name": "web_manual",
        "min_static_ratio": 0.1,
    })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert _EXPORT_PAYLOAD_KEYS <= set(body), body
    assert body["format"] == "yara"
    assert "rule" in body["content"]

    region = body["region"]
    assert _REGION_KEYS <= set(region)
    assert region["offset"] == _MANUAL_OFFSET
    assert region["length"] == _MANUAL_LENGTH
    assert region["key_start"] == _MANUAL_OFFSET
    assert region["key_end"] == _MANUAL_OFFSET + _MANUAL_LENGTH


def test_route_defaults_to_volatility3(client, aes_dumps):
    """``format`` is optional and defaults to the same vol3 renderer the auto
    route and the CLI default to — surfaces must not disagree on the default
    artifact type."""
    resp = client.post(_ROUTE, json={
        "dump_paths": aes_dumps,
        "offset": _MANUAL_OFFSET,
        "length": _MANUAL_LENGTH,
        "min_static_ratio": 0.1,
    })

    assert resp.status_code == 200, resp.text
    assert resp.json()["format"] == "volatility3"


def test_route_rejects_a_single_dump(client, aes_dumps):
    """PRECONDITION (400): the differential needs at least two dumps to tell a
    static anchor from a volatile key."""
    resp = client.post(_ROUTE, json={
        "dump_paths": aes_dumps[:1],
        "offset": _MANUAL_OFFSET,
        "length": _MANUAL_LENGTH,
    })

    assert resp.status_code == 400, resp.text
    assert "at least 2 dumps" in resp.json()["detail"]


def test_route_reports_missing_files_as_not_found(client):
    """NOT_FOUND (404) — not a 400 and not a 500: the paths are server-side, so
    a typo has to be distinguishable from a bad region."""
    resp = client.post(_ROUTE, json={
        "dump_paths": ["/nonexistent/a.dump", "/nonexistent/b.dump"],
        "offset": 0,
        "length": 64,
    })

    assert resp.status_code == 404, resp.text
    assert "File not found" in resp.json()["detail"]


def test_route_rejects_an_unknown_format(client, aes_dumps):
    """UNSUPPORTED (400) reaches the wire with its own category. The producer
    lets ``AnalysisServiceError`` propagate unmodified precisely so this route
    can report "Unknown format" rather than a blanket INVALID_INPUT."""
    resp = client.post(_ROUTE, json={
        "dump_paths": aes_dumps,
        "offset": _MANUAL_OFFSET,
        "length": _MANUAL_LENGTH,
        "format": "xml",
    })

    assert resp.status_code == 400, resp.text
    assert "Unknown format" in resp.json()["detail"]


def test_route_rejects_an_empty_region(client, aes_dumps):
    """A zero length is refused rather than crashing the handler.

    It arrives as a 500 because ``EmptyRegionError`` carries category INTERNAL
    ("Failed to read region") — the producer's long-standing classification,
    shared verbatim with the auto path and the CLI. Asserted exactly, not as
    ">= 400", so that if the category is ever corrected to a 4xx this test says
    so instead of quietly passing.
    """
    resp = client.post(_ROUTE, json={
        "dump_paths": aes_dumps,
        "offset": _MANUAL_OFFSET,
        "length": 0,
    })

    assert resp.status_code == 500, resp.text
    assert resp.json()["detail"] == "Failed to read region"


def test_route_reports_a_too_volatile_region(client, aes_dumps):
    """A region that cannot meet ``min_static_ratio`` yields the producer's
    InsufficientStaticError, translated — the manual path's most likely real
    failure, since the user picked the region."""
    resp = client.post(_ROUTE, json={
        "dump_paths": aes_dumps,
        # The planted key alone: every byte varies run to run, so there is no
        # static filler left to anchor a signature on.
        "offset": KEY_OFFSET,
        "length": KEY_LENGTH,
        "min_static_ratio": 0.99,
    })

    assert resp.status_code == 400, resp.text
    assert "Insufficient static bytes" in resp.json()["detail"]


def test_route_is_the_manual_sibling_of_auto_export(client, aes_dumps):
    """Parity guard: both export routes render the same payload SHAPE, so a
    caller can switch between "find the region for me" and "here is the region"
    without reshaping its result handling."""
    manual = client.post(_ROUTE, json={
        "dump_paths": aes_dumps,
        "offset": _MANUAL_OFFSET,
        "length": _MANUAL_LENGTH,
        "format": "json",
        "min_static_ratio": 0.1,
    })
    auto = client.post("/api/analysis/auto-export", json={
        "dump_paths": aes_dumps,
        "format": "json",
        "align": False,
        "context": 32,
    })

    assert manual.status_code == 200, manual.text
    assert auto.status_code == 200, auto.text
    assert set(manual.json()) == set(auto.json()) == _EXPORT_PAYLOAD_KEYS
    assert set(manual.json()["region"]) == set(auto.json()["region"]) == _REGION_KEYS


# ---------------------------------------------------------------------------
# MCP: the manual_export_pattern tool
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def mcp_tool():
    """The registered MCP tool's callable, funnel and all."""
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "manual_export_pattern" in tools, sorted(tools)
    return tools["manual_export_pattern"].fn


def test_mcp_tool_returns_json_payload(mcp_tool, aes_dumps, tmp_path):
    """The tool returns a JSON STRING (the MCP transport contract), carrying the
    producer's payload — and writes the artifact when ``output_dir`` is given,
    which is the parameter the web route deliberately does not expose."""
    raw = mcp_tool(
        dump_paths=aes_dumps,
        offset=_MANUAL_OFFSET,
        length=_MANUAL_LENGTH,
        output_dir=str(tmp_path / "manual"),
        fmt="yara",
        name="mcp_manual",
        min_static_ratio=0.1,
    )
    assert isinstance(raw, str)

    payload = json.loads(raw)
    assert "error" not in payload, payload
    assert _EXPORT_PAYLOAD_KEYS <= set(payload)
    assert payload["format"] == "yara"
    assert payload["region"]["offset"] == _MANUAL_OFFSET
    assert payload["region"]["key_start"] == _MANUAL_OFFSET
    assert Path(payload["pattern_path"]).is_file()


def test_mcp_tool_funnels_precondition_error(mcp_tool, aes_dumps):
    """A CapabilityError escaping the body is rendered as the structured
    ``{error, code, category}`` dict — an agent gets machine-readable text, not
    an MCP stack trace."""
    payload = json.loads(mcp_tool(
        dump_paths=aes_dumps[:1],
        offset=_MANUAL_OFFSET,
        length=_MANUAL_LENGTH,
    ))

    assert payload["category"] == "PRECONDITION"
    assert payload["error"] == "Need at least 2 dumps, got 1"


def test_mcp_tool_funnels_not_found_error(mcp_tool):
    """Missing paths funnel as NOT_FOUND, matching the route's 404 — the two
    agent-facing surfaces must classify the same mistake the same way."""
    payload = json.loads(mcp_tool(
        dump_paths=["/nonexistent/a.dump", "/nonexistent/b.dump"],
        offset=0,
        length=64,
    ))

    assert payload["category"] == "NOT_FOUND"
    assert payload["error"].startswith("File not found:")


def test_mcp_tool_funnels_unknown_format(mcp_tool, aes_dumps):
    """UNSUPPORTED survives the funnel with its own category, for the same
    reason the route keeps it: the producer never re-wraps
    ``AnalysisServiceError`` in a blanket INVALID_INPUT."""
    payload = json.loads(mcp_tool(
        dump_paths=aes_dumps,
        offset=_MANUAL_OFFSET,
        length=_MANUAL_LENGTH,
        fmt="xml",
    ))

    assert payload["category"] == "UNSUPPORTED"
    assert "Unknown format" in payload["error"]


def test_mcp_and_web_agree_on_the_same_region(mcp_tool, client, aes_dumps):
    """Cross-surface parity: the MCP tool and the HTTP route dispatch through
    the ONE producer, so the same inputs must yield byte-identical content.
    Any future change that inlines the pipeline in one adapter fails here."""
    from_mcp = json.loads(mcp_tool(
        dump_paths=aes_dumps,
        offset=_MANUAL_OFFSET,
        length=_MANUAL_LENGTH,
        fmt="json",
        name="parity",
        min_static_ratio=0.1,
    ))
    resp = client.post(_ROUTE, json={
        "dump_paths": aes_dumps,
        "offset": _MANUAL_OFFSET,
        "length": _MANUAL_LENGTH,
        "format": "json",
        "name": "parity",
        "min_static_ratio": 0.1,
    })

    assert resp.status_code == 200, resp.text
    from_web = resp.json()
    assert from_mcp["region"] == from_web["region"]
    assert from_mcp["content"] == from_web["content"]
