"""P2.4 — ``analyze_region_result`` on all four surfaces.

``analyze_region_result`` answers the one question a hex viewer, an entropy
spike or a byte-search hit always raises next: *"what is actually AT this
offset?"* — the byte value, the local entropy band, and the printable strings
in the neighbourhood window. It was a complete, tested producer reachable from
NOWHERE, which is exactly why it sat in the completeness suite's
``EXEMPT_PRODUCERS`` and outside the parity ratchet entirely. This module covers
the four entry points added to close that:

* ``GET /api/inspect/region`` — the web route.
* the MCP ``analyze_region`` tool.
* the CLI ``memdiver inspect region`` subcommand.
* ``memdiver.services.analyze_region_result`` — the library surface.

The compute itself is covered by the producer- and ``core.region_analysis``-level
tests; these are adapter tests, so each surface is checked for the two things an
adapter can get wrong: does the payload arrive intact, and does the producer's
``CapabilityError`` reach the caller in that surface's OWN error shape rather
than a blanket 500 / stack trace / silent success.

The error shapes deliberately differ per surface, and each is asserted exactly:

* **web** — the route is newer than the global ``CapabilityError`` funnel
  (api/main.py), so unlike its ``_http_inspect`` siblings it has no legacy
  200-with-``{"error": …}`` body to preserve and answers a real 404 / 400
  carrying the producer's category.
* **MCP / CLI** — the inspect family's presenters render ``to_error_body()``
  (message plus structured details, no category), which is what every sibling
  inspect tool/subcommand already emits.
* **library** — the typed exception itself, category and all.
"""

import argparse
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import memdiver  # noqa: E402
from memdiver.api.main import create_app  # noqa: E402
from memdiver.core.service_errors import (  # noqa: E402
    ErrorCategory,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
)

_ROUTE = "/api/inspect/region"

# The fixture is hand-built rather than generated so every asserted number is
# derivable by reading this file: a 256-byte zero dump with one ASCII string
# planted at 64 and one distinctive byte at the offset under investigation.
_DUMP_SIZE = 256
_STRING_AT = 64
_PLANTED_STRING = b"MEMDIVER_HI\x00"
_PROBE_OFFSET = 100
_PROBE_BYTE = 0xAB
_MISSING = "/nonexistent/region.dump"
_PAYLOAD_KEYS = {
    "offset", "byte_value", "entropy", "entropy_level", "variance_at_offset",
    "variance_class", "matching_secrets", "strings", "neighborhood_hex",
    "window", "view",
}


@pytest.fixture(scope="module")
def dump_path(tmp_path_factory):
    """A raw ``.dump`` with a known byte at ``_PROBE_OFFSET`` and one string."""
    data = bytearray(_DUMP_SIZE)
    data[_STRING_AT:_STRING_AT + len(_PLANTED_STRING)] = _PLANTED_STRING
    data[_PROBE_OFFSET] = _PROBE_BYTE
    path = tmp_path_factory.mktemp("analyze_region") / "probe.dump"
    path.write_bytes(bytes(data))
    return str(path)


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


# ---------------------------------------------------------------------------
# Web: GET /api/inspect/region
# ---------------------------------------------------------------------------


def test_route_returns_the_producer_payload(client, dump_path):
    """The route hands back the producer's payload verbatim (status block
    dropped, as every inspect route drops it)."""
    resp = client.get(_ROUTE, params={"dump_path": dump_path,
                                      "offset": _PROBE_OFFSET})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == _PAYLOAD_KEYS, body
    assert body["offset"] == _PROBE_OFFSET
    assert body["byte_value"] == _PROBE_BYTE
    assert body["window"] == 64
    assert body["view"] == "raw"


def test_route_reports_variance_fields_as_empty(client, dump_path):
    """``variance_at_offset`` / ``matching_secrets`` are structurally empty on
    this path — they are in-memory cross-run artefacts a path-based producer
    cannot accept. Asserted so the fields are never mistaken for a real "no
    variance" measurement by a caller."""
    body = client.get(_ROUTE, params={"dump_path": dump_path,
                                      "offset": _PROBE_OFFSET}).json()

    assert body["variance_at_offset"] is None
    assert body["variance_class"] is None
    assert body["matching_secrets"] == []


def test_route_honours_the_window(client, dump_path):
    """``window`` bounds the neighbourhood read — the whole point of the
    producer's bounded slice, since dumps are routinely multi-GB. The hex is
    the window, so its length is the direct proof."""
    body = client.get(_ROUTE, params={"dump_path": dump_path,
                                      "offset": _PROBE_OFFSET,
                                      "window": 16}).json()

    assert body["window"] == 16
    assert len(bytes.fromhex(body["neighborhood_hex"])) == 16


def test_route_finds_strings_in_the_neighbourhood(client, dump_path):
    """A window wide enough to reach the planted string reports it; a narrow
    one does not. This is the behaviour that makes the view worth having."""
    wide = client.get(_ROUTE, params={"dump_path": dump_path,
                                      "offset": _PROBE_OFFSET,
                                      "window": 128}).json()
    narrow = client.get(_ROUTE, params={"dump_path": dump_path,
                                        "offset": _PROBE_OFFSET,
                                        "window": 8}).json()

    assert any("MEMDIVER" in s["value"] for s in wide["strings"]), wide["strings"]
    assert narrow["strings"] == []


def test_route_reports_a_missing_file_as_not_found(client):
    """NOT_FOUND (404) — not a 200-with-error-dict and not a 500. This route
    postdates the global CapabilityError funnel, so it reports the producer's
    real status and category."""
    resp = client.get(_ROUTE, params={"dump_path": _MISSING, "offset": 0})

    assert resp.status_code == 404, resp.text
    assert resp.json()["category"] == ErrorCategory.NOT_FOUND.name
    assert resp.json()["error"] == f"File not found: {_MISSING}"


def test_route_reports_an_out_of_range_offset_as_invalid_input(client, dump_path):
    """INVALID_INPUT (400) with the producer's own category — an offset past
    the end is the caller's mistake, distinguishable from a bad path."""
    resp = client.get(_ROUTE, params={"dump_path": dump_path,
                                      "offset": _DUMP_SIZE * 10})

    assert resp.status_code == 400, resp.text
    assert resp.json()["category"] == ErrorCategory.INVALID_INPUT.name
    assert resp.json()["error"] == "offset out of range"


def test_route_rejects_a_negative_offset(client, dump_path):
    """``Query(ge=0)`` refuses a negative offset at the boundary (422), the
    same guard ``/hex`` carries, so it never reaches the producer."""
    resp = client.get(_ROUTE, params={"dump_path": dump_path, "offset": -1})

    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# MCP: the analyze_region tool
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def mcp_tool():
    """The registered MCP tool's callable, presenter and all."""
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "analyze_region" in tools, sorted(tools)
    return tools["analyze_region"].fn


def test_mcp_tool_returns_json_payload(mcp_tool, dump_path):
    """The tool returns a JSON STRING (the MCP transport contract) carrying the
    producer's payload."""
    raw = mcp_tool(dump_path=dump_path, offset=_PROBE_OFFSET)
    assert isinstance(raw, str)

    payload = json.loads(raw)
    assert "error" not in payload, payload
    assert set(payload) == _PAYLOAD_KEYS
    assert payload["byte_value"] == _PROBE_BYTE


def test_mcp_tool_reports_a_missing_file(mcp_tool):
    """The inspect family's presenter renders a CapabilityError as the flat
    ``{"error": …}`` body — the same shape every sibling inspect tool emits, so
    an agent gets machine-readable text rather than an MCP stack trace."""
    payload = json.loads(mcp_tool(dump_path=_MISSING, offset=0))

    assert payload == {"error": f"File not found: {_MISSING}"}


def test_mcp_tool_reports_an_out_of_range_offset_with_details(mcp_tool, dump_path):
    """``OffsetOutOfRangeError``'s structured details are merged into the body,
    so an agent learns the actual file size and can retry without guessing."""
    payload = json.loads(mcp_tool(dump_path=dump_path, offset=_DUMP_SIZE * 10))

    assert payload == {
        "error": "offset out of range",
        "offset": _DUMP_SIZE * 10,
        "file_size": _DUMP_SIZE,
        "view": "raw",
    }


# ---------------------------------------------------------------------------
# CLI: memdiver inspect region
# ---------------------------------------------------------------------------


def _run_inspect_region(argv: list) -> tuple:
    """Parse a real ``inspect region`` argv and dispatch it; return (rc, json).

    Goes through ``build_parser()`` rather than a hand-built Namespace so the
    subcommand's REGISTRATION is proven too — a handler wired into
    ``_INSPECT_HANDLERS`` but missing its parser would still pass otherwise.
    """
    from memdiver.cli.inspect import _cmd_inspect
    from memdiver.cli.main import build_parser

    args = build_parser().parse_args(argv)
    assert isinstance(args, argparse.Namespace)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = _cmd_inspect(args)
    return rc, json.loads(buf.getvalue())


def test_cli_region_emits_the_payload(dump_path):
    """Exit 0 and the producer's payload as JSON on stdout."""
    rc, payload = _run_inspect_region(
        ["inspect", "region", dump_path, "--offset", str(_PROBE_OFFSET)])

    assert rc == 0
    assert set(payload) == _PAYLOAD_KEYS
    assert payload["byte_value"] == _PROBE_BYTE


def test_cli_region_accepts_hex_offsets_and_a_window(dump_path):
    """``--offset`` takes ``0x`` notation (every inspect subcommand does) and
    ``--window`` is forwarded, not silently defaulted."""
    rc, payload = _run_inspect_region(
        ["inspect", "region", dump_path, "--offset", hex(_PROBE_OFFSET),
         "--window", "16"])

    assert rc == 0
    assert payload["offset"] == _PROBE_OFFSET
    assert payload["window"] == 16


def test_cli_region_reports_a_missing_file(dump_path):
    """Exit 1 plus the flat error body — the CLI's long-standing contract for a
    hard producer error, shared verbatim with the other inspect subcommands."""
    rc, payload = _run_inspect_region(["inspect", "region", _MISSING])

    assert rc == 1
    assert payload == {"error": f"File not found: {_MISSING}"}


def test_cli_region_reports_an_out_of_range_offset(dump_path):
    """Exit 1 with the structured details merged in, mirroring MCP."""
    rc, payload = _run_inspect_region(
        ["inspect", "region", dump_path, "--offset", str(_DUMP_SIZE * 10)])

    assert rc == 1
    assert payload["error"] == "offset out of range"
    assert payload["file_size"] == _DUMP_SIZE


# ---------------------------------------------------------------------------
# Library: memdiver.services.analyze_region_result
# ---------------------------------------------------------------------------


def test_library_producer_is_public():
    """Reachable via the supported public API — the facade AND the lifted top
    level, as the same object (single source of truth)."""
    assert "analyze_region_result" in memdiver.services.__all__
    assert "analyze_region_result" in memdiver.__all__
    assert memdiver.analyze_region_result is memdiver.services.analyze_region_result


def test_library_producer_returns_a_status_carrying_result(dump_path):
    """The library surface gets the whole ``ServiceResult``, status block and
    all — that block is precisely what the other three surfaces drop."""
    result = memdiver.services.analyze_region_result(
        memdiver.ToolSession(), dump_path, _PROBE_OFFSET)

    assert result.payload["byte_value"] == _PROBE_BYTE
    assert result.status.key.decrypted is True


def test_library_producer_raises_typed_errors(dump_path):
    """The library caller gets the exception itself, category and all — no
    ``{"error": …}`` dict to string-match against."""
    session = memdiver.ToolSession()

    with pytest.raises(FileNotFoundServiceError) as missing:
        memdiver.services.analyze_region_result(session, _MISSING, 0)
    assert missing.value.category is ErrorCategory.NOT_FOUND

    with pytest.raises(OffsetOutOfRangeError) as out_of_range:
        memdiver.services.analyze_region_result(
            session, dump_path, _DUMP_SIZE * 10)
    assert out_of_range.value.category is ErrorCategory.INVALID_INPUT
    assert out_of_range.value.details["file_size"] == _DUMP_SIZE


# ---------------------------------------------------------------------------
# Cross-surface parity
# ---------------------------------------------------------------------------


def test_all_four_surfaces_agree(mcp_tool, client, dump_path):
    """The four adapters dispatch through the ONE producer, so identical inputs
    must yield an identical payload. Any future change that inlines the compute
    in one adapter fails here."""
    from_lib = memdiver.services.analyze_region_result(
        memdiver.ToolSession(), dump_path, _PROBE_OFFSET, 32).payload
    from_mcp = json.loads(mcp_tool(dump_path=dump_path, offset=_PROBE_OFFSET,
                                   window=32))
    from_web = client.get(_ROUTE, params={"dump_path": dump_path,
                                          "offset": _PROBE_OFFSET,
                                          "window": 32}).json()
    _rc, from_cli = _run_inspect_region(
        ["inspect", "region", dump_path, "--offset", str(_PROBE_OFFSET),
         "--window", "32"])

    assert from_lib == from_mcp == from_web == from_cli


def test_capability_is_registered_on_all_four_surfaces():
    """The registry entry this change exists to make true. Guards against a
    surface being quietly dropped later while the ``_cap`` still claims it."""
    from memdiver.app.capabilities import CAPABILITIES

    cap = next(c for c in CAPABILITIES if c.name == "inspect.analyze_region")
    assert cap.producer == "memdiver.app.tools_inspect.analyze_region_result"
    assert cap.surfaces == frozenset({"library", "cli", "web", "mcp"})
