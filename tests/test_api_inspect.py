"""Happy-path tests for the non-MSL-table half of the /api/inspect router.

The MSL table-block + tag-status endpoints are covered by
``tests/test_api_msl_endpoints.py``. This file targets the remaining
endpoints: /blocks, /modules, /session-info, /format, /strings, /entropy.

Fixtures (client / msl_path via generate_msl_file) mirror that sibling file.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from memdiver.api.main import create_app
from tests.fixtures.generate_msl_fixtures import generate_msl_file


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture
def msl_path(tmp_path):
    p = tmp_path / "inspect_test.msl"
    p.write_bytes(generate_msl_file())
    return str(p)


@pytest.fixture
def raw_dump(tmp_path):
    """A tiny raw binary blob containing ASCII strings + arbitrary bytes."""
    p = tmp_path / "sample.dump"
    payload = (
        b"\x00\x01\x02\x03"
        b"HELLO_WORLD_STRING"
        b"\xff\xfe\xfd\x00"
        b"another_ascii_token"
        b"\x10\x20\x30\x40\x50"
    )
    p.write_bytes(payload)
    return str(p), len(payload)


# -- MSL-path endpoints --------------------------------------------------

def test_blocks_grouped_categories(client, msl_path):
    resp = client.get("/api/inspect/blocks", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0
    for group in data:
        assert "category" in group
        assert "blocks" in group
        assert isinstance(group["blocks"], list)
        for block in group["blocks"]:
            assert "label" in block
            assert "offset" in block
            assert "size" in block


def test_modules_list(client, msl_path):
    resp = client.get("/api/inspect/modules", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    m0 = data[0]
    assert "path" in m0
    assert "base_addr" in m0
    assert "size" in m0
    assert "version" in m0
    # The fixture seeds a libssl module at the canonical base.
    paths = [m["path"] for m in data]
    assert "/usr/lib/libssl.so" in paths


def test_session_info(client, msl_path):
    resp = client.get("/api/inspect/session-info", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    for key in ("dump_uuid", "pid", "os_type", "arch_type", "region_count",
                "modules", "vas_entries"):
        assert key in data, key
    assert isinstance(data["modules"], list)
    assert isinstance(data["vas_entries"], list)


def test_vas_regions(client, msl_path):
    resp = client.get("/api/inspect/vas", params={"msl_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    for key in ("vas_entries", "region_count", "total_region_size", "vas_coverage"):
        assert key in data, key
    assert isinstance(data["vas_coverage"], dict)
    entries = data["vas_entries"]
    assert isinstance(entries, list) and len(entries) >= 1
    # The full five-field VAS entry shape the VasChart frontend consumes.
    assert set(entries[0]) == {
        "base_addr", "region_size", "region_type", "protection", "mapped_path",
    }
    libssl = next(e for e in entries if e["mapped_path"] == "/usr/lib/libssl.so")
    assert libssl["base_addr"] == 0x00400000
    assert libssl["region_size"] == 0x10000


# -- raw-dump / format endpoints ----------------------------------------

def test_format_detects_msl_container(client, msl_path):
    resp = client.get("/api/inspect/format", params={"dump_path": msl_path})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    assert "format" in data
    assert "nav_tree" in data
    assert "detected_format" in data
    assert "available_formats" in data


def test_strings_paginated_result(client, raw_dump):
    path, size = raw_dump
    resp = client.get(
        "/api/inspect/strings",
        params={"dump_path": path, "offset": 0, "length": size, "min_length": 4},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    assert "strings" in data
    assert "next_cursor" in data
    assert "window_end" in data
    assert isinstance(data["strings"], list)
    values = [s["value"] for s in data["strings"]]
    assert any("HELLO_WORLD_STRING" in v for v in values)
    for s in data["strings"]:
        assert "offset" in s
        assert "value" in s
        assert "length" in s


def test_entropy_structure(client, raw_dump):
    path, size = raw_dump
    resp = client.get(
        "/api/inspect/entropy",
        params={"dump_path": path, "offset": 0, "length": size},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    assert "overall_entropy" in data
    assert "high_entropy_regions" in data
    assert "profile_sample" in data
    assert "stats" in data
    assert isinstance(data["high_entropy_regions"], list)
    assert isinstance(data["profile_sample"], list)
    for key in ("min", "max", "mean"):
        assert key in data["stats"]


# -- error paths --------------------------------------------------------

def test_blocks_rejects_non_msl_suffix(client, tmp_path):
    not_msl = tmp_path / "file.txt"
    not_msl.write_text("not an msl file")
    resp = client.get("/api/inspect/blocks", params={"msl_path": str(not_msl)})
    assert resp.status_code == 400


def test_blocks_missing_file_404(client, tmp_path):
    missing = tmp_path / "does_not_exist.msl"
    resp = client.get("/api/inspect/blocks", params={"msl_path": str(missing)})
    assert resp.status_code == 404


# -- offset bounds guards ------------------------------------------------

def test_hex_rejects_negative_offset_422(client, raw_dump):
    """The /hex offset query param has ge=0, so a negative offset is a 422."""
    path, _ = raw_dump
    resp = client.get(
        "/api/inspect/hex", params={"dump_path": path, "offset": -1}
    )
    assert resp.status_code == 422


def test_read_hex_negative_offset_errors(raw_dump):
    """read_hex itself returns a clean 'out of range' error for a negative
    offset, even when called below the API validation layer."""
    from memdiver.mcp_server import tools_inspect
    from memdiver.mcp_server.session import ToolSession

    path, _ = raw_dump
    result = tools_inspect.read_hex(ToolSession(), path, offset=-1, length=16)
    assert "error" in result
    assert "out of range" in result["error"]


# -- byte-search view="va" over HTTP ------------------------------------


@pytest.fixture
def gcore_dump(tmp_path):
    """A synthetic ELF ``gcore.core`` — a dump format with no "va" view."""
    from tests.fixtures import synth_elf_core

    return str(synth_elf_core.build(tmp_path / "run_0001") / "gcore.core")


def test_byte_search_va_view_on_msl_returns_offsets(client, msl_path):
    """The .msl fixture's captured page is 0xAA-filled, so a 0xAAAA needle
    must come back with real VA-span-relative offsets."""
    resp = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": msl_path, "pattern_hex": "aaaa", "view": "va"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "error" not in data
    assert data["view"] == "va"
    assert data["offsets"][:3] == [0, 1, 2]
    assert data["count"] > 0


def test_byte_search_va_view_on_gcore_is_an_error_body_not_a_500(client, gcore_dump):
    """The regression this endpoint guard exists for.

    ``view`` is persisted in the frontend's localStorage, so opening a gcore
    dump after using VA on an .msl sends ``view=va`` with no user action. The
    source raises a bare ``ValueError`` for that view, which used to escape
    the ``_http_inspect`` CapabilityError funnel and surface as
    ``Search failed: 500`` — a server fault for what is a plain capability
    gap. Asserting the status code alone is not enough: the body has to name
    the view, so the UI can say which views DO work.
    """
    resp = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": gcore_dump, "pattern_hex": "aaaa", "view": "va"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "error" in data
    assert "va" in data["error"]
    assert data["view"] == "va"
    assert data["supported_views"] == ["raw", "vas"]


def test_byte_search_supported_view_on_gcore_still_works(client, gcore_dump):
    """The negative control: the guard must reject only the unavailable view,
    so the same dump on ``view=raw`` still searches normally."""
    resp = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": gcore_dump, "pattern_hex": "7f454c46", "view": "raw"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "error" not in data
    assert data["offsets"][0] == 0  # the ELF magic, at offset 0.


def test_hex_va_view_on_gcore_is_an_error_body_not_a_500(client, gcore_dump):
    """The same persisted ``viewMode`` reaches /hex without any search at all
    — it is the first request the viewer makes when a dump is opened."""
    resp = client.get(
        "/api/inspect/hex",
        params={"dump_path": gcore_dump, "offset": 0, "length": 64, "view": "va"},
    )
    assert resp.status_code == 200, resp.text
    assert "error" in resp.json()
    assert resp.json()["supported_views"] == ["raw", "vas"]


# -- byte-search pattern_format over HTTP --------------------------------
#
# The query param exists so the web search box can offer more than hex. These
# tests pin the wire contract the frontend depends on: the resolved bytes come
# back in ``pattern_hex``, a bad needle is the router's legacy 200-with-error
# body (NOT a 500), and omitting the param keeps the old hex behaviour.


def test_byte_search_text_format_finds_the_ascii_string(client, raw_dump):
    """``pattern_format=text`` searches the UTF-8 bytes of what was typed.

    The fixture plants ``HELLO_WORLD_STRING`` at offset 4, so the offset is
    asserted exactly: an endpoint that ignored ``pattern_format`` and parsed
    the pattern as hex would fail on the parse rather than return a wrong
    offset, but one that searched the literal characters of some other encoding
    would return an empty list — and only a named offset catches that.
    """
    path, _ = raw_dump
    resp = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": path, "pattern_hex": "HELLO_WORLD_STRING",
                "pattern_format": "text"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "error" not in data
    assert data["offsets"] == [4]
    assert data["count"] == 1
    assert data["count_exact"] is True
    # The RESOLVED bytes: what the hex viewer highlights.
    assert data["pattern_hex"] == b"HELLO_WORLD_STRING".hex()
    assert data["pattern_format"] == "text"
    assert data["pattern_format_requested"] == "text"


def test_byte_search_utf16le_format_does_not_match_an_ascii_string(client, raw_dump):
    """The same word in the wrong width is genuinely absent — 0 hits, not an
    error. This is why utf16le is a format of its own rather than a variant of
    ``text``: a dump that stores wide strings and one that stores narrow ones
    are different searches, and conflating them would silently answer the wrong
    question."""
    path, _ = raw_dump
    resp = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": path, "pattern_hex": "HELLO_WORLD_STRING",
                "pattern_format": "utf16le"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "error" not in data
    assert data["offsets"] == []
    assert data["count"] == 0


def test_byte_search_u32le_format_finds_a_pointer_sized_value(client, raw_dump):
    """The trailing ``10 20 30 40`` bytes read as a little-endian u32.

    An analyst reading a value off another pane types the NUMBER, not its
    byte order — so the endianness lives in the format name and the endpoint
    has to do the conversion.
    """
    path, _ = raw_dump
    resp = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": path, "pattern_hex": "0x40302010",
                "pattern_format": "u32le"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["offsets"] == [45]
    assert data["pattern_hex"] == "10203040"


@pytest.mark.parametrize(
    "pattern, pattern_format",
    [
        pytest.param("abc", "hex", id="odd-length-hex"),
        pytest.param("not base64!", "base64", id="bad-base64"),
        pytest.param("-1", "u32le", id="negative-integer"),
        pytest.param("4294967296", "u32le", id="integer-too-wide"),
        pytest.param("4142", "utf16", id="unknown-format"),
    ],
)
def test_byte_search_invalid_pattern_is_an_error_body_not_a_500(
    client, raw_dump, pattern, pattern_format
):
    """A typo in the search box is the CALLER's error, not a server fault.

    This router's legacy contract is a 200 carrying ``{"error": ...}`` (see
    ``_http_inspect``), which the frontend renders inline beside the box. A
    needle that raised past the CapabilityError funnel would surface as
    ``Search failed: 500`` — the exact failure mode the funnel exists to
    prevent — and would tell the analyst nothing about what to fix.
    """
    path, _ = raw_dump
    resp = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": path, "pattern_hex": pattern,
                "pattern_format": pattern_format},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "error" in data, data
    assert data["error"]


def test_byte_search_without_pattern_format_is_still_a_hex_search(client, raw_dump):
    """Back-compat: every pre-existing caller omits ``pattern_format``.

    The default is ``hex``, NOT ``auto`` — an odd-length hex string has always
    been an error here and must not quietly become a text search that returns a
    confident "0 hits". Both halves are asserted: the valid hex needle still
    resolves to its bytes, and the invalid one still fails.
    """
    path, _ = raw_dump
    ok = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": path, "pattern_hex": "1020304050"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["offsets"] == [45]
    assert ok.json()["pattern_format"] == "hex"

    bad = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": path, "pattern_hex": "abc"},
    )
    assert bad.status_code == 200, bad.text
    assert "error" in bad.json()


def test_byte_search_auto_format_reports_what_it_resolved_to(client, raw_dump):
    """``auto`` is available over HTTP, and says which reading it chose.

    The UI shows the resolved bytes before the search runs, so the response has
    to carry BOTH the request (``auto``) and the resolution — a wrong guess the
    analyst can see costs one click.
    """
    path, _ = raw_dump
    resp = client.get(
        "/api/inspect/byte-search",
        params={"dump_path": path, "pattern_hex": "another_ascii_token",
                "pattern_format": "auto"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["pattern_format"] == "text"
    assert data["pattern_format_requested"] == "auto"
    assert data["offsets"] == [26]
