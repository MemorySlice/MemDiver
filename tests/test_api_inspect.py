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
