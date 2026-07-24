"""Unit tests for the Phase-4 (G3) ServiceResult producers.

Covers the producers introduced to eliminate the web-only re-implementation
in ``api/routers/inspect.py``: ``connections_result`` / ``module_index_result``
/ ``blocks_result`` in ``app.tools_inspect`` and ``apply_structure_result`` in
``app.tools_xref``.

Each producer returns a status-carrying ``ServiceResult`` on success and RAISES
a ``CapabilityError`` subclass for the hard-error cases the web endpoints used
to translate into HTTP 400/404 responses inline.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
    UnsupportedFormatError,
)
from memdiver.core.service_result import Resolution, ServiceResult  # noqa: E402
from memdiver.mcp_server import tools_inspect, tools_xref  # noqa: E402
from memdiver.mcp_server.session import ToolSession  # noqa: E402
from tests.fixtures.generate_msl_fixtures import generate_msl_file  # noqa: E402


@pytest.fixture
def session():
    return ToolSession()


@pytest.fixture
def msl_path(tmp_path):
    """A rich synthetic MSL carrying module-index / process / connection /
    handle / block content."""
    p = tmp_path / "g3_inspect.msl"
    p.write_bytes(generate_msl_file())
    return str(p)


def _write_plain_msl(path: Path, *, data=b"\xAB" * 4096, base=0x1000):
    from memdiver.msl.writer import MslWriter

    w = MslWriter(path, pid=7)
    w.add_memory_region(base, data)
    w.add_end_of_capture()
    w.write()


# --- connections_result ----------------------------------------------------


def test_connections_result_returns_service_result(session, msl_path):
    result = tools_inspect.connections_result(session, msl_path)
    assert isinstance(result, ServiceResult)
    assert result.status.resolution == Resolution.OK
    conns = result.payload["connections"]
    assert len(conns) == 2
    c0 = conns[0]
    assert c0["pid"] == 1234
    assert c0["family"] == 0x02
    assert c0["protocol"] == 0x06
    assert c0["local_addr"] == "127.0.0.1"
    assert c0["local_port"] == 443
    assert c0["remote_addr"] == "8.8.8.8"
    assert ":" in conns[1]["local_addr"]  # AF_INET6 renders via ipaddress


def test_connections_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.connections_result(session, "/nonexistent/path.msl")


def test_connections_result_non_msl_raises(session, tmp_path):
    p = tmp_path / "not_msl.dump"
    p.write_bytes(b"not msl")
    with pytest.raises(UnsupportedFormatError):
        tools_inspect.connections_result(session, str(p))


# --- module_index_result ---------------------------------------------------


def test_module_index_result_returns_service_result(session, msl_path):
    result = tools_inspect.module_index_result(session, msl_path)
    assert isinstance(result, ServiceResult)
    assert result.status.resolution == Resolution.OK
    entries = result.payload["module_index"]
    assert len(entries) == 2
    assert entries[0]["path"] == "/usr/lib/libssl.so"
    assert entries[0]["base_addr"] == 0x00400000
    assert "module_uuid" in entries[0]


def test_module_index_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.module_index_result(session, "/nonexistent/path.msl")


# --- blocks_result ---------------------------------------------------------


def test_blocks_result_returns_grouped_service_result(session, msl_path):
    result = tools_inspect.blocks_result(session, msl_path)
    assert isinstance(result, ServiceResult)
    assert result.status.resolution == Resolution.OK
    groups = result.payload["blocks"]
    assert isinstance(groups, list)
    assert len(groups) > 0
    for group in groups:
        assert set(group) == {"category", "blocks"}
        for block in group["blocks"]:
            assert set(block) == {"label", "block_type", "offset", "size", "detail"}


def test_blocks_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.blocks_result(session, "/nonexistent/path.msl")


def test_blocks_result_non_msl_raises(session, tmp_path):
    p = tmp_path / "not_msl.txt"
    p.write_text("nope")
    with pytest.raises(UnsupportedFormatError):
        tools_inspect.blocks_result(session, str(p))


# --- apply_structure_result ------------------------------------------------


@pytest.fixture
def big_dump(tmp_path):
    """A plain dump large enough to overlay the smallest TLS13 structure."""
    p = tmp_path / "apply.dump"
    p.write_bytes(bytes(range(256)) * 8)  # 2 KiB
    return str(p)


def test_apply_structure_result_happy_path(session, big_dump):
    result = tools_xref.apply_structure_result(
        session, big_dump, offset=0, structure_name="tls13_early_secret")
    assert isinstance(result, ServiceResult)
    assert result.status.resolution == Resolution.OK
    assert "structure" in result.payload
    assert result.payload["structure"]["offset"] == 0


def test_apply_structure_result_unknown_structure_raises(session, big_dump):
    with pytest.raises(CapabilityError) as exc:
        tools_xref.apply_structure_result(
            session, big_dump, offset=0, structure_name="does_not_exist")
    assert exc.value.category == ErrorCategory.NOT_FOUND
    assert exc.value.status == 404


def test_apply_structure_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_xref.apply_structure_result(
            session, "/nonexistent/path.dump", offset=0,
            structure_name="tls13_early_secret")


def test_apply_structure_result_beyond_boundary_raises(session, tmp_path):
    tiny = tmp_path / "tiny.dump"
    tiny.write_bytes(b"\x00" * 4)  # smaller than any structure
    with pytest.raises(OffsetOutOfRangeError) as exc:
        tools_xref.apply_structure_result(
            session, str(tiny), offset=0, structure_name="tls13_early_secret")
    assert exc.value.status == 400
    assert exc.value.message == "Structure extends beyond file boundary"


# --- web parity: producer payload matches the rerouted endpoints -----------


def test_producers_match_web_endpoint_shapes(session, msl_path):
    """The bare arrays the web endpoints return must equal the extracted
    producer payload lists (byte-identical wire contract preservation)."""
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app

    client = TestClient(create_app())

    for endpoint, key in (
        ("connections", "connections"),
        ("module-index", "module_index"),
        ("blocks", "blocks"),
        ("processes", "processes"),
        ("handles", "handles"),
        ("modules", "modules"),
    ):
        resp = client.get(f"/api/inspect/{endpoint}", params={"msl_path": msl_path})
        assert resp.status_code == 200, endpoint
        producer = getattr(tools_inspect, f"{key}_result")
        assert resp.json() == producer(session, msl_path).payload[key], endpoint
