"""Unit tests for the Phase-1 (G2) ServiceResult producers.

These cover the producers introduced to eliminate the "presentation-in-core"
leak: ``entropy_result`` / ``strings_result`` / ``detect_format_result`` in
``app.tools_inspect`` and ``get_cross_references_result`` /
``identify_structure_result`` in ``app.tools_xref``.

Each producer returns a status-carrying ``ServiceResult`` on success and RAISES
a ``CapabilityError`` subclass for the hard-error cases the legacy shims used to
return as ``{"error": ...}`` dicts. The deprecated shims are exercised too, to
lock the "shim renders the legacy dict" backward-compatibility contract.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import (  # noqa: E402
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
)
from memdiver.core.service_result import Resolution, ServiceResult  # noqa: E402
from memdiver.mcp_server import tools_inspect, tools_xref  # noqa: E402
from memdiver.mcp_server.session import ToolSession  # noqa: E402


@pytest.fixture
def session():
    return ToolSession()


@pytest.fixture
def dump(tmp_path):
    """A plain (non-MSL) dump with a printable string, for the keyless path."""
    p = tmp_path / "sample.dump"
    p.write_bytes(b"hello world\x00" + bytes(range(256)) * 4)
    return str(p)


def _write_plain_msl(path: Path, *, data=b"\xAB" * 4096, base=0x1000):
    from memdiver.msl.writer import MslWriter

    w = MslWriter(path, pid=7)
    w.add_memory_region(base, data)
    w.add_end_of_capture()
    w.write()


# --- entropy_result --------------------------------------------------------


def test_entropy_result_returns_service_result(session, dump):
    result = tools_inspect.entropy_result(session, dump)
    assert isinstance(result, ServiceResult)
    assert result.status.resolution == Resolution.OK
    assert "overall_entropy" in result.payload
    assert "stats" in result.payload


def test_entropy_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.entropy_result(session, "/nonexistent/path.dump")


def test_entropy_result_offset_out_of_range_raises(session, dump):
    with pytest.raises(OffsetOutOfRangeError) as exc:
        tools_inspect.entropy_result(session, dump, offset=10**9)
    assert exc.value.message == "offset out of range"
    assert set(exc.value.details) == {"offset", "file_size"}


def test_entropy_result_payload_matches_legacy_shim(session, dump):
    result = tools_inspect.entropy_result(session, dump)
    legacy = tools_inspect.get_entropy(session, dump)
    assert result.payload == legacy


def test_get_entropy_shim_missing_file_returns_error_dict(session):
    res = tools_inspect.get_entropy(session, "/nonexistent/path.dump")
    assert res == {"error": "File not found: /nonexistent/path.dump"}


# --- strings_result --------------------------------------------------------


def test_strings_result_returns_service_result(session, dump):
    result = tools_inspect.strings_result(session, dump)
    assert isinstance(result, ServiceResult)
    assert result.status.resolution == Resolution.OK
    assert "strings" in result.payload
    assert any(s["value"] == "hello world" for s in result.payload["strings"])


def test_strings_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.strings_result(session, "/nonexistent/path.dump")


def test_strings_result_payload_matches_legacy_shim(session, dump):
    result = tools_inspect.strings_result(session, dump)
    legacy = tools_inspect._extract_strings(session, dump)
    assert result.payload == legacy


# --- detect_format_result --------------------------------------------------


def test_detect_format_result_returns_service_result(session, tmp_path):
    msl = tmp_path / "plain.msl"
    _write_plain_msl(msl)
    result = tools_inspect.detect_format_result(session, str(msl))
    assert isinstance(result, ServiceResult)
    # raw view is keyless by design → clean/decrypted status
    assert result.status.resolution == Resolution.OK
    assert result.payload["format"] == "msl"
    assert result.payload["detected_format"] == "msl"


def test_detect_format_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.detect_format_result(session, "/nonexistent/path.msl")


def test_detect_format_result_offset_out_of_range_raises(session, dump):
    with pytest.raises(OffsetOutOfRangeError) as exc:
        tools_inspect.detect_format_result(session, dump, offset=10**9)
    assert exc.value.message == "offset out of range"
    assert set(exc.value.details) == {"offset", "file_size"}


def test_detect_format_result_payload_matches_legacy_shim(session, tmp_path):
    msl = tmp_path / "plain.msl"
    _write_plain_msl(msl)
    result = tools_inspect.detect_format_result(session, str(msl))
    legacy = tools_inspect.detect_format(session, str(msl))
    assert result.payload == legacy


# --- get_cross_references_result -------------------------------------------


def test_get_cross_references_result_returns_service_result(session, tmp_path):
    msl = tmp_path / "plain.msl"
    _write_plain_msl(msl)
    result = tools_xref.get_cross_references_result(session, str(msl))
    assert isinstance(result, ServiceResult)
    assert result.status.resolution == Resolution.OK
    assert "dump_uuid" in result.payload
    assert "cross_references" in result.payload


def test_get_cross_references_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_xref.get_cross_references_result(session, "/nonexistent/path.msl")


def test_get_cross_references_result_payload_matches_legacy_shim(session, tmp_path):
    msl = tmp_path / "plain.msl"
    _write_plain_msl(msl)
    result = tools_xref.get_cross_references_result(session, str(msl))
    legacy = tools_xref.get_cross_references(session, str(msl))
    assert result.payload == legacy


# --- identify_structure_result ---------------------------------------------


def test_identify_structure_result_returns_service_result(session, dump):
    result = tools_xref.identify_structure_result(session, dump, offset=0)
    assert isinstance(result, ServiceResult)
    assert result.status.resolution == Resolution.OK
    # Either a match payload or a legitimate no-match reason — never an error.
    assert "match" in result.payload
    assert "error" not in result.payload


def test_identify_structure_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_xref.identify_structure_result(session, "/nonexistent/path.dump")


def test_identify_structure_result_offset_out_of_range_raises(session, dump):
    with pytest.raises(OffsetOutOfRangeError) as exc:
        tools_xref.identify_structure_result(session, dump, offset=10**9)
    assert exc.value.message == "offset out of range"
    assert set(exc.value.details) == {"offset", "file_size"}


def test_identify_structure_shim_missing_file_returns_error_dict(session):
    res = tools_xref.identify_structure(session, "/nonexistent/path.dump")
    assert res == {"error": "File not found: /nonexistent/path.dump"}
