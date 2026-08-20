"""Unit tests for the step-2a ServiceResult producers in tools_inspect.

The nine ``<publicname>_result`` producers ALWAYS carry a status block: where
the legacy ``get_*`` / ``read_hex`` siblings returned an error dict for an
encrypted-but-unkeyed container, the producers still perform the read and
report the lock purely through ``status.key`` / ``status.resolution``. Hard
errors (missing file, wrong format) are RAISED as CapabilityError subclasses.

These call the PURE ``mcp_server.tools_inspect`` producers directly (never via
FastMCP) and reuse the encrypted-.msl fixture style from
``tests/test_mcp_new_tools.py`` (MslWriter + MslEncryptionConfig(raw_key=...)).
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
    UnsupportedFormatError,
)
from memdiver.core.service_result import Resolution  # noqa: E402
from memdiver.mcp_server import tools_inspect  # noqa: E402
from memdiver.mcp_server.session import ToolSession  # noqa: E402
from memdiver.msl.enums import TagStatus  # noqa: E402


@pytest.fixture
def session():
    return ToolSession()


def _write_plain_msl(path: Path, *, data=b"\xAB" * 4096, base=0x1000):
    from memdiver.msl.writer import MslWriter

    w = MslWriter(path, pid=7)
    w.add_memory_region(base, data)
    w.add_end_of_capture()
    w.write()


def _write_encrypted_msl(path: Path, key: bytes, *, data=b"\xCD" * 4096):
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    cfg = MslEncryptionConfig(raw_key=key)
    w = MslWriter(path, pid=7, encryption=cfg)
    w.add_memory_region(0x1000, data)
    w.add_end_of_capture()
    w.write()


@pytest.fixture
def encrypted_msl(tmp_path):
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    msl = tmp_path / "enc.msl"
    _write_encrypted_msl(msl, key)
    return str(msl), str(keyfile)


@pytest.fixture
def plain_msl(tmp_path):
    msl = tmp_path / "plain.msl"
    _write_plain_msl(msl)
    return str(msl)


@pytest.fixture
def raw_dump(tmp_path):
    """A plain (non-MSL) raw dump file, for the VA-on-non-msl raise path."""
    dump = tmp_path / "plain.dump"
    dump.write_bytes(b"\x00" * 1024)
    return str(dump)


# The six producers that today return an error dict for an unkeyed encrypted
# container. read_hex_result must be exercised with view="vas" (the raw view
# is keyless and never gates).
_MSL_METADATA_PRODUCERS = [
    "session_info_result",
    "vas_regions_result",
    "page_states_result",
    "processes_result",
    "modules_result",
    "handles_result",
]


@pytest.mark.parametrize("fn_name", _MSL_METADATA_PRODUCERS)
def test_metadata_producer_without_key_reports_missing_key(session, encrypted_msl, fn_name):
    msl_path, _ = encrypted_msl
    result = getattr(tools_inspect, fn_name)(session, msl_path)
    assert result.status.key.tag_status == TagStatus.MISSING_KEY
    assert result.status.key.decrypted is False
    assert result.status.resolution == Resolution.UNRESOLVED


def test_read_hex_result_vas_without_key_reports_missing_key(session, encrypted_msl):
    msl_path, _ = encrypted_msl
    result = tools_inspect.read_hex_result(
        session, msl_path, offset=0, length=64, view="vas")
    assert result.status.key.tag_status == TagStatus.MISSING_KEY
    assert result.status.key.decrypted is False
    assert result.status.resolution == Resolution.UNRESOLVED


@pytest.mark.parametrize("fn_name", ["read_hex_result", "read_hex_raw_result"])
def test_read_hex_locked_vas_nonzero_offset_reports_missing_key(
    session, encrypted_msl, fn_name
):
    """Regression (code-review): a locked ``vas`` view must surface the key lock
    BEFORE the offset-bounds check. ``size_for("vas")`` is 0 for an unkeyed
    encrypted dump, so a nonzero offset previously raised a misleading
    ``OffsetOutOfRangeError`` on CLI/MCP instead of reporting ``missing_key``
    (the legacy ``read_hex`` ran the tag-status guard first)."""
    msl_path, _ = encrypted_msl
    result = getattr(tools_inspect, fn_name)(
        session, msl_path, offset=64, length=64, view="vas")
    assert result.status.key.tag_status == TagStatus.MISSING_KEY
    assert result.status.key.decrypted is False
    assert result.status.resolution == Resolution.UNRESOLVED


@pytest.mark.parametrize("fn_name", _MSL_METADATA_PRODUCERS)
def test_metadata_producer_with_wrong_key_reports_corrupted(session, encrypted_msl, tmp_path, fn_name):
    msl_path, _ = encrypted_msl
    wrong = tmp_path / "wrong.bin"
    wrong.write_bytes(b"\x00" * 32)
    result = getattr(tools_inspect, fn_name)(session, msl_path, key_file=str(wrong))
    assert result.status.key.tag_status == TagStatus.CORRUPTED
    assert result.status.key.decrypted is False
    assert result.status.resolution == Resolution.UNRESOLVED


def test_read_hex_result_raw_view_without_key_is_decrypted(session, encrypted_msl):
    """The raw container view is keyless by design: no lock, resolution OK."""
    msl_path, _ = encrypted_msl
    result = tools_inspect.read_hex_result(
        session, msl_path, offset=0, length=64, view="raw")
    assert result.status.key.decrypted is True
    assert result.status.resolution == Resolution.OK


def test_metadata_producer_with_key_is_ok(session, encrypted_msl):
    msl_path, keyfile = encrypted_msl
    result = tools_inspect.session_info_result(session, msl_path, key_file=keyfile)
    assert result.status.key.decrypted is True
    assert result.status.resolution == Resolution.OK
    assert result.payload["region_count"] == 1
    assert result.payload["pid"] == 7


def test_plaintext_msl_producer_is_ok(session, plain_msl):
    result = tools_inspect.session_info_result(session, plain_msl)
    assert result.status.resolution == Resolution.OK
    assert result.status.key.decrypted is True
    assert result.payload["pid"] == 7


@pytest.fixture
def msl_with_vas(tmp_path):
    """A complete synthetic .msl carrying a VAS_MAP block (three entries)."""
    from tests.fixtures.generate_msl_fixtures import write_msl_fixture

    return str(write_msl_fixture(tmp_path / "vas.msl"))


def test_vas_regions_result_emits_full_five_field_entries(session, msl_with_vas):
    """The VAS producer emits the FULL five-field entries the VasChart consumes,
    plus the region_count / total_region_size / vas_coverage summary fields."""
    result = tools_inspect.vas_regions_result(session, msl_with_vas)
    assert result.status.resolution == Resolution.OK
    assert result.status.key.decrypted is True

    payload = result.payload
    assert payload["region_count"] >= 1
    assert isinstance(payload["total_region_size"], int)
    assert isinstance(payload["vas_coverage"], dict)

    entries = payload["vas_entries"]
    assert len(entries) >= 1
    # The summary counts describe the VAS entries themselves (not the captured
    # regions session_info counts), so they stay consistent with the array.
    assert payload["region_count"] == len(entries)
    assert payload["total_region_size"] == sum(e["region_size"] for e in entries)
    for entry in entries:
        assert set(entry) == {
            "base_addr", "region_size", "region_type", "protection", "mapped_path",
        }
    # The fixture seeds a libssl mapping at the canonical base (base/size/type/prot).
    libssl = next(e for e in entries if e["mapped_path"] == "/usr/lib/libssl.so")
    assert libssl["base_addr"] == 0x00400000
    assert libssl["region_size"] == 0x10000
    assert libssl["region_type"] == 0x03
    assert libssl["protection"] == 0x05


def test_read_hex_result_plaintext_vas_is_ok(session, plain_msl):
    result = tools_inspect.read_hex_result(
        session, plain_msl, offset=0, length=64, view="vas")
    assert result.status.resolution == Resolution.OK
    assert result.status.key.decrypted is True


def test_producer_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.session_info_result(session, "/nonexistent/path.msl")


def test_producer_non_msl_suffix_raises(session, tmp_path):
    txt = tmp_path / "not_a_dump.txt"
    txt.write_text("hello")
    with pytest.raises(UnsupportedFormatError):
        tools_inspect.session_info_result(session, str(txt))


# ── hard-error raise paths (missing file / bad format / offset / pattern) ──


@pytest.mark.parametrize(
    "fn_name",
    ["read_hex_result", "read_hex_raw_result", "search_bytes_result"],
)
def test_dump_producer_file_not_found_raises(session, fn_name):
    fn = getattr(tools_inspect, fn_name)
    kwargs = {"pattern_hex": "ab"} if fn_name == "search_bytes_result" else {}
    with pytest.raises(FileNotFoundServiceError):
        fn(session, "/nonexistent/path.dump", **kwargs)


def test_resolve_va_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.resolve_va_result(session, "/nonexistent/path.msl", va=0x1000)


def test_resolve_va_result_non_msl_raises(session, raw_dump):
    """VA translation on a non-MSL dump raises UnsupportedFormatError,
    mirroring the legacy ``{"error": "VA translation requires an MSL dump"}``."""
    with pytest.raises(UnsupportedFormatError, match="VA translation requires an MSL dump"):
        tools_inspect.resolve_va_result(session, raw_dump, va=0x1000)


def test_read_hex_result_offset_out_of_range_raises(session, plain_msl):
    with pytest.raises(OffsetOutOfRangeError) as exc_info:
        tools_inspect.read_hex_result(session, plain_msl, offset=10**9, length=64, view="vas")
    err = exc_info.value
    assert err.message == "offset out of range"
    assert set(err.details) == {"offset", "file_size", "view", "format"}
    assert err.details["offset"] == 10**9
    assert err.details["view"] == "vas"


def test_read_hex_raw_result_offset_out_of_range_raises(session, plain_msl):
    with pytest.raises(OffsetOutOfRangeError) as exc_info:
        tools_inspect.read_hex_raw_result(session, plain_msl, offset=10**9, length=64, view="vas")
    err = exc_info.value
    assert err.message == "offset out of range"
    assert set(err.details) == {"offset", "file_size", "view", "format"}


def test_read_hex_result_negative_offset_raises(session, plain_msl):
    with pytest.raises(OffsetOutOfRangeError):
        tools_inspect.read_hex_result(session, plain_msl, offset=-1, length=64, view="vas")


@pytest.mark.parametrize("pattern_hex", ["", "   ", "0x"])
def test_search_bytes_result_empty_pattern_raises(session, plain_msl, pattern_hex):
    with pytest.raises(CapabilityError, match="Empty byte pattern"):
        tools_inspect.search_bytes_result(session, plain_msl, pattern_hex=pattern_hex)


def test_search_bytes_result_invalid_hex_raises(session, plain_msl):
    with pytest.raises(CapabilityError, match="Invalid hex byte pattern"):
        tools_inspect.search_bytes_result(session, plain_msl, pattern_hex="zz")


def test_search_bytes_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.search_bytes_result(session, "/nonexistent/path.dump", pattern_hex="ab")


# ── producer/legacy payload parity (plaintext MSL, no lock in play) ────────


def test_session_info_result_payload_matches_legacy(session, plain_msl):
    """Locks producer/legacy equivalence: the ServiceResult payload is
    byte-for-byte identical to the legacy dict (minus report_key_status)."""
    result = tools_inspect.session_info_result(session, plain_msl)
    legacy = tools_inspect.get_session_info(session, plain_msl, report_key_status=False)
    assert result.payload == legacy


def test_read_hex_result_vas_payload_matches_legacy(session, plain_msl):
    result = tools_inspect.read_hex_result(
        session, plain_msl, offset=0, length=64, view="vas")
    legacy = tools_inspect.read_hex(
        session, plain_msl, offset=0, length=64, view="vas", report_key_status=False)
    assert result.payload == legacy


def test_read_hex_raw_result_vas_payload_matches_legacy(session, plain_msl):
    result = tools_inspect.read_hex_raw_result(
        session, plain_msl, offset=0, length=64, view="vas")
    legacy = tools_inspect._read_hex_raw(
        session, plain_msl, offset=0, length=64, view="vas", report_key_status=False)
    assert result.payload == legacy


def test_search_bytes_result_payload_matches_legacy(session, plain_msl):
    result = tools_inspect.search_bytes_result(
        session, plain_msl, pattern_hex="ab", view="vas")
    legacy = tools_inspect.search_bytes(
        session, plain_msl, pattern_hex="ab", view="vas", report_key_status=False)
    assert result.payload == legacy


def test_resolve_va_result_payload_matches_legacy(session, plain_msl):
    result = tools_inspect.resolve_va_result(session, plain_msl, va=0x1000)
    legacy = tools_inspect._resolve_va(
        session, plain_msl, va=0x1000, report_key_status=False)
    assert result.payload == legacy


@pytest.mark.parametrize(
    "result_fn_name, legacy_fn_name",
    [
        ("page_states_result", "get_page_states"),
        ("processes_result", "get_processes"),
        ("modules_result", "get_modules"),
        ("handles_result", "get_handles"),
    ],
)
def test_metadata_producer_payload_matches_legacy(
    session, plain_msl, result_fn_name, legacy_fn_name
):
    result_fn = getattr(tools_inspect, result_fn_name)
    legacy_fn = getattr(tools_inspect, legacy_fn_name)
    result = result_fn(session, plain_msl)
    legacy = legacy_fn(session, plain_msl, report_key_status=False)
    assert result.payload == legacy


# ── analyze_region_result (new producer) ───────────────────────────────────


@pytest.fixture
def region_dump(tmp_path):
    """A raw dump with a printable string embedded near the middle."""
    data = bytes(range(256)) * 2 + b"PRIVATE_KEY_MARKER" + b"\xff" * 100
    dump = tmp_path / "region.dump"
    dump.write_bytes(data)
    return str(dump), data


def test_analyze_region_result_payload_matches_core(session, region_dump):
    """Single-source parity: the producer payload equals a direct
    core.region_analysis.analyze_region run over the same bytes."""
    from memdiver.core.region_analysis import analyze_region

    dump_path, data = region_dump
    offset = len(data) // 2
    result = tools_inspect.analyze_region_result(session, dump_path, offset)

    report = analyze_region(data, offset, window=64)
    assert result.payload["offset"] == report.offset
    assert result.payload["byte_value"] == report.byte_value
    assert result.payload["entropy"] == round(report.entropy, 4)
    assert result.payload["entropy_level"] == report.entropy_level
    assert result.payload["neighborhood_hex"] == report.neighborhood.hex()
    assert result.payload["strings"] == [
        {"offset": st.offset, "value": st.value,
         "encoding": st.encoding, "length": st.length}
        for st in report.strings
    ]
    # No variance/hits supplied on the path-based producer.
    assert result.payload["variance_at_offset"] is None
    assert result.payload["matching_secrets"] == []


def test_analyze_region_result_status_is_ok_for_raw(session, region_dump):
    dump_path, _ = region_dump
    result = tools_inspect.analyze_region_result(session, dump_path, 0)
    assert result.status.resolution == Resolution.OK
    assert result.status.key.decrypted is True


def test_analyze_region_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.analyze_region_result(session, "/nonexistent/path.dump", 0)


def test_analyze_region_result_offset_out_of_range_raises(session, region_dump):
    dump_path, data = region_dump
    with pytest.raises(OffsetOutOfRangeError):
        tools_inspect.analyze_region_result(session, dump_path, len(data))


def test_analyze_region_result_negative_offset_raises(session, region_dump):
    dump_path, _ = region_dump
    with pytest.raises(OffsetOutOfRangeError):
        tools_inspect.analyze_region_result(session, dump_path, -1)
