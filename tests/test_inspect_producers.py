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
    FileNotFoundServiceError,
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


# The six producers that today return an error dict for an unkeyed encrypted
# container. read_hex_result must be exercised with view="vas" (the raw view
# is keyless and never gates).
_MSL_METADATA_PRODUCERS = [
    "session_info_result",
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
