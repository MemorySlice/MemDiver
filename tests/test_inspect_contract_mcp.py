"""Characterization tests pinning the MCP inspect surface's CURRENT behavior.

PHASE 0 (additive, test-only): these lock the observable contract of the MCP
inspect tools at the MCP boundary so a later refactor cannot silently change it.

The MCP tool wrappers in ``mcp_server/server.py`` require the ``mcp`` SDK
(not installed in CI), so — exactly as ``tests/test_mcp_new_tools.py`` does —
we exercise the PURE ``mcp_server.tools_inspect`` functions directly. The
server wrappers call those functions WITHOUT passing ``report_key_status``
(relying on its default ``True``) and then ``json.dumps(...)`` the returned
dict. We reproduce that faithfully here: call the tool with no
``report_key_status`` argument, then round-trip the result through
``json.dumps`` / ``json.loads`` to mirror the wrapper's serialization.
"""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.mcp_server import tools_inspect  # noqa: E402
from memdiver.mcp_server.session import ToolSession  # noqa: E402


@pytest.fixture
def session():
    return ToolSession()


def _write_encrypted_msl(path: Path, key: bytes, *, data=b"\xCD" * 4096):
    """Reuse the existing encrypted-.msl construction (MslWriter + AEAD cfg),
    identical to the helper in tests/test_mcp_new_tools.py."""
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    cfg = MslEncryptionConfig(raw_key=key)
    w = MslWriter(path, pid=7, encryption=cfg)
    w.add_memory_region(0x1000, data)
    w.add_end_of_capture()
    w.write()


@pytest.fixture
def encrypted_msl(tmp_path):
    """A raw-key AES-256-GCM encrypted .msl with one captured region."""
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


def _mcp(fn, session, *args, **kwargs):
    """Invoke a tools_inspect fn the way an mcp_server/server.py wrapper does:
    no ``report_key_status`` override (default True) + json.dumps round-trip."""
    return json.loads(json.dumps(fn(session, *args, **kwargs)))


# ── MSL-metadata + decrypted-hex tools flag a missing key (no key) ──────
@pytest.mark.parametrize(
    "invoke",
    [
        pytest.param(lambda s, p: _mcp(tools_inspect.get_session_info, s, p),
                     id="get_session_info"),
        pytest.param(lambda s, p: _mcp(tools_inspect.get_page_states, s, p),
                     id="get_page_states"),
        pytest.param(lambda s, p: _mcp(tools_inspect.get_processes, s, p),
                     id="get_processes"),
        pytest.param(lambda s, p: _mcp(tools_inspect.get_modules, s, p),
                     id="get_modules"),
        pytest.param(lambda s, p: _mcp(tools_inspect.get_handles, s, p),
                     id="get_handles"),
        pytest.param(
            lambda s, p: _mcp(tools_inspect.read_hex, s, p,
                              offset=0, length=64, view="vas"),
            id="read_hex_vas"),
    ],
)
def test_mcp_inspect_without_key_reports_missing_key(session, encrypted_msl, invoke):
    msl_path, _ = encrypted_msl
    res = invoke(session, msl_path)
    assert "error" in res, res
    assert res["tag_status"] == "missing_key"


# ── wrong key → corrupted ───────────────────────────────────────────────
def test_mcp_inspect_with_wrong_key_reports_corrupted(session, encrypted_msl, tmp_path):
    msl_path, _ = encrypted_msl
    wrong = tmp_path / "wrong.bin"
    wrong.write_bytes(b"\x00" * 32)
    res = _mcp(tools_inspect.get_session_info, session, msl_path, key_file=str(wrong))
    assert "error" in res, res
    assert res["tag_status"] == "corrupted"


# ── positive control: the raw container view is keyless by design ───────
def test_mcp_read_hex_raw_view_without_key_still_reads(session, encrypted_msl):
    """Mirrors test_read_hex_raw_view_without_key_still_reads: the keyless raw
    view must NOT error even when no key is supplied."""
    msl_path, _ = encrypted_msl
    res = _mcp(tools_inspect.read_hex, session, msl_path,
               offset=0, length=64, view="raw")
    assert "error" not in res, res
