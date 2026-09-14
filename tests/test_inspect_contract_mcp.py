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


# ── search_bytes: multi-format needles through the REGISTERED tool ───────
#
# Unlike the characterization tests above, these go through the actual
# ``@mcp.tool()`` wrapper in ``mcp_server/server.py``. That matters here: the
# wrapper passes its arguments POSITIONALLY to ``search_bytes_result``, so a
# ``pattern_format`` appended in the wrong position would still type-check,
# still return a plausible JSON string, and silently search the wrong bytes.
# Calling the pure producer could never catch that.


@pytest.fixture
def mcp_search_bytes():
    """The registered ``search_bytes`` tool, or a skip where the SDK is absent.

    Matches the introspection style of the other surface-parity tests
    (``tests/test_api_locate_key.py``, ``tests/test_consensus_regions_surfaces.py``):
    ``create_server()._tool_manager.list_tools()`` → ``tool.fn``.
    """
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    return tools["search_bytes"].fn


@pytest.fixture
def token_dump(tmp_path):
    """A raw dump with ``SECRET`` (ASCII) planted at offset 8."""
    p = tmp_path / "token.dump"
    p.write_bytes(b"\x00" * 8 + b"SECRET" + b"\x00" * 8)
    return str(p)


@pytest.mark.parametrize(
    "pattern, pattern_format",
    [
        pytest.param("SECRET", "text", id="text"),
        pytest.param("534543524554", "hex", id="hex"),
        pytest.param("U0VDUkVU", "base64", id="base64"),
    ],
)
def test_mcp_search_bytes_honours_pattern_format(
    mcp_search_bytes, token_dump, pattern, pattern_format
):
    """Three spellings of the same six bytes, one offset.

    An agent holding a secret rarely holds it as hex — it comes off a key log,
    a JSON config or a protocol field. All three rows must resolve to the same
    ``pattern_hex`` and the same hit, which is also the assertion that pins the
    wrapper's positional forwarding: a ``pattern_format`` landing in the
    ``key_file`` slot would fail every row but the hex one.
    """
    res = json.loads(mcp_search_bytes(
        dump_path=token_dump, pattern_hex=pattern,
        pattern_format=pattern_format))
    assert "error" not in res, res
    assert res["pattern_hex"] == b"SECRET".hex()
    assert res["pattern_format"] == pattern_format
    assert res["offsets"] == [8]
    assert res["count_exact"] is True


def test_mcp_search_bytes_auto_reports_the_resolved_format(
    mcp_search_bytes, token_dump
):
    """``auto`` tells the agent which reading it got, not which it asked for.

    An agent cannot see the search box, so the echoed pair is its ONLY way to
    know whether ``deadbeef`` was read as four bytes or eight characters.
    """
    res = json.loads(mcp_search_bytes(
        dump_path=token_dump, pattern_hex="SECRET", pattern_format="auto"))
    assert res["pattern_format"] == "text"
    assert res["pattern_format_requested"] == "auto"
    assert res["offsets"] == [8]


def test_mcp_search_bytes_defaults_to_hex_not_auto(mcp_search_bytes, token_dump):
    """Back-compat, and the property that keeps an agent predictable.

    Every MCP client written before this change omits ``pattern_format``. The
    default therefore has to be ``hex``: under ``auto``, an odd-length hex
    string — today an explicit error — would become a text search reporting a
    confident "0 hits" for a needle nobody asked for, and an agent has no way
    to notice that.
    """
    ok = json.loads(mcp_search_bytes(
        dump_path=token_dump, pattern_hex="534543524554"))
    assert ok["pattern_format"] == "hex"
    assert ok["pattern_format_requested"] == "hex"
    assert ok["offsets"] == [8]

    bad = json.loads(mcp_search_bytes(dump_path=token_dump, pattern_hex="abc"))
    assert "error" in bad, bad


def test_mcp_search_bytes_invalid_needle_is_an_error_dict_not_a_raise(
    mcp_search_bytes, token_dump
):
    """A bad needle must come back as the legacy ``{"error": ...}`` body.

    An exception escaping the tool is an MCP protocol-level failure the agent
    cannot act on; the error dict tells it exactly what to retype. ``utf16`` is
    the near-miss spelling of a real format, so the message has to name the
    valid ones.
    """
    res = json.loads(mcp_search_bytes(
        dump_path=token_dump, pattern_hex="4142", pattern_format="utf16"))
    assert "error" in res, res
    assert "utf16le" in res["error"]
