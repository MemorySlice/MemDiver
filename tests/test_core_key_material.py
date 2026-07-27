"""Unit tests for the canonical key-material decoders in core.key_material.

These pin the two input idioms the surface adapters delegate to:
``from_files`` (CLI/app/MCP file-path inputs) and ``from_hex`` (HTTP wire
inputs), including the divergent empty-return + error contracts each surface
relies on.
"""

import os

import pytest

from memdiver.core.key_material import from_files, from_hex
from memdiver.core.service_errors import CapabilityError, ErrorCategory


# ── from_files (CLI / app / MCP file-path idiom) ─────────────────────
def test_from_files_reads_key_and_encodes_passphrase(tmp_path):
    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    km = from_files(str(keyfile), "pw", None)
    assert km == {"key": key, "passphrase": b"pw", "kem_private_key": None}


def test_from_files_reads_kem_key(tmp_path):
    kem = os.urandom(32)
    kemfile = tmp_path / "kem.bin"
    kemfile.write_bytes(kem)
    km = from_files(None, None, str(kemfile))
    assert km == {"key": None, "passphrase": None, "kem_private_key": kem}


def test_from_files_empty_is_all_none_dict():
    assert from_files() == {
        "key": None,
        "passphrase": None,
        "kem_private_key": None,
    }


def test_from_files_empty_passphrase_is_none():
    # A falsy passphrase must become None, never empty bytes.
    assert from_files(None, "", None)["passphrase"] is None


# ── from_hex (HTTP wire idiom) ───────────────────────────────────────
def test_from_hex_decodes_hex_and_encodes_passphrase():
    key = os.urandom(16)
    km = from_hex("pw", key.hex(), None)
    assert km == {"key": key, "passphrase": b"pw", "kem_private_key": None}


def test_from_hex_decodes_kem_key():
    kem = os.urandom(16)
    km = from_hex(None, None, kem.hex())
    assert km == {"key": None, "passphrase": None, "kem_private_key": kem}


def test_from_hex_empty_returns_none():
    # None (not an all-None dict) so callers can splat ``**(km or {})``.
    assert from_hex() is None
    assert from_hex(None, None, None) is None


def test_from_hex_bad_key_hex_raises_capability_error():
    with pytest.raises(CapabilityError) as exc:
        from_hex(None, "not-hex", None)
    assert exc.value.message == "Invalid key material encoding"
    assert exc.value.category is ErrorCategory.INVALID_INPUT


def test_from_hex_bad_kem_hex_raises_capability_error():
    with pytest.raises(CapabilityError):
        from_hex(None, None, "zz")
