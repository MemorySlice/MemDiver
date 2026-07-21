"""Inspect an encrypted ``.msl`` container through the HTTP API (spec §10).

Asserts that the ``/api/inspect`` read endpoints can decrypt an AEAD
container when the caller supplies key material (as ``passphrase`` /
``key_hex`` / ``kem_key_hex`` query params — the same shape the keyed
``POST /api/inspect/tag-status`` uses) and read back nothing but a locked
state when no key is supplied.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from memdiver.api.main import create_app
from memdiver.api.services.reader_cache import MslReaderCache, set_default_cache
from memdiver.msl import crypto
from memdiver.msl.enums import EncAlgo, KdfType, KeyEncap
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

_REGION_BASE = 0x1000
_REGION_DATA = b"\xAB" * 4096


@pytest.fixture
def client():
    # Isolate the process-wide reader cache so a prior unkeyed open of the
    # same path never leaks into (or out of) this test.
    set_default_cache(MslReaderCache())
    try:
        yield TestClient(create_app())
    finally:
        set_default_cache(MslReaderCache())


@pytest.fixture
def encrypted_msl(tmp_path):
    """A raw-key AES-256-GCM encrypted .msl with one captured region."""
    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    out = tmp_path / "encrypted.msl"
    cfg = MslEncryptionConfig(
        enc_algo=EncAlgo.AES_256_GCM, kdf_type=KdfType.NONE,
        key_encap=KeyEncap.NONE, raw_key=key,
    )
    w = MslWriter(out, pid=7, encryption=cfg)
    w.add_memory_region(_REGION_BASE, _REGION_DATA)
    w.add_end_of_capture()
    w.write()
    return str(out), key.hex()


# -- session-info: real data with the key, locked (empty) without ------


def test_session_info_locked_without_key(client, encrypted_msl):
    path, _ = encrypted_msl
    resp = client.get("/api/inspect/session-info", params={"msl_path": path})
    assert resp.status_code == 200
    # Encrypted-and-locked: the block stream is unreadable, so no regions
    # surface. This is the clear "locked" signal the UI keys off.
    assert resp.json()["region_count"] == 0


def test_session_info_readable_with_key(client, encrypted_msl):
    path, key_hex = encrypted_msl
    resp = client.get(
        "/api/inspect/session-info",
        params={"msl_path": path, "key_hex": key_hex},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["pid"] == 7
    assert body["region_count"] == 1
    assert body["captured_page_count"] > 0


# -- hex (VAS projection): captured bytes only appear once decrypted -----


def test_hex_vas_empty_without_key(client, encrypted_msl):
    path, _ = encrypted_msl
    resp = client.get(
        "/api/inspect/hex",
        params={"dump_path": path, "view": "vas", "offset": 0, "length": 64},
    )
    assert resp.status_code == 200
    assert resp.json()["length"] == 0


def test_hex_vas_decrypts_with_key(client, encrypted_msl):
    path, key_hex = encrypted_msl
    resp = client.get(
        "/api/inspect/hex",
        params={
            "dump_path": path, "view": "vas", "offset": 0, "length": 64,
            "key_hex": key_hex,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["length"] == 64
    # The captured region is all 0xAB.
    assert all("ab ab ab" in line for line in body["hex_lines"])


# -- processes/table endpoints also honor the key ------------------------


def test_tag_status_get_vs_keyed(client, encrypted_msl):
    path, key_hex = encrypted_msl
    # Unkeyed GET can only report missing_key for an encrypted container.
    resp = client.get("/api/inspect/tag-status", params={"msl_path": path})
    assert resp.status_code == 200
    assert resp.json()["tag_status"] == "missing_key"
    # Keyed POST verifies the AEAD tag.
    resp = client.post(
        "/api/inspect/tag-status",
        json={"msl_path": path, "key_hex": key_hex},
    )
    assert resp.status_code == 200
    assert resp.json()["tag_status"] == "valid"


def test_bad_key_encoding_is_400(client, encrypted_msl):
    path, _ = encrypted_msl
    resp = client.get(
        "/api/inspect/session-info",
        params={"msl_path": path, "key_hex": "nothex!!"},
    )
    assert resp.status_code == 400
