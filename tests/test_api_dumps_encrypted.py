"""REST import surface for ENCRYPTED .msl: key material in the POST body /
form, re-encrypted materialized copy by default, plaintext on opt-in."""

from __future__ import annotations

from pathlib import Path

import pytest

from memdiver.msl.enums import TagStatus
from memdiver.msl.importer import DECRYPTED_OUTPUT_WARNING
from memdiver.msl.reader import MslReader
from memdiver.msl.writer import MslEncryptionConfig

from tests.test_api_dumps import client, isolated_env  # noqa: F401 (fixtures)
from tests.test_msl_materialize import _writer_built_msl

RAW_KEY = bytes(range(32))
KEY_HEX = RAW_KEY.hex()
KEPT = {0x10000000, 0x7FFF0000}


@pytest.fixture
def enc_msl(tmp_path) -> Path:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    return _writer_built_msl(src_dir, encryption=MslEncryptionConfig(
        raw_key=RAW_KEY))


def _bases(path: Path, **km) -> set:
    with MslReader(path, **km) as r:
        assert r.tag_status in (TagStatus.VALID, TagStatus.NOT_ENCRYPTED)
        return {g.base_addr for g in r.collect_regions()}


def test_preview_with_key_lists_regions(client, enc_msl):
    locked = client.post("/api/dumps/preview", json={"path": str(enc_msl)})
    assert locked.status_code == 200, locked.text
    assert locked.json()["encrypted"] and not locked.json()["decrypted"]
    assert locked.json()["regions"] == []
    r = client.post("/api/dumps/preview",
                    json={"path": str(enc_msl), "key_hex": KEY_HEX})
    body = r.json()
    assert body["encrypted"] and body["decrypted"]
    assert len(body["regions"]) == 3


def test_preview_bad_hex_is_400(client, enc_msl):
    r = client.post("/api/dumps/preview",
                    json={"path": str(enc_msl), "key_hex": "zz"})
    assert r.status_code == 400


def test_import_path_materialize_reencrypts(client, enc_msl, tmp_path):
    out_dir = tmp_path / "uploads"
    r = client.post("/api/dumps/import-path", json={
        "path": str(enc_msl), "output_dir": str(out_dir),
        "regions": "heap,stack", "materialize": True, "key_hex": KEY_HEX})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["materialized"] and body["reencrypted"]
    assert body["decrypted_output"] is False
    out = Path(body["output"])
    with MslReader(out) as locked:
        assert locked.tag_status is TagStatus.MISSING_KEY
    assert _bases(out, key=RAW_KEY) == KEPT


def test_import_path_decrypt_output_plaintext_with_warning(client, enc_msl,
                                                          tmp_path):
    r = client.post("/api/dumps/import-path", json={
        "path": str(enc_msl), "output_dir": str(tmp_path / "uploads"),
        "regions": "heap,stack", "materialize": True, "key_hex": KEY_HEX,
        "decrypt_output": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decrypted_output"] and not body["reencrypted"]
    assert DECRYPTED_OUTPUT_WARNING in body["warnings"]
    assert _bases(Path(body["output"])) == KEPT


@pytest.mark.parametrize("extra", [{"key_hex": "02" * 32}, {}])
def test_import_path_wrong_or_missing_key_is_400(client, enc_msl, tmp_path,
                                                 extra):
    out_dir = tmp_path / "uploads"
    r = client.post("/api/dumps/import-path", json={
        "path": str(enc_msl), "output_dir": str(out_dir),
        "regions": "heap,stack", "materialize": True, **extra})
    assert r.status_code == 400
    assert "cannot materialize encrypted" in r.text
    assert "02" * 32 not in r.text
    assert not list(out_dir.glob("*.msl"))


def test_upload_with_form_key_fields(client, enc_msl):
    r = client.post(
        "/api/dumps/upload",
        files={"file": ("enc.msl", enc_msl.read_bytes(),
                        "application/octet-stream")},
        data={"regions": "heap,stack", "materialize": "true",
              "key_hex": KEY_HEX})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reencrypted"]
    assert _bases(Path(body["output"]), key=RAW_KEY) == KEPT


def test_upload_key_in_query_string_is_ignored(client, enc_msl):
    """Key material is read from the form body only, never the URL."""
    r = client.post(
        f"/api/dumps/upload?key_hex={KEY_HEX}",
        files={"file": ("enc.msl", enc_msl.read_bytes(),
                        "application/octet-stream")},
        data={"regions": "heap,stack", "materialize": "true"})
    assert r.status_code == 400
