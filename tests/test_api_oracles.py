"""Tests for api.services.oracle_registry + api.routers.oracles.

Covers Phase 25 B5: upload, arm-by-sha256, dry-run, delete, 503 when
MEMDIVER_ORACLE_DIR is unset, and the pycache-poisoning mitigation.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
from pathlib import Path

import pytest

from api.services.oracle_registry import (
    OracleDisabled,
    OracleNotFound,
    OracleRegistry,
    OracleRegistryError,
    OracleShaMismatch,
    reset_oracle_registry,
)


# A Shape-1 oracle that only passes on a specific sentinel.
ORACLE_SHAPE1 = """\
SENTINEL = bytes(range(16))

def verify(candidate):
    return candidate == SENTINEL
"""


# A Shape-2 oracle that exposes a class + build_oracle factory.
ORACLE_SHAPE2 = """\
class MyOracle:
    def __init__(self, cfg):
        self.tag = cfg.get("tag", b"magic!") if isinstance(cfg, dict) else b"magic!"
        if isinstance(self.tag, str):
            self.tag = self.tag.encode()
    def verify(self, candidate):
        return candidate == self.tag

def build_oracle(cfg):
    return MyOracle(cfg)
"""


@pytest.fixture
def examples_dir():
    return Path(__file__).parent.parent / "docs" / "oracle_examples"


@pytest.fixture
def registry(tmp_path, examples_dir):
    reg = OracleRegistry(oracle_dir=tmp_path / "oracles", examples_dir=examples_dir)
    yield reg
    reset_oracle_registry()


@pytest.fixture
def disabled_registry(tmp_path, examples_dir):
    reg = OracleRegistry(oracle_dir=None, examples_dir=examples_dir)
    yield reg
    reset_oracle_registry()


# ---------- examples enumeration ----------


def test_list_examples_returns_bundled_oracles(registry, examples_dir):
    examples = registry.list_examples()
    names = {e["filename"] for e in examples}
    # All three example oracles from the Phase 25 DFRWS deliverables.
    assert {"gocryptfs.py", "generic_aes_gcm.py", "tls13_stub.py"} <= names
    for ex in examples:
        assert ex["shape"] in (1, 2)
        assert len(ex["sha256"]) == 64


def test_list_examples_works_when_disabled(disabled_registry):
    # examples don't require an oracle_dir to be configured
    examples = disabled_registry.list_examples()
    assert len(examples) >= 3


# ---------- upload / shape detection ----------


def test_upload_shape1(registry):
    entry = registry.upload(filename="my.py", content=ORACLE_SHAPE1.encode())
    assert entry.shape == 1
    assert entry.sha256 == hashlib.sha256(ORACLE_SHAPE1.encode()).hexdigest()
    assert entry.armed is False
    # On-disk file is locked down to 0o600.
    mode = entry.path.stat().st_mode & 0o777
    assert mode == 0o600
    # head_lines preserved
    assert any("verify" in ln for ln in entry.head_lines)


def test_upload_shape2(registry):
    entry = registry.upload(filename="stateful.py", content=ORACLE_SHAPE2.encode())
    assert entry.shape == 2


def test_upload_disabled_raises(disabled_registry):
    with pytest.raises(OracleDisabled):
        disabled_registry.upload(filename="x.py", content=ORACLE_SHAPE1.encode())


def test_upload_broken_oracle_rejected(registry):
    with pytest.raises(OracleRegistryError):
        registry.upload(filename="broken.py", content=b"this is not python(((")


def test_upload_purges_pycache(registry, tmp_path):
    # Upload, create a rogue __pycache__ next to it, then re-detect
    # shape via list_entries; the pycache should not cause a load.
    entry = registry.upload(filename="s1.py", content=ORACLE_SHAPE1.encode())
    cache_dir = entry.path.parent / "__pycache__"
    cache_dir.mkdir(exist_ok=True)
    (cache_dir / "poisoned.cpython-314.pyc").write_bytes(b"\x00" * 32)
    # arm re-hashes and purges the cache; this should still succeed.
    armed = registry.arm(entry.oracle_id, entry.sha256)
    assert armed.armed is True
    assert not cache_dir.exists()


# ---------- arm sha256 echo ----------


def test_arm_rejects_mismatched_sha(registry):
    entry = registry.upload(filename="s.py", content=ORACLE_SHAPE1.encode())
    bogus = "0" * 64
    with pytest.raises(OracleShaMismatch):
        registry.arm(entry.oracle_id, bogus)
    assert registry.get(entry.oracle_id).armed is False


def test_arm_accepts_matching_sha(registry):
    entry = registry.upload(filename="s.py", content=ORACLE_SHAPE1.encode())
    armed = registry.arm(entry.oracle_id, entry.sha256)
    assert armed.armed is True
    # Subsequent require_armed() returns without raising.
    registry.require_armed(entry.oracle_id)


def test_arm_detects_on_disk_tamper(registry):
    entry = registry.upload(filename="s.py", content=ORACLE_SHAPE1.encode())
    # Swap the file contents after upload.
    entry.path.write_bytes(b"verify = lambda c: True\n")
    with pytest.raises(OracleShaMismatch):
        registry.arm(entry.oracle_id, entry.sha256)


# ---------- dry run ----------


def test_dry_run_shape1(registry):
    entry = registry.upload(filename="s1.py", content=ORACLE_SHAPE1.encode())
    sentinel = bytes(range(16))
    samples = [sentinel, b"nope-nope-nope!!", sentinel, b"\x00" * 16]
    report = registry.dry_run(entry.oracle_id, samples=samples)
    assert report["samples"] == 4
    assert report["passes"] == 2
    assert report["fails"] == 2
    assert report["errors"] == 0
    assert all("duration_us" in r for r in report["results"])


def test_dry_run_shape2(registry):
    entry = registry.upload(filename="s2.py", content=ORACLE_SHAPE2.encode())
    samples = [b"magic!", b"bogus!"]
    report = registry.dry_run(entry.oracle_id, samples=samples)
    assert report["passes"] == 1
    assert report["fails"] == 1


def test_dry_run_does_not_require_armed(registry):
    entry = registry.upload(filename="s1.py", content=ORACLE_SHAPE1.encode())
    assert entry.armed is False
    # Should not raise.
    registry.dry_run(entry.oracle_id, samples=[b"x" * 16])


# ---------- delete / not found ----------


def test_delete_removes_file_and_entry(registry):
    entry = registry.upload(filename="s.py", content=ORACLE_SHAPE1.encode())
    path = entry.path
    assert path.is_file()
    registry.delete(entry.oracle_id)
    assert not path.is_file()
    with pytest.raises(OracleNotFound):
        registry.get(entry.oracle_id)


def test_delete_unknown_raises(registry):
    with pytest.raises(OracleNotFound):
        registry.delete("deadbeef")


# ---------- HTTP router integration ----------


def test_router_returns_503_when_disabled(tmp_path, monkeypatch):
    """The upload endpoint must 503 when MEMDIVER_ORACLE_DIR is unset."""
    from fastapi.testclient import TestClient

    from api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle_examples"
    init_oracle_registry(oracle_dir=None, examples_dir=examples_dir)
    try:
        from fastapi import FastAPI
        from api.routers.oracles import router

        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)
        # examples still work
        r = client.get("/api/oracles/examples")
        assert r.status_code == 200
        # upload is gated on MEMDIVER_ORACLE_DIR
        r = client.post(
            "/api/oracles/upload",
            files={"file": ("x.py", ORACLE_SHAPE1.encode(), "text/x-python")},
        )
        assert r.status_code == 503
    finally:
        reset_oracle_registry()


def test_router_full_round_trip(tmp_path):
    """Upload → arm → dry-run → delete via the real router."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.routers.oracles import router
    from api.services.oracle_registry import init_oracle_registry

    examples_dir = Path(__file__).parent.parent / "docs" / "oracle_examples"
    init_oracle_registry(
        oracle_dir=tmp_path / "oracles",
        examples_dir=examples_dir,
    )
    try:
        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)

        upload = client.post(
            "/api/oracles/upload",
            files={"file": ("my.py", ORACLE_SHAPE1.encode(), "text/x-python")},
            data={"description": "sentinel"},
        )
        assert upload.status_code == 200, upload.text
        body = upload.json()
        oracle_id = body["id"]
        sha = body["sha256"]
        assert body["armed"] is False
        assert body["shape"] == 1

        # list returns it
        listed = client.get("/api/oracles")
        assert any(o["id"] == oracle_id for o in listed.json()["oracles"])

        # mismatched arm rejected
        r = client.post(f"/api/oracles/{oracle_id}/arm", json={"sha256": "0" * 64})
        assert r.status_code == 409

        # correct arm accepted
        r = client.post(f"/api/oracles/{oracle_id}/arm", json={"sha256": sha})
        assert r.status_code == 200
        assert r.json()["armed"] is True

        # dry-run returns structured report
        sentinel_b64 = base64.b64encode(bytes(range(16))).decode()
        other_b64 = base64.b64encode(b"\x00" * 16).decode()
        r = client.post(
            f"/api/oracles/{oracle_id}/dry-run",
            json={"samples_b64": [sentinel_b64, other_b64]},
        )
        assert r.status_code == 200
        report = r.json()
        assert report["passes"] == 1
        assert report["fails"] == 1

        # delete
        r = client.delete(f"/api/oracles/{oracle_id}")
        assert r.status_code == 200

        r = client.get("/api/oracles")
        assert not any(o["id"] == oracle_id for o in r.json()["oracles"])
    finally:
        reset_oracle_registry()
