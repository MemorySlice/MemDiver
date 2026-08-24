"""HTTP-layer tests for api.routers.pcaps (prefix ``/api/pcaps``).

The pcaps router exposes ``POST /api/pcaps/upload`` which streams a
multipart capture in 1 MiB chunks to ``settings.upload_dir/pcaps/``,
enforces a 512 MiB size cap (``PCAP_UPLOAD_MAX_BYTES``), validates the
suffix, and *persists* the file (the verification pipeline re-reads
``pcap_path`` later).

We redirect every settings-controlled directory into ``tmp_path`` (same
fixtures as tests/test_api_dumps.py).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# A real TLS 1.3 capture (one session) reused for the /validate happy path.
REAL_PCAP = Path(
    "/Users/danielbaier/Desktop/tls_dumps/TLS13/"
    "100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/"
    "run_data/traffic.pcap"
)

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.api.path_safety import ensure_within
from memdiver.api.routers import pcaps as pcaps_router


# ---------------------------------------------------------------------------
# Fixtures (copied verbatim from tests/test_api_dumps.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch):
    """Redirect every settings-controlled directory into tmp_path."""
    for sub, env in [
        ("oracles", "MEMDIVER_ORACLE_DIR"),
        ("tasks", "MEMDIVER_TASK_ROOT"),
        ("uploads", "MEMDIVER_UPLOAD_DIR"),
        ("sessions", "MEMDIVER_SESSION_DIR"),
    ]:
        d = tmp_path / sub
        d.mkdir()
        monkeypatch.setenv(env, str(d))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(isolated_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# POST /api/pcaps/upload — happy path
# ---------------------------------------------------------------------------


def test_upload_pcap_happy_path(client, isolated_env):
    """A valid capture is persisted under upload_dir/pcaps with correct size."""
    payload = b"\xd4\xc3\xb2\xa1pcap-body-bytes"
    r = client.post(
        "/api/pcaps/upload",
        files={"file": ("capture.pcap", payload, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["filename"] == "capture.pcap"
    assert body["size"] == len(payload)

    dest = Path(body["pcap_path"])
    assert dest.is_file(), "capture must be persisted (not unlinked) on success"
    assert dest.read_bytes() == payload
    assert dest.suffix == ".pcap"  # original suffix preserved
    upload_dir = isolated_env / "uploads"
    assert dest.parent == (upload_dir / "pcaps").resolve()


def test_upload_pcap_preserves_pcapng_suffix(client):
    """The stored filename and returned name keep the original suffix."""
    r = client.post(
        "/api/pcaps/upload",
        files={"file": ("trace.pcapng", b"body", "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    assert Path(r.json()["pcap_path"]).suffix == ".pcapng"


# ---------------------------------------------------------------------------
# POST /api/pcaps/upload — size cap → 413
# ---------------------------------------------------------------------------


def test_upload_pcap_over_cap_is_413(client, monkeypatch, isolated_env):
    """An upload larger than the cap is rejected with 413 and leaves no file.

    We shrink the module-level ``PCAP_UPLOAD_MAX_BYTES`` constant so we don't
    have to stream 512 MiB.
    """
    monkeypatch.setattr(pcaps_router, "PCAP_UPLOAD_MAX_BYTES", 1024)

    payload = b"a" * 2048  # > 1024-byte cap
    r = client.post(
        "/api/pcaps/upload",
        files={"file": ("big.pcap", payload, "application/octet-stream")},
    )
    assert r.status_code == 413
    assert "cap" in r.json()["detail"].lower()

    # The partial file must have been unlinked on the exception path.
    pcap_dir = isolated_env / "uploads" / "pcaps"
    if pcap_dir.exists():
        assert list(pcap_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# POST /api/pcaps/upload — bad suffix → 400
# ---------------------------------------------------------------------------


def test_upload_pcap_bad_suffix_is_400(client):
    """A disallowed suffix (e.g. .txt) is rejected with 400."""
    r = client.post(
        "/api/pcaps/upload",
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )
    assert r.status_code == 400, r.text
    assert "suffix" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# POST /api/pcaps/upload — destination is structurally contained
# ---------------------------------------------------------------------------


def test_upload_pcap_dest_within_upload_dir(client, isolated_env):
    """A traversal filename cannot escape upload_dir: the uuid name makes
    containment structural. Assert the dest stays inside upload_dir."""
    r = client.post(
        "/api/pcaps/upload",
        files={"file": ("../../../../etc/evil.pcap", b"body",
                        "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    dest = Path(r.json()["pcap_path"])
    upload_dir = isolated_env / "uploads"
    # ensure_within raises if dest escapes upload_dir.
    ensure_within(upload_dir, dest)
    assert dest.parent == (upload_dir / "pcaps").resolve()


# ---------------------------------------------------------------------------
# POST /api/pcaps/upload — aggregate quota + LRU pruning
# ---------------------------------------------------------------------------


def test_upload_pcap_prunes_oldest_over_quota(client, monkeypatch, isolated_env):
    """Uploading past the quota evicts oldest files so the dir stays capped.

    We set a tiny ``pcap_quota_bytes`` so three ~200-byte uploads exceed it; the
    dir must never hold more bytes than the cap after each upload.
    """
    monkeypatch.setenv("MEMDIVER_PCAP_QUOTA_BYTES", "512")
    get_settings.cache_clear()

    pcap_dir = isolated_env / "uploads" / "pcaps"
    payload = b"x" * 200
    for i in range(3):
        r = client.post(
            "/api/pcaps/upload",
            files={"file": (f"c{i}.pcap", payload, "application/octet-stream")},
        )
        assert r.status_code == 200, r.text
        total = sum(f.stat().st_size for f in pcap_dir.iterdir() if f.is_file())
        assert total <= 512, f"dir over quota after upload {i}: {total}"

    # Two 200-byte files (400) fit under the 512 cap; the oldest was pruned.
    assert len(list(pcap_dir.iterdir())) == 2


def test_upload_pcap_never_prunes_just_uploaded_file(client, monkeypatch, isolated_env):
    """The freshly written capture survives even when it alone exceeds the cap."""
    monkeypatch.setenv("MEMDIVER_PCAP_QUOTA_BYTES", "10")
    get_settings.cache_clear()

    payload = b"y" * 200  # single upload already dwarfs the 10-byte quota
    r = client.post(
        "/api/pcaps/upload",
        files={"file": ("only.pcap", payload, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    dest = Path(r.json()["pcap_path"])
    assert dest.is_file(), "the just-uploaded capture must never be pruned"
    assert dest.read_bytes() == payload


def test_prune_pcap_dir_tolerates_missing_file(tmp_path, monkeypatch):
    """A candidate vanishing between listing and unlink does not crash the prune.

    We patch ``Path.unlink`` so the first eviction raises ``FileNotFoundError``
    (as if a racing request already removed it); the prune must swallow it,
    press on to the next-oldest, and leave ``keep`` untouched.
    """
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir()
    keep = pcap_dir / "keep.pcap"
    keep.write_bytes(b"k" * 100)
    # Two eviction candidates older than keep; the dir is far over the 1-byte cap.
    (pcap_dir / "old1.pcap").write_bytes(b"o" * 100)
    (pcap_dir / "old2.pcap").write_bytes(b"p" * 100)

    real_unlink = Path.unlink
    calls = {"n": 0}

    def flaky_unlink(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise FileNotFoundError(self)  # first candidate raced away
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", flaky_unlink)
    # Must not raise despite the first unlink failing.
    pcaps_router._prune_pcap_dir(pcap_dir, 1, keep=keep)
    assert keep.is_file(), "keep must survive pruning"


# ---------------------------------------------------------------------------
# POST /api/pcaps/validate — arm/validate a persisted capture
# ---------------------------------------------------------------------------


def test_validate_pcap_happy_path(client, isolated_env):
    """A real capture inside upload_dir is summarised into >=1 TLS session."""
    pytest.importorskip("dpkt")
    if not REAL_PCAP.is_file():
        pytest.skip(f"sample capture not present: {REAL_PCAP}")

    pcap_dir = isolated_env / "uploads" / "pcaps"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    local = pcap_dir / "traffic.pcap"
    local.write_bytes(REAL_PCAP.read_bytes())

    r = client.post("/api/pcaps/validate", json={"pcap_path": str(local)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["session_count"] >= 1
    assert len(body["sessions"]) == body["session_count"]
    assert len(body["sessions"][0]["client_random"]) == 64


def test_validate_pcap_outside_upload_dir_is_400(client, tmp_path):
    """A pcap_path escaping upload_dir is rejected with 400 (containment)."""
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1payload")

    r = client.post("/api/pcaps/validate", json={"pcap_path": str(outside)})
    assert r.status_code == 400, r.text
    assert "escapes" in r.json()["detail"].lower()


def test_validate_pcap_truncated_capture_is_400(client, isolated_env):
    """A truncated capture inside upload_dir surfaces as 400, not 500.

    dpkt raises ``dpkt.dpkt.NeedData`` (its own base ``dpkt.dpkt.Error``, not an
    OSError/ValueError) on a cut-short global header; the widened funnel maps
    that to a ``CapabilityError(INVALID_INPUT)`` → HTTP 400 rather than a 500.
    """
    pytest.importorskip("dpkt")

    pcap_dir = isolated_env / "uploads" / "pcaps"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    truncated = pcap_dir / "truncated.pcap"
    # 7 bytes: valid little-endian pcap magic + a partial global header.
    truncated.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x00")

    r = client.post("/api/pcaps/validate", json={"pcap_path": str(truncated)})
    assert r.status_code == 400, r.text


def test_validate_pcap_error_detail_does_not_leak_absolute_base(client, tmp_path):
    """The escape-rejection detail must not echo the resolved absolute base."""
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1payload")

    r = client.post("/api/pcaps/validate", json={"pcap_path": str(outside)})
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert "escapes" in detail.lower()
    # The upload_dir absolute base lives under tmp_path; it must not be disclosed.
    assert str(tmp_path) not in detail
