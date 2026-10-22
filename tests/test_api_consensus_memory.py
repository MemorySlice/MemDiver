"""/api/consensus memory bounds: size ceiling, budget gate, chunked upload."""

import io

import pytest
from fastapi.testclient import TestClient

from memdiver.api.main import create_app
from memdiver.api.routers.consensus import CONSENSUS_SESSION_MAX_BYTES
from memdiver.api.services.consensus_session import ConsensusSessionManager


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture(autouse=True)
def _fresh_manager(monkeypatch):
    import memdiver.api.services.consensus_session as mod
    mgr = ConsensusSessionManager()
    monkeypatch.setattr(mod, "_default_manager", mgr)
    yield mgr


def test_begin_rejects_size_above_ceiling(client):
    r = client.post("/api/consensus/begin", json={"size": CONSENSUS_SESSION_MAX_BYTES + 1})
    assert r.status_code == 422


def test_begin_budget_gate_and_force(client, monkeypatch):
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "1")
    size = 1024 * 1024
    r = client.post("/api/consensus/begin", json={"size": size})
    assert r.status_code >= 400
    assert "memory_budget_exceeded" in r.text
    forced = client.post("/api/consensus/begin", json={"size": size, "force": True})
    assert forced.status_code == 200


def test_upload_reads_only_the_prefix_and_rejects_short(client, _fresh_manager):
    sid = client.post("/api/consensus/begin", json={"size": 300}).json()["session_id"]
    payload = bytes(range(256)) * 4  # 1024 bytes, longer than the session
    r = client.post(f"/api/consensus/{sid}/add-upload",
                    files={"file": ("d.bin", io.BytesIO(payload), "application/octet-stream")})
    assert r.status_code == 200
    assert _fresh_manager.get(sid).matrix.reference_bytes == payload[:300]
    short = client.post(f"/api/consensus/{sid}/add-upload",
                        files={"file": ("s.bin", io.BytesIO(b"x" * 10), "application/octet-stream")})
    assert short.status_code == 400
    assert "10 < 300" in short.json()["detail"]
