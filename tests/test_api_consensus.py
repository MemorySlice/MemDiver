"""End-to-end tests for /api/consensus endpoints."""

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient

from api.main import create_app
from api.services.consensus_session import ConsensusSessionManager, get_consensus_manager


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture(autouse=True)
def _fresh_manager(monkeypatch):
    """Use a per-test ConsensusSessionManager so tests don't share state."""
    import api.services.consensus_session as mod

    mgr = ConsensusSessionManager()
    monkeypatch.setattr(mod, "_default_manager", mgr)
    yield mgr


def _synthetic_dump(byte_val: int, size: int = 256) -> bytes:
    return bytes([byte_val]) * 50 + bytes((byte_val + i) & 0xFF for i in range(size - 50))


def test_consensus_begin_add_finalize_flow(client):
    response = client.post("/api/consensus/begin", json={"size": 256})
    assert response.status_code == 200
    session_id = response.json()["session_id"]
    assert response.json()["size"] == 256

    for val in (0x10, 0x20, 0x30):
        files = {"file": ("d.bin", io.BytesIO(_synthetic_dump(val)), "application/octet-stream")}
        r = client.post(f"/api/consensus/{session_id}/add-upload", files=files)
        assert r.status_code == 200
        body = r.json()
        assert body["session_id"] == session_id
        assert "num_dumps" in body
        assert "live_stats" in body

    status = client.get(f"/api/consensus/{session_id}").json()
    assert status["num_dumps"] == 3
    assert status["finalized"] is False
    assert len(status["dump_labels"]) == 3

    final = client.post(f"/api/consensus/{session_id}/finalize").json()
    assert final["num_dumps"] == 3
    assert final["size"] == 256
    assert "classification_counts" in final
    assert "variance_summary" in final
    # First 50 bytes are invariant (same byte across all 3)... wait, no: each
    # synthetic dump writes a different base byte, so bytes 0..49 differ too.
    # Just assert the histogram sums to size and variance_summary is sane.
    assert sum(final["classification_counts"].values()) == 256
    assert final["variance_summary"]["max"] >= 0.0


def test_consensus_invalid_session_returns_404(client):
    r = client.get("/api/consensus/nonexistent")
    assert r.status_code == 404
    r = client.post("/api/consensus/nonexistent/finalize")
    assert r.status_code == 404
    r = client.delete("/api/consensus/nonexistent")
    assert r.status_code == 404


def test_consensus_finalize_twice_is_idempotent(client):
    sid = client.post("/api/consensus/begin", json={"size": 64}).json()["session_id"]
    for val in (1, 2):
        files = {"file": ("d.bin", io.BytesIO(bytes([val]) * 64), "application/octet-stream")}
        client.post(f"/api/consensus/{sid}/add-upload", files=files)
    a = client.post(f"/api/consensus/{sid}/finalize").json()
    b = client.post(f"/api/consensus/{sid}/finalize").json()
    assert a["classification_counts"] == b["classification_counts"]


def test_consensus_add_after_finalize_is_rejected(client):
    sid = client.post("/api/consensus/begin", json={"size": 64}).json()["session_id"]
    for val in (1, 2):
        files = {"file": ("d.bin", io.BytesIO(bytes([val]) * 64), "application/octet-stream")}
        client.post(f"/api/consensus/{sid}/add-upload", files=files)
    client.post(f"/api/consensus/{sid}/finalize")
    files = {"file": ("d.bin", io.BytesIO(bytes([3]) * 64), "application/octet-stream")}
    r = client.post(f"/api/consensus/{sid}/add-upload", files=files)
    assert r.status_code == 409


def test_consensus_delete_session(client):
    sid = client.post("/api/consensus/begin", json={"size": 32}).json()["session_id"]
    r = client.delete(f"/api/consensus/{sid}")
    assert r.status_code == 200
    assert r.json() == {"deleted": True}
    assert client.get(f"/api/consensus/{sid}").status_code == 404
