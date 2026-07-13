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


def test_add_upload_offloads_add_dump_off_event_loop(client, monkeypatch):
    """Regression: the CPU-heavy synchronous ``manager.add_dump`` (numpy
    Welford fold) must run via ``asyncio.to_thread`` so a large upload does
    not stall the event loop for all concurrent requests. We assert the
    handler dispatches through ``asyncio.to_thread`` while preserving the
    AddResponse shape."""
    import api.routers.consensus as consensus_mod

    sid = client.post("/api/consensus/begin", json={"size": 64}).json()["session_id"]

    calls: list[bool] = []
    real_to_thread = consensus_mod.asyncio.to_thread

    async def spy_to_thread(func, *args, **kwargs):
        # Only record offloads of the add_dump bound method.
        if getattr(func, "__name__", "") == "add_dump":
            calls.append(True)
        return await real_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(consensus_mod.asyncio, "to_thread", spy_to_thread)

    files = {"file": ("d.bin", io.BytesIO(bytes([7]) * 64), "application/octet-stream")}
    r = client.post(f"/api/consensus/{sid}/add-upload", files=files)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["session_id"] == sid
    assert body["num_dumps"] == 1
    assert "live_stats" in body
    assert calls == [True], "add_dump must be offloaded via asyncio.to_thread"


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


# ---------------------------------------------------------------------------
# Regression (C1): POST /api/analysis/consensus over two .msl dumps must
# succeed. The bug was that run_consensus built MslDumpSource via open_dump()
# but never called .open(), so build_from_sources raised
# RuntimeError('MslDumpSource not opened'). The fix opens each source first.
# ---------------------------------------------------------------------------


def test_analysis_consensus_over_two_msl_dumps(client, tmp_path):
    """Two .msl dump paths through /api/analysis/consensus return 200, not a
    'not opened' RuntimeError."""
    from tests.fixtures.generate_msl_fixtures import generate_msl_file

    blob = generate_msl_file()
    p1 = tmp_path / "a.msl"
    p2 = tmp_path / "b.msl"
    p1.write_bytes(blob)
    p2.write_bytes(blob)

    r = client.post(
        "/api/analysis/consensus",
        json={"dump_paths": [str(p1), str(p2)]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["size"] > 0
    assert body["num_dumps"] == 2
    assert "counts" in body


# ---------------------------------------------------------------------------
# Regression: the consensus build must be addressed by a server-generated
# ``consensus_id`` rather than stashed on a process-wide singleton. The old
# behaviour let concurrent /analysis/consensus builds overwrite each other's
# range-query state; each build now gets its own id.
# ---------------------------------------------------------------------------


def _write_raw_dumps(tmp_path, prefix: str, size: int):
    """Write two distinct raw dumps of ``size`` bytes and return their paths."""
    p1 = tmp_path / f"{prefix}_a.bin"
    p2 = tmp_path / f"{prefix}_b.bin"
    p1.write_bytes(_synthetic_dump(0x11, size))
    p2.write_bytes(_synthetic_dump(0x22, size))
    return p1, p2


def test_analysis_consensus_post_returns_consensus_id(client, tmp_path):
    """POST /api/analysis/consensus returns a non-empty consensus_id."""
    p1, p2 = _write_raw_dumps(tmp_path, "build", 128)
    r = client.post(
        "/api/analysis/consensus",
        json={"dump_paths": [str(p1), str(p2)]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "consensus_id" in body
    assert isinstance(body["consensus_id"], str)
    assert body["consensus_id"]  # non-empty


def test_analysis_consensus_range_requires_and_uses_consensus_id(client, tmp_path):
    """GET .../range?consensus_id=<id> returns the build's classifications."""
    size = 200
    p1, p2 = _write_raw_dumps(tmp_path, "build", size)
    post = client.post(
        "/api/analysis/consensus",
        json={"dump_paths": [str(p1), str(p2)]},
    )
    assert post.status_code == 200, post.text
    consensus_id = post.json()["consensus_id"]

    r = client.get(
        "/api/analysis/consensus/range",
        params={"consensus_id": consensus_id, "offset": 0, "length": size},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body["classifications"], list)
    assert len(body["classifications"]) == size


def test_analysis_consensus_range_unknown_id_returns_404(client, tmp_path):
    """GET .../range with a bogus consensus_id returns 404."""
    r = client.get(
        "/api/analysis/consensus/range",
        params={"consensus_id": "does-not-exist", "offset": 0, "length": 16},
    )
    assert r.status_code == 404


def test_analysis_consensus_builds_are_isolated(client, tmp_path):
    """Two separate builds get distinct ids and both stay queryable.

    The old process-wide singleton would have let the second build overwrite
    the first; here the two builds have different sizes, so a stale read would
    surface as a wrong-length range result.
    """
    size_a = 100
    size_b = 250
    a1, a2 = _write_raw_dumps(tmp_path, "first", size_a)
    b1, b2 = _write_raw_dumps(tmp_path, "second", size_b)

    post_a = client.post(
        "/api/analysis/consensus", json={"dump_paths": [str(a1), str(a2)]},
    )
    post_b = client.post(
        "/api/analysis/consensus", json={"dump_paths": [str(b1), str(b2)]},
    )
    assert post_a.status_code == 200, post_a.text
    assert post_b.status_code == 200, post_b.text

    id_a = post_a.json()["consensus_id"]
    id_b = post_b.json()["consensus_id"]
    assert id_a and id_b
    assert id_a != id_b

    range_a = client.get(
        "/api/analysis/consensus/range",
        params={"consensus_id": id_a, "offset": 0, "length": size_b},
    )
    range_b = client.get(
        "/api/analysis/consensus/range",
        params={"consensus_id": id_b, "offset": 0, "length": size_b},
    )
    assert range_a.status_code == 200, range_a.text
    assert range_b.status_code == 200, range_b.text

    # Each id reads its own build: lengths are clamped to that build's size,
    # so the first build still reports size_a even though it was built first.
    assert len(range_a.json()["classifications"]) == size_a
    assert len(range_b.json()["classifications"]) == size_b
