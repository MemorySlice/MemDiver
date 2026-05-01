"""Tests for the MemDiver FastAPI application (Phase A endpoints)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import create_app

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "dataset"
TLS12_LIB_DIR = FIXTURE_ROOT / "TLS12" / "scenario_a" / "openssl"
TLS12_RUN_DIR = TLS12_LIB_DIR / "openssl_run_12_1"
TLS12_DUMP = TLS12_RUN_DIR / "20240101_120001_000002_post_handshake.dump"


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


# ---- App health ----


def test_app_creates_without_error():
    app = create_app()
    assert app is not None
    assert app.title == "MemDiver"


def test_openapi_schema_accessible(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    assert "paths" in schema
    assert schema["info"]["title"] == "MemDiver"


# ---- Dataset endpoints ----


def test_scan_dataset(client):
    resp = client.post(
        "/api/dataset/scan",
        json={"root": str(FIXTURE_ROOT)},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)


def test_list_protocols(client):
    resp = client.get("/api/dataset/protocols")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, (dict, list))


def test_list_phases(client):
    resp = client.get(
        "/api/dataset/phases",
        params={"library_dir": str(TLS12_LIB_DIR)},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, (dict, list))


# ---- Analysis endpoint ----


def test_run_analysis(client):
    resp = client.post(
        "/api/analysis/run",
        json={
            "library_dirs": [str(TLS12_LIB_DIR)],
            "phase": "post_handshake",
            "protocol_version": "TLS12",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)


# ---- Inspect endpoints ----


def test_read_hex(client):
    resp = client.get(
        "/api/inspect/hex",
        params={"dump_path": str(TLS12_DUMP), "offset": 0, "length": 64},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)


def test_get_entropy(client):
    resp = client.get(
        "/api/inspect/entropy",
        params={"dump_path": str(TLS12_DUMP)},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)


def test_extract_strings(client):
    resp = client.get(
        "/api/inspect/strings",
        params={"dump_path": str(TLS12_DUMP)},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)


def test_identify_structure(client):
    resp = client.get(
        "/api/inspect/structure",
        params={"dump_path": str(TLS12_DUMP)},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)


def test_xref_non_msl_returns_error():
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get(
            "/api/inspect/xref",
            params={"msl_path": str(TLS12_DUMP)},
        )
        # Non-MSL file triggers MslParseError -> 500 internal server error
        assert resp.status_code == 500


def test_session_info_non_msl_returns_error(client):
    resp = client.get(
        "/api/inspect/session-info",
        params={"msl_path": str(TLS12_DUMP)},
    )
    # Tool returns 200 with {"error": ...} for non-MSL files
    assert resp.status_code == 200
    data = resp.json()
    assert "error" in data


# ---- Sessions endpoints ----


def test_list_sessions(client):
    resp = client.get("/api/sessions/")
    assert resp.status_code == 200
    data = resp.json()
    assert "sessions" in data
    assert isinstance(data["sessions"], list)


def test_load_nonexistent_session(client):
    resp = client.get("/api/sessions/nonexistent")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_delete_nonexistent_session(client):
    resp = client.delete("/api/sessions/nonexistent")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---- Tasks endpoint ----


def test_get_task_returns_503_without_manager(client):
    """Without the FastAPI lifespan running, TaskManager is not
    initialized; the endpoint must surface that as 503 rather than
    silently returning a stub payload."""
    resp = client.get("/api/tasks/test123")
    assert resp.status_code == 503


def test_get_task_result_returns_503_without_manager(client):
    resp = client.get("/api/tasks/test123/result")
    assert resp.status_code == 503


def test_cancel_task_returns_503_without_manager(client):
    resp = client.delete("/api/tasks/test123")
    assert resp.status_code == 503


# ---- Analysis batch stub ----


def test_batch_analysis_stub(client):
    """The batch endpoint now requires a real BatchRunRequest body (Phase B).

    A bodyless POST should be rejected by Pydantic with HTTP 422 — the
    legacy 'not_implemented' stub at this path was replaced by a
    TaskManager-backed runner; see ``tests/test_api_analysis.py`` for
    the full lifecycle coverage.
    """
    resp = client.post("/api/analysis/batch")
    assert resp.status_code == 422


# ---- Session save ----


def test_save_session(client, tmp_path):
    resp = client.post("/api/sessions/", json={"name": "test_save", "mode": "testing"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "path" in data


# ---- Convergence endpoint ----


class TestConvergenceEndpoint:
    def test_convergence_requires_min_dumps(self, client, tmp_path):
        # Use an existing file so the count check triggers (not the missing-file check)
        dump = tmp_path / "single.dump"
        dump.write_bytes(b"\x00" * 256)
        resp = client.post("/api/analysis/convergence",
                          json={"dump_paths": [str(dump)]})
        assert resp.status_code == 400

    def test_convergence_missing_files(self, client):
        resp = client.post("/api/analysis/convergence",
                          json={"dump_paths": ["/nonexistent/a.dump", "/nonexistent/b.dump"]})
        assert resp.status_code == 404


# ---- Verify key endpoint ----


class TestVerifyKeyEndpoint:
    def test_verify_missing_dump(self, client):
        resp = client.post("/api/analysis/verify-key",
                          json={"dump_path": "/nonexistent.dump",
                                "offset": 0, "ciphertext_hex": "aa" * 48})
        assert resp.status_code == 404

    def test_verify_unknown_cipher(self, client):
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(suffix=".dump", delete=False) as f:
            f.write(b"\x00" * 1024)
            dump_path = f.name
        try:
            resp = client.post("/api/analysis/verify-key",
                              json={"dump_path": dump_path,
                                    "offset": 0,
                                    "ciphertext_hex": "aa" * 48,
                                    "cipher": "UNKNOWN-CIPHER"})
            assert resp.status_code == 400
        finally:
            os.unlink(dump_path)


# ---- Auto-export endpoint ----


class TestAutoExportEndpoint:
    def test_auto_export_requires_min_dumps(self, client, tmp_path):
        # Use an existing file so the count check triggers (not the missing-file check)
        dump = tmp_path / "single.dump"
        dump.write_bytes(b"\x00" * 256)
        resp = client.post("/api/analysis/auto-export",
                          json={"dump_paths": [str(dump)]})
        assert resp.status_code == 400

    def test_auto_export_missing_files(self, client):
        resp = client.post("/api/analysis/auto-export",
                          json={"dump_paths": ["/nonexistent/a.dump", "/nonexistent/b.dump"]})
        assert resp.status_code == 404
