"""HTTP-layer tests for api.routers.dataset (prefix ``/api/dataset``).

The dataset router wraps ``mcp_server.tools`` for protocol/phase/run
discovery and dataset scanning. We point every settings-controlled
directory at ``tmp_path`` (mirroring ``test_api_sessions.py``) so the app
boots in isolation, then exercise the discovery endpoints against real
directories created under ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app


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
# GET /api/dataset/protocols
# ---------------------------------------------------------------------------


def test_list_protocols_non_empty(client):
    """The protocol registry returns a non-empty list under ``protocols``."""
    r = client.get("/api/dataset/protocols")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "protocols" in body
    assert isinstance(body["protocols"], list)
    assert len(body["protocols"]) >= 1


# ---------------------------------------------------------------------------
# GET /api/dataset/runs
# ---------------------------------------------------------------------------


def test_list_runs_shape(client, isolated_env):
    """A root containing a run-style subdir returns a ``runs`` list."""
    root = isolated_env / "dataset_root"
    root.mkdir()
    # A directory named like a legacy run dir (<lib>_run_<ver>_<n>).
    (root / "openssl_run_3.3_1").mkdir()

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "runs" in body
    assert isinstance(body["runs"], list)


def test_list_runs_404_on_file(client, isolated_env):
    """Pointing ``root`` at a plain file (not a dir) yields 404."""
    f = isolated_env / "not_a_dir.txt"
    f.write_text("hello")

    r = client.get("/api/dataset/runs", params={"root": str(f)})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/dataset/phases
# ---------------------------------------------------------------------------


def test_list_phases_shape_or_graceful(client, isolated_env):
    """A library dir returns phases/runs keys, or a graceful error dict."""
    lib = isolated_env / "openssl_lib"
    lib.mkdir()

    r = client.get("/api/dataset/phases", params={"library_dir": str(lib)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    # Either the success shape (phases + runs) or a graceful error.
    assert ("phases" in body and "runs" in body) or "error" in body


# ---------------------------------------------------------------------------
# POST /api/dataset/scan
# ---------------------------------------------------------------------------


def test_scan_minimal_root(client, isolated_env):
    """Scanning a minimal dataset root returns 200 with a dict body."""
    root = isolated_env / "scan_root"
    root.mkdir()

    r = client.post("/api/dataset/scan", json={"root": str(root)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
