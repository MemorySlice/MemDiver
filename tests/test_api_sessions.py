"""HTTP-layer tests for api.routers.sessions.

The sessions router is a thin adapter over ``api.services.session_service``.
We redirect the session directory into ``tmp_path`` so the tests never
read or write real session files under ``~/.memdiver/sessions/``.

Note: FastAPI's ``Depends(get_api_settings)`` re-reads the cached settings
each request, so clearing ``get_settings.cache_clear()`` after setting
``MEMDIVER_SESSION_DIR`` ensures the override propagates.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import get_settings
from api.main import create_app


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


def _minimal_payload(name: str = "demo_session") -> dict:
    """A minimal but field-complete payload that satisfies SessionPayload."""
    return {
        "session_name": name,
        "input_mode": "directory",
        "input_path": "/tmp/example",
        "dataset_root": "",
        "keylog_filename": "",
        "template_name": "",
        "protocol_name": "TLS",
        "protocol_version": "1.3",
        "scenario": "",
        "selected_libraries": ["openssl"],
        "selected_phase": "",
        "algorithm": "",
        "mode": "verification",
        "max_runs": 5,
        "normalize_phases": False,
        "single_file_format": "",
        "ground_truth_mode": "auto",
        "selected_algorithms": [],
        "analysis_result": None,
        "bookmarks": [],
        "investigation_offset": None,
    }


# ---------------------------------------------------------------------------
# GET /api/sessions
# ---------------------------------------------------------------------------


def test_list_sessions_empty(client):
    """An empty session dir returns ``{"sessions": []}``."""
    r = client.get("/api/sessions/")
    assert r.status_code == 200
    body = r.json()
    assert body == {"sessions": []}


# ---------------------------------------------------------------------------
# POST /api/sessions
# ---------------------------------------------------------------------------


def test_save_session_happy_path(client, isolated_env):
    """POST persists a .memdiver file under the redirected session dir."""
    payload = _minimal_payload("save_demo")
    r = client.post("/api/sessions/", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["name"] == "save_demo"
    persisted = Path(body["path"])
    assert persisted.is_file()
    assert persisted.parent == isolated_env / "sessions"
    assert persisted.suffix == ".memdiver"


def test_save_session_422_on_invalid_payload(client):
    """A non-dict payload is rejected by Pydantic with 422."""
    # ``max_runs`` declared int -> string fails coercion.
    bad = _minimal_payload("bad")
    bad["max_runs"] = "not-an-int"
    r = client.post("/api/sessions/", json=bad)
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# GET /api/sessions/{name} round trip + 404
# ---------------------------------------------------------------------------


def test_load_session_round_trip(client):
    """Save then load returns a snapshot dict with the saved fields."""
    payload = _minimal_payload("round_trip")
    r = client.post("/api/sessions/", json=payload)
    assert r.status_code == 200, r.text

    r = client.get("/api/sessions/round_trip")
    assert r.status_code == 200, r.text
    snapshot = r.json()
    assert snapshot["session_name"] == "round_trip"
    assert snapshot["protocol_version"] == "1.3"
    assert snapshot["selected_libraries"] == ["openssl"]


def test_load_session_404_on_unknown_name(client):
    """A name that doesn't map to any persisted file returns 404."""
    r = client.get("/api/sessions/nonexistent_session_name_xyz")
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# DELETE /api/sessions/{name}
# ---------------------------------------------------------------------------


def test_delete_session_round_trip(client, isolated_env):
    """save -> delete removes the persisted file and 404s on subsequent load."""
    payload = _minimal_payload("deletable")
    r = client.post("/api/sessions/", json=payload)
    assert r.status_code == 200

    r = client.delete("/api/sessions/deletable")
    assert r.status_code == 200
    assert r.json()["deleted"] == "deletable"
    # File is gone.
    assert not (isolated_env / "sessions" / "deletable.memdiver").exists()
    # And subsequent GET 404s.
    r = client.get("/api/sessions/deletable")
    assert r.status_code == 404
