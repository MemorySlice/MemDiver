"""HTTP-layer tests for api.routers.sessions.

The sessions router is a thin adapter over ``api.services.session_service``.
We redirect the session directory into ``tmp_path`` so the tests never
read or write real session files under ``~/.memdiver/sessions/``.

Note: FastAPI's ``Depends(get_api_settings)`` re-reads the cached settings
each request, so clearing ``get_settings.cache_clear()`` after setting
``MEMDIVER_SESSION_DIR`` ensures the override propagates.
"""

from __future__ import annotations

import gzip
import json
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


# ---------------------------------------------------------------------------
# Path-safety regression: a session_name with traversal must be rejected and
# must not write a file outside the session dir.
# ---------------------------------------------------------------------------


def test_save_session_rejects_traversal_name(client, isolated_env):
    """A traversal session_name returns 400 and writes nothing outside the dir."""
    payload = _minimal_payload("../../../../tmp/evil")
    r = client.post("/api/sessions/", json=payload)
    assert r.status_code == 400, r.text
    # No file escaped to /tmp/evil.memdiver.
    assert not Path("/tmp/evil.memdiver").exists()
    # And nothing landed in the session dir either.
    assert list((isolated_env / "sessions").glob("*.memdiver")) == []


def test_save_session_normal_name_still_saves(client, isolated_env):
    """A normal session_name continues to save with 200 after the guard."""
    payload = _minimal_payload("normal_after_guard")
    r = client.post("/api/sessions/", json=payload)
    assert r.status_code == 200, r.text
    persisted = Path(r.json()["path"])
    assert persisted.is_file()
    assert persisted.parent == isolated_env / "sessions"


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


# ---------------------------------------------------------------------------
# Schema v2 — the dump list, and the secrets that must never reach disk
# ---------------------------------------------------------------------------


PERSISTABLE_DUMP_KEYS = {"path", "name", "size", "format"}


def _read_session_file(isolated_env: Path, name: str) -> str:
    """Return the decompressed JSON text of a persisted session file."""
    path = isolated_env / "sessions" / f"{name}.memdiver"
    assert path.is_file(), f"session file missing: {path}"
    return gzip.decompress(path.read_bytes()).decode("utf-8")


def test_save_session_without_dumps_still_succeeds(client, isolated_env):
    """The v2 fields are genuinely optional on the wire.

    ``_minimal_payload()`` deliberately stays minimal (no ``dumps`` key), so
    this is the proof that an older client still saves without a 422.
    """
    r = client.post("/api/sessions/", json=_minimal_payload("no_dumps_wire"))
    assert r.status_code == 200, r.text

    loaded = client.get("/api/sessions/no_dumps_wire").json()
    assert loaded["dumps"] == []
    assert loaded["main_view"] == "single"
    assert loaded["dump_weights"] == {}


def test_save_session_persists_dump_list(client, isolated_env):
    payload = _minimal_payload("with_dumps")
    payload["dumps"] = [
        {"path": "/d/a.msl", "name": "a.msl", "size": 10, "format": "msl"},
    ]
    payload["active_dump_path"] = "/d/a.msl"
    payload["dump_weights"] = {"/d/a.msl": 2.0}
    r = client.post("/api/sessions/", json=payload)
    assert r.status_code == 200, r.text

    loaded = client.get("/api/sessions/with_dumps").json()
    assert loaded["dumps"] == payload["dumps"]
    assert loaded["active_dump_path"] == "/d/a.msl"
    assert loaded["dump_weights"] == {"/d/a.msl": 2.0}


def test_saved_session_file_never_contains_key_material(client, isolated_env):
    """SECURITY: plaintext secrets on a dump entry must not reach disk.

    Asserted on the FILE BYTES rather than on the GET response — only the
    file proves nothing was written. Session files are unprotected gzipped
    JSON under ~/.memdiver/sessions/.
    """
    payload = _minimal_payload("secretive")
    payload["dumps"] = [{
        "path": "/d/secret.msl",
        "name": "secret.msl",
        "size": 4096,
        "format": "msl",
        "passphrase": "hunter2",
        "key_material": {
            "passphrase": "hunter2",
            "key_hex": "deadbeef",
            "kem_key_hex": "cafebabe",
        },
        "tag_status": "valid",
    }]
    r = client.post("/api/sessions/", json=payload)
    assert r.status_code == 200, r.text

    text = _read_session_file(isolated_env, "secretive")
    assert "hunter2" not in text
    assert "deadbeef" not in text
    assert "cafebabe" not in text
    assert "key_material" not in text
    assert "tag_status" not in text
    # The whitelisted part did survive.
    assert "/d/secret.msl" in text

    persisted = json.loads(text)
    assert [set(d) for d in persisted["dumps"]] == [PERSISTABLE_DUMP_KEYS]


def test_saved_session_file_stamps_schema_version_and_memdiver_version(
    client, isolated_env,
):
    r = client.post("/api/sessions/", json=_minimal_payload("stamped"))
    assert r.status_code == 200, r.text

    persisted = json.loads(_read_session_file(isolated_env, "stamped"))
    assert persisted["schema_version"] == 2
    # Previously always "" — the router never passed a version through.
    assert persisted["memdiver_version"]


def test_list_sessions_reports_dump_count(client):
    payload = _minimal_payload("counted")
    payload["dumps"] = [
        {"path": "/d/a", "name": "a", "size": 1, "format": "raw"},
        {"path": "/d/b", "name": "b", "size": 2, "format": "raw"},
    ]
    assert client.post("/api/sessions/", json=payload).status_code == 200
    assert client.post(
        "/api/sessions/", json=_minimal_payload("uncounted"),
    ).status_code == 200

    listed = {s["name"]: s for s in client.get("/api/sessions/").json()["sessions"]}
    assert listed["counted"]["dump_count"] == 2
    assert listed["uncounted"]["dump_count"] == 0


def test_save_session_accepts_null_for_absent_string_fields(client, isolated_env):
    """A JS client sends ``null`` for "nothing selected"; that must not 422.

    Regression test for a real defect. ``dump-rail-store.soloPath`` and
    ``dump-store.originDumpId`` are typed ``string | null`` in the frontend, so
    a workspace with nothing soloed POSTed ``"solo_dump_path": null`` and the
    save was rejected with a 422. Neither suite could see it: the frontend tests
    mock this endpoint, and every backend test sent ``""``. It only surfaced
    when a session was saved from the real browser.
    """
    payload = _minimal_payload("nulls_session")
    payload.update(
        solo_dump_path=None,
        origin_dump_path=None,
        active_dump_path=None,
        scenario=None,
    )

    response = client.post("/api/sessions/", json=payload)

    assert response.status_code == 200, response.text

    loaded = client.get("/api/sessions/nulls_session").json()
    # Normalized on the way in, so nothing downstream has to handle both forms.
    assert loaded["solo_dump_path"] == ""
    assert loaded["origin_dump_path"] == ""
    assert loaded["active_dump_path"] == ""
    assert loaded["scenario"] == ""
