"""HTTP-layer tests for api.routers.structures.

Exercise the public REST contract for structure-definition CRUD. We
monkeypatch the user-structure directory into ``tmp_path`` so the tests
never touch the real ``~/.memdiver/structures/`` directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api.routers.structures as structures_router
import core.structure_loader as structure_loader
from api.config import get_settings
from api.main import create_app
from core.structure_library import StructureLibrary


# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch):
    """Redirect every settings-controlled directory + the user-structure dir."""
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

    # Redirect user-structure persistence to tmp_path. The router calls
    # ``save_user_structure(sd)`` with no directory arg, which binds the
    # default at function-definition time -- so we patch __defaults__ in
    # addition to the module-level constants.
    user_dir = tmp_path / "structures"
    user_dir.mkdir()
    monkeypatch.setattr(structure_loader, "DEFAULT_USER_DIR", user_dir)
    monkeypatch.setattr(structures_router, "DEFAULT_USER_DIR", user_dir)
    monkeypatch.setattr(
        structure_loader.save_user_structure,
        "__defaults__",
        (user_dir,),
    )
    monkeypatch.setattr(
        structure_loader.load_user_structures,
        "__defaults__",
        (user_dir,),
    )

    # Reset the global structure library so each test starts from a clean
    # slate (otherwise test order would leak created/deleted structures).
    import core.structure_library as lib_mod
    monkeypatch.setattr(lib_mod, "_library", None)

    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(isolated_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# /api/structures/list
# ---------------------------------------------------------------------------


def test_list_structures_returns_builtins(client):
    """list returns at least the built-in structure definitions."""
    r = client.get("/api/structures/list")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    # The library auto-registers built-in TLS/SSH/AES structures.
    assert len(body) > 0
    sample = body[0]
    for key in ("name", "protocol", "description", "total_size",
                "field_count", "tags"):
        assert key in sample, f"missing key: {key}"


# ---------------------------------------------------------------------------
# /api/structures/create
# ---------------------------------------------------------------------------


def _valid_create_payload(name: str = "user_struct_demo") -> dict:
    """A small but schema-valid structure-create payload."""
    return {
        "name": name,
        "total_size": 16,
        "protocol": "test",
        "description": "synthetic test structure",
        "tags": ["test"],
        "fields": [
            {"name": "field_a", "field_type": "uint32_le",
             "offset": 0, "size": 4},
            {"name": "field_b", "field_type": "uint32_le",
             "offset": 4, "size": 4},
            {"name": "field_c", "field_type": "bytes",
             "offset": 8, "size": 8},
        ],
    }


def test_create_structure_happy_path(client, isolated_env):
    """POST /create persists the JSON file and registers the library entry."""
    payload = _valid_create_payload()
    r = client.post("/api/structures/create", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == payload["name"]
    persisted = Path(body["path"])
    # The persisted JSON file lives under the redirected user dir.
    assert persisted.is_file()
    assert persisted.parent == isolated_env / "structures"

    # And the library can now look it up via GET /{name}.
    r2 = client.get(f"/api/structures/{payload['name']}")
    assert r2.status_code == 200
    assert r2.json()["name"] == payload["name"]


def test_create_structure_400_on_invalid_payload(client):
    """A semantically invalid payload (overflow) returns 400, not 422."""
    payload = _valid_create_payload(name="overflow_struct")
    # Field extends beyond total_size -> validate_structure_json fails.
    payload["fields"][0]["size"] = 999
    r = client.post("/api/structures/create", json=payload)
    assert r.status_code == 400
    # Detail is the list of error strings from validate_structure_json.
    assert isinstance(r.json()["detail"], list)


# ---------------------------------------------------------------------------
# /api/structures/{name}
# ---------------------------------------------------------------------------


def test_get_structure_404_on_unknown_name(client):
    """A name that isn't registered returns 404."""
    r = client.get("/api/structures/this_does_not_exist_anywhere")
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# DELETE /api/structures/{name}
# ---------------------------------------------------------------------------


def test_delete_structure_round_trip(client, isolated_env):
    """create -> delete removes both the file and the library entry."""
    payload = _valid_create_payload(name="deletable_struct")
    r = client.post("/api/structures/create", json=payload)
    assert r.status_code == 200, r.text

    r = client.delete(f"/api/structures/{payload['name']}")
    assert r.status_code == 200
    assert r.json()["deleted"] == payload["name"]

    # Subsequent GET 404s.
    r = client.get(f"/api/structures/{payload['name']}")
    assert r.status_code == 404
