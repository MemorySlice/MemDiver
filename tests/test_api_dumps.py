"""HTTP-layer tests for api.routers.dumps (prefix ``/api/dumps``).

The dumps router exposes ``POST /api/dumps/upload`` which streams a
multipart file to a temp path, enforces a 4 GiB size cap
(``DUMP_UPLOAD_MAX_BYTES``), then converts it via ``tools.import_raw_dump``.

We redirect every settings-controlled directory into ``tmp_path`` (same
fixtures as tests/test_api_sessions.py) and monkeypatch
``import_raw_dump`` for the happy path so the test doesn't depend on the
real MSL importer accepting garbage bytes.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import get_settings
from api.main import create_app
from api.routers import dumps as dumps_router
from mcp_server import tools


# ---------------------------------------------------------------------------
# Fixtures (copied verbatim from tests/test_api_sessions.py)
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
# POST /api/dumps/upload — happy path
# ---------------------------------------------------------------------------


def test_upload_dump_happy_path(client, monkeypatch):
    """A valid upload streams through to ``import_raw_dump`` and returns
    its dict result. We patch ``import_raw_dump`` where the router calls
    it (``mcp_server.tools.import_raw_dump``) so the test does not depend
    on the real MSL importer parsing garbage bytes.
    """
    sentinel = {"source": "x", "output": "y", "regions_written": 3}

    def _fake_import(session, raw_path, output_path, pid=0):
        # The router should have written the uploaded bytes to a real temp
        # file before calling us.
        assert Path(raw_path).is_file()
        return sentinel

    monkeypatch.setattr(tools, "import_raw_dump", _fake_import)

    r = client.post(
        "/api/dumps/upload",
        files={"file": ("t.dump", b"\x00\x01\x02\x03small", "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    assert body == sentinel


# ---------------------------------------------------------------------------
# POST /api/dumps/upload — missing file → 422
# ---------------------------------------------------------------------------


def test_upload_dump_missing_file_is_422(client):
    """``file`` is a required multipart field → 422 when absent."""
    r = client.post("/api/dumps/upload")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/dumps/upload — size cap → 413
# ---------------------------------------------------------------------------


def test_upload_dump_over_cap_is_413(client, monkeypatch):
    """An upload larger than the size cap is rejected with 413.

    We shrink the module-level ``DUMP_UPLOAD_MAX_BYTES`` constant so we
    don't have to stream 4 GiB.
    """
    monkeypatch.setattr(dumps_router, "DUMP_UPLOAD_MAX_BYTES", 1024)

    payload = b"a" * 2048  # > 1024-byte cap
    r = client.post(
        "/api/dumps/upload",
        files={"file": ("big.dump", payload, "application/octet-stream")},
    )
    assert r.status_code == 413
    assert "cap" in r.json()["detail"].lower()
