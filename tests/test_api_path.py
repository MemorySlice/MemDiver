"""HTTP-layer tests for api.routers.path (prefix ``/api/path``).

The path router is pure filesystem: it inspects a path and reports
metadata, or lists directory contents for a browser UI. We point every
settings-controlled directory at ``tmp_path`` (mirroring
``test_api_sessions.py``) so the app boots in isolation, then exercise
the endpoints against real files created under ``tmp_path``.
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
# GET /api/path/info
# ---------------------------------------------------------------------------


def test_info_single_file(client, isolated_env):
    """A real file is detected as ``single_file`` with correct size."""
    f = isolated_env / "sample.dump"
    payload = b"hello memdiver"
    f.write_bytes(payload)

    r = client.get("/api/path/info", params={"path": str(f)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["exists"] is True
    assert body["is_file"] is True
    assert body["is_directory"] is False
    assert body["detected_mode"] == "single_file"
    assert body["file_size"] == len(payload)


def test_info_directory_with_dump(client, isolated_env):
    """A directory containing a ``*.msl`` dump reports a dump count + mode."""
    d = isolated_env / "run_dir"
    d.mkdir()
    (d / "capture.msl").write_bytes(b"\x00\x01\x02")

    r = client.get("/api/path/info", params={"path": str(d)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_directory"] is True
    assert body["is_file"] is False
    assert body["dump_count"] >= 1
    assert body["detected_mode"] in {"run_directory", "dataset"}


def test_info_missing_path(client, isolated_env):
    """A path that does not exist reports ``exists == False``."""
    missing = isolated_env / "does_not_exist_xyz"

    r = client.get("/api/path/info", params={"path": str(missing)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["exists"] is False
    assert body["is_file"] is False
    assert body["is_directory"] is False
    assert body["detected_mode"] == "unknown"


# ---------------------------------------------------------------------------
# GET /api/path/browse
# ---------------------------------------------------------------------------


def test_browse_filters_to_dumps_and_dirs(client, isolated_env):
    """Only dump/.msl files and directories are returned; dirs sorted first."""
    d = isolated_env / "browse_root"
    d.mkdir()
    (d / "keep.msl").write_bytes(b"x")
    (d / "ignore.txt").write_text("nope")
    (d / "subdir").mkdir()

    r = client.get("/api/path/browse", params={"path": str(d)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["parent"] is not None
    entries = body["entries"]

    names = [e["name"] for e in entries]
    # The .txt file must be filtered out.
    assert "ignore.txt" not in names
    # The dump file and the directory survive.
    assert "keep.msl" in names
    assert "subdir" in names

    # Every returned file entry is a dump/.msl; dirs come first.
    file_entries = [e for e in entries if not e["is_dir"]]
    for e in file_entries:
        assert e["extension"] in {".dump", ".msl"}
    dir_flags = [e["is_dir"] for e in entries]
    # All True values (dirs) precede any False values (files).
    assert dir_flags == sorted(dir_flags, reverse=True)


def test_browse_nonexistent_path(client, isolated_env):
    """A non-existent path returns a graceful error and empty entries."""
    missing = isolated_env / "no_such_dir"

    r = client.get("/api/path/browse", params={"path": str(missing)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["error"]
    assert body["entries"] == []
