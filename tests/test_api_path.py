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


# ---------------------------------------------------------------------------
# GET /api/path/browse — opt-in all_files filter
# ---------------------------------------------------------------------------


def test_browse_default_is_unchanged_when_all_files_omitted(client, isolated_env):
    """Omitting ``all_files`` yields byte-identical output to today's call."""
    d = isolated_env / "browse_compat"
    d.mkdir()
    (d / "keep.msl").write_bytes(b"x")
    (d / "jxSMOg-V7hYDb5UsGpxWxg").write_bytes(b"ciphertext")
    (d / "ignore.txt").write_text("nope")
    (d / "subdir").mkdir()

    implicit = client.get("/api/path/browse", params={"path": str(d)})
    explicit = client.get(
        "/api/path/browse", params={"path": str(d), "all_files": "false"}
    )
    assert implicit.status_code == 200, implicit.text
    assert implicit.json() == explicit.json()

    names = [e["name"] for e in implicit.json()["entries"]]
    assert names == ["subdir", "keep.msl"]


def test_browse_all_files_surfaces_extensionless_file(client, isolated_env):
    """``all_files=true`` shows a file with no extension at all."""
    d = isolated_env / "browse_all"
    d.mkdir()
    (d / "keep.msl").write_bytes(b"x")
    (d / "jxSMOg-V7hYDb5UsGpxWxg").write_bytes(b"ciphertext")
    (d / "notes.txt").write_text("hi")

    r = client.get("/api/path/browse", params={"path": str(d), "all_files": "true"})
    assert r.status_code == 200, r.text
    names = [e["name"] for e in r.json()["entries"]]
    assert "jxSMOg-V7hYDb5UsGpxWxg" in names
    assert "notes.txt" in names
    assert "keep.msl" in names

    ciphertext = next(
        e for e in r.json()["entries"] if e["name"] == "jxSMOg-V7hYDb5UsGpxWxg"
    )
    assert ciphertext["extension"] == ""
    assert ciphertext["size"] == len(b"ciphertext")


# ---------------------------------------------------------------------------
# GET /api/path/discover-dumps
# ---------------------------------------------------------------------------


def _make_corpus(root: Path) -> Path:
    """Build a corpus whose runs sit four levels below the root.

    This is the shape the endpoint exists for: ``/api/dataset/runs`` is depth
    <= 1 and ``/api/path/browse`` is single-level, so both find nothing here.
    """
    deep = root / "tls_dumps" / "wolfssl" / "v5.6" / "wolfssl_run_1_1"
    deep.mkdir(parents=True)
    (deep / "memslicer.msl").write_bytes(b"msl")
    (deep / "gcore.core").write_bytes(b"core")
    (deep / "gdb_raw.bin").write_bytes(b"gdb")
    (deep / "gdb_raw.maps").write_text("not a dump")
    (deep / "keylog.csv").write_text("not a dump")
    return root / "tls_dumps"


def test_discover_finds_dumps_several_levels_down(client, isolated_env):
    """A recursive scan reaches runs that sit four levels below the root."""
    corpus = _make_corpus(isolated_env)

    r = client.get(
        "/api/path/discover-dumps", params={"path": str(corpus), "kinds": "msl"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    assert body["truncated"] is False
    entry = body["dumps"][0]
    assert entry["path"].endswith("memslicer.msl")
    assert entry["kind"] == "msl"
    assert entry["size"] == len(b"msl")
    assert entry["run"] == "wolfssl_run_1_1"


def test_discover_defaults_to_msl(client, isolated_env):
    """With no ``kinds`` the endpoint returns only ``.msl`` dumps."""
    corpus = _make_corpus(isolated_env)

    r = client.get("/api/path/discover-dumps", params={"path": str(corpus)})
    assert r.status_code == 200, r.text
    assert [e["kind"] for e in r.json()["dumps"]] == ["msl"]


def test_discover_kinds_filter_accepts_repeat_and_comma_forms(client, isolated_env):
    """``kinds=a&kinds=b`` and ``kinds=a,b`` select the same dumps."""
    corpus = _make_corpus(isolated_env)

    repeated = client.get(
        "/api/path/discover-dumps",
        params=[("path", str(corpus)), ("kinds", "gcore"), ("kinds", "gdb_raw")],
    )
    comma = client.get(
        "/api/path/discover-dumps",
        params={"path": str(corpus), "kinds": "gcore,gdb_raw"},
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json() == comma.json()
    assert sorted(e["kind"] for e in comma.json()["dumps"]) == ["gcore", "gdb_raw"]


def test_discover_counts_by_kind_ignores_the_kinds_filter(client, isolated_env):
    """``counts_by_kind`` covers everything found, not just the selected kinds.

    The UI renders it as kind checkboxes with counts; filtering it first would
    make the unselected kinds vanish from the picker.
    """
    corpus = _make_corpus(isolated_env)

    r = client.get(
        "/api/path/discover-dumps", params={"path": str(corpus), "kinds": "msl"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["dumps"]) == 1
    assert body["counts_by_kind"] == {"msl": 1, "gcore": 1, "gdb_raw": 1}


def test_discover_skips_non_dump_files_and_dot_directories(client, isolated_env):
    """Sidecars are not dumps, and dot-directories are never entered."""
    corpus = _make_corpus(isolated_env)
    hidden = corpus / ".cache" / "run"
    hidden.mkdir(parents=True)
    (hidden / "hidden.msl").write_bytes(b"msl")

    r = client.get(
        "/api/path/discover-dumps",
        params={"path": str(corpus), "kinds": "msl,gcore,gdb_raw,lldb_raw,raw"},
    )
    assert r.status_code == 200, r.text
    names = [Path(e["path"]).name for e in r.json()["dumps"]]
    assert "hidden.msl" not in names
    assert "gdb_raw.maps" not in names
    assert "keylog.csv" not in names


def test_discover_non_recursive_stays_at_one_level(client, isolated_env):
    """``recursive=false`` lists only the directory it was handed."""
    corpus = _make_corpus(isolated_env)

    r = client.get(
        "/api/path/discover-dumps",
        params={"path": str(corpus), "kinds": "msl", "recursive": "false"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 0


def test_discover_returns_sorted_paths(client, isolated_env):
    """Order is deterministic — consensus alignment pairs dumps positionally."""
    root = isolated_env / "sorted_corpus"
    for run in ("run_0003", "run_0001", "run_0002"):
        d = root / "nested" / run
        d.mkdir(parents=True)
        (d / "memslicer.msl").write_bytes(b"msl")

    r = client.get(
        "/api/path/discover-dumps", params={"path": str(root), "kinds": "msl"}
    )
    assert r.status_code == 200, r.text
    paths = [e["path"] for e in r.json()["dumps"]]
    assert paths == sorted(paths)
    assert [Path(p).parent.name for p in paths] == ["run_0001", "run_0002", "run_0003"]


def test_discover_truncates_on_result_cap(client, isolated_env):
    """More results than ``limit`` reports ``truncated`` instead of silently cutting."""
    root = isolated_env / "many"
    root.mkdir()
    for i in range(5):
        (root / f"dump_{i}.msl").write_bytes(b"msl")

    r = client.get(
        "/api/path/discover-dumps",
        params={"path": str(root), "kinds": "msl", "limit": 2},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["truncated"] is True
    assert len(body["dumps"]) == 2
    # ``total`` still reports the full count behind the cap.
    assert body["total"] == 5
    # The returned page is the deterministic prefix of the sorted list.
    assert [Path(e["path"]).name for e in body["dumps"]] == ["dump_0.msl", "dump_1.msl"]


def test_discover_limit_is_clamped_to_the_server_cap(client, isolated_env, monkeypatch):
    """A caller cannot ask for more than the module's own result ceiling."""
    from memdiver.api.routers import path as path_router

    monkeypatch.setattr(path_router, "_DISCOVER_MAX_RESULTS", 2)
    root = isolated_env / "clamped"
    root.mkdir()
    for i in range(4):
        (root / f"dump_{i}.msl").write_bytes(b"msl")

    r = client.get(
        "/api/path/discover-dumps",
        params={"path": str(root), "kinds": "msl", "limit": 10_000},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["dumps"]) == 2
    assert body["truncated"] is True


def test_discover_truncates_on_walk_cap(client, isolated_env, monkeypatch):
    """Exhausting the file budget reports ``truncated``, never a partial silence."""
    from memdiver.api.routers import path as path_router

    monkeypatch.setattr(path_router, "_DISCOVER_MAX_FILES", 2)
    root = isolated_env / "walk_capped"
    root.mkdir()
    for i in range(6):
        (root / f"dump_{i}.msl").write_bytes(b"msl")

    r = client.get(
        "/api/path/discover-dumps", params={"path": str(root), "kinds": "msl"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["truncated"] is True


def test_discover_terminates_on_symlink_cycle(client, isolated_env):
    """A directory symlink pointing at its own ancestor must not loop."""
    root = isolated_env / "loop_corpus"
    inner = root / "runs" / "run_0001"
    inner.mkdir(parents=True)
    (inner / "memslicer.msl").write_bytes(b"msl")
    try:
        (inner / "back").symlink_to(root, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - platform guard
        pytest.skip("symlinks unavailable on this platform")

    r = client.get(
        "/api/path/discover-dumps", params={"path": str(root), "kinds": "msl"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # Exactly one dump: the cycle was never entered, so it was not counted twice.
    assert body["total"] == 1
    assert body["truncated"] is False


def test_discover_nonexistent_and_file_paths_match_browse_style(client, isolated_env):
    """Bad input mirrors ``browse``'s ``{"error": ...}`` contract, not a raise."""
    missing = isolated_env / "no_such_corpus"
    r = client.get("/api/path/discover-dumps", params={"path": str(missing)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["error"] == "Path does not exist"
    assert body["dumps"] == []
    assert body["counts_by_kind"] == {}

    f = isolated_env / "plain.msl"
    f.write_bytes(b"msl")
    r = client.get("/api/path/discover-dumps", params={"path": str(f)})
    assert r.status_code == 200, r.text
    assert r.json()["error"] == "Path is not a directory"


def test_discover_requires_a_path(client):
    """``path`` is required — omitting it is a validation error, not a home scan."""
    r = client.get("/api/path/discover-dumps")
    assert r.status_code == 422


def test_discover_on_the_gocryptfs_fixture(client):
    """Real-data smoke test against the checked-in gocryptfs dataset."""
    fixture = Path(__file__).resolve().parent / "fixtures" / "datasets" / "gocryptfs"
    assert fixture.is_dir(), fixture

    r = client.get(
        "/api/path/discover-dumps",
        params={"path": str(fixture), "kinds": "gdb_raw,lldb_raw"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    names = [Path(e["path"]).name for e in body["dumps"]]
    assert names == ["gdb_raw.bin", "lldb_raw.bin"]
    assert {e["run"] for e in body["dumps"]} == {"run_0001"}
    assert body["counts_by_kind"] == {"gdb_raw": 1, "lldb_raw": 1}
