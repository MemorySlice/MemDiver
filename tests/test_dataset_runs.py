"""Populated-run serialization tests for ``GET /api/dataset/runs``.

``tests/test_api_dataset.py`` already covers the empty-run and 404 shapes,
but its run dirs carry no ``meta.json`` or dump files, so the serialization
helpers in ``api.routers.dataset`` (``_load_run_entry``, ``_dump_to_dict``,
``_meta_to_dict``) never execute. These tests build a real run directory
under ``tmp_path`` — a ``meta.json`` next to an ``.msl`` dump — so the
endpoint drives the full populated path: dump enumeration, ``bytes -> hex``
master-key rendering, and the ``dumps`` subtree.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app


# ---------------------------------------------------------------------------
# Fixtures (mirror tests/test_api_dataset.py)
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
# Helpers — build a valid dataset-style run directory on disk
# ---------------------------------------------------------------------------

MASTER_KEY_HEX = "0011223344556677"


def _make_run_dir(run_dir: Path, *, msl_size: int = 48) -> Path:
    """Create ``run_dir`` with a ``meta.json`` + an ``.msl`` dump file.

    The layout mirrors the *dataset_memory_slice* corpus: ``meta.json``
    references dumps by a ``<run>/<file>`` path relative to the dataset
    root (``run_dir.parent``), which is how ``load_run_meta`` resolves
    them. Presence of ``meta.json`` makes the directory register as a
    dataset-style run even though its name is not the legacy
    ``<lib>_run_<ver>_<n>`` shape.
    """
    run_dir.mkdir(parents=True)
    msl_path = run_dir / "test_capture.msl"
    msl_path.write_bytes(b"MSL0" + b"\x00" * (msl_size - 4))

    meta = {
        "run_id": run_dir.name,
        "cipher": "AES-256-GCM",
        "password": "hunter2",
        "master_key_hex": MASTER_KEY_HEX,
        "aslr_base": "0x400000",
        "pid": 4321,
        "dumps": {
            "memslicer": {
                "path": f"{run_dir.name}/{msl_path.name}",
                "size": msl_size,
            },
        },
    }
    (run_dir / "meta.json").write_text(json.dumps(meta))
    return msl_path


def _assert_populated_run(run: dict, msl_path: Path, msl_size: int) -> None:
    """Shared assertions for a serialized populated run entry."""
    # meta.json -> _meta_to_dict, with bytes rendered as hex.
    meta = run["meta"]
    assert meta is not None
    assert meta["cipher"] == "AES-256-GCM"
    assert meta["password"] == "hunter2"
    assert meta["master_key"] == MASTER_KEY_HEX  # bytes -> hex string
    assert meta["pid"] == 4321
    assert "msl" in meta["dumps"]  # 'memslicer' aliased to canonical 'msl'
    assert meta["dumps"]["msl"]["size"] == msl_size

    # The .msl file -> _dump_to_dict via RunDiscovery dataset-dump parsing.
    dumps = run["dumps"]
    assert len(dumps) == 1
    dump = dumps[0]
    assert dump["kind"] == "msl"
    assert dump["path"] == str(msl_path)
    assert dump["size"] == msl_size
    assert dump["phase"] == "full_msl"


# ---------------------------------------------------------------------------
# GET /api/dataset/runs — populated serialization
# ---------------------------------------------------------------------------


def test_list_runs_populated_child_run(client, isolated_env):
    """A dataset root with populated child runs serializes dumps + meta.

    Two children exercise both discovery branches:

    * ``run_0001`` — dataset-style (recognised via ``meta.json``), so it
      carries a serialized ``meta`` block with the hex master key.
    * ``openssl_run_5_1`` — legacy ``<lib>_run_<ver>_<n>`` naming with no
      ``meta.json``, so its ``meta`` serializes to ``None`` while its
      ``.msl`` dump is still enumerated.
    """
    root = isolated_env / "dataset_root"
    root.mkdir()
    msl_size = 48
    dataset_child = root / "run_0001"
    dataset_msl = _make_run_dir(dataset_child, msl_size=msl_size)

    legacy_child = root / "openssl_run_5_1"
    legacy_child.mkdir()
    legacy_msl = legacy_child / "test_capture.msl"
    legacy_msl.write_bytes(b"MSL0" + b"\x00" * 28)  # 32 bytes, no meta.json

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    runs = r.json()["runs"]
    by_path = {run["path"]: run for run in runs}
    assert str(dataset_child) in by_path
    assert str(legacy_child) in by_path

    _assert_populated_run(by_path[str(dataset_child)], dataset_msl, msl_size)

    legacy = by_path[str(legacy_child)]
    assert legacy["meta"] is None  # no meta.json → _meta_to_dict(None)
    assert [d["kind"] for d in legacy["dumps"]] == ["msl"]
    assert legacy["dumps"][0]["path"] == str(legacy_msl)


def test_list_runs_root_is_itself_a_run(client, isolated_env):
    """When ``root`` itself is a run dir it is returned as the sole entry."""
    root = isolated_env / "single_run"
    msl_size = 64
    msl_path = _make_run_dir(root, msl_size=msl_size)

    r = client.get("/api/dataset/runs", params={"root": str(root)})
    assert r.status_code == 200, r.text
    runs = r.json()["runs"]
    assert len(runs) == 1

    run = runs[0]
    assert run["path"] == str(root)
    _assert_populated_run(run, msl_path, msl_size)


def test_list_runs_404_on_missing_root(client, isolated_env):
    """A non-existent ``root`` path yields 404."""
    missing = isolated_env / "does_not_exist"
    r = client.get("/api/dataset/runs", params={"root": str(missing)})
    assert r.status_code == 404
