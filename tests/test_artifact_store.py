"""Tests for api.services.artifact_store — per-task dirs + traversal guard + GC."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from api.services.artifact_store import (
    ArtifactNotFound,
    ArtifactStore,
    InvalidArtifactName,
)


def _store(tmp_path: Path, quota: int = 1024 * 1024) -> ArtifactStore:
    return ArtifactStore(tmp_path / "store", max_total_bytes=quota)


# ---------- task dir lifecycle ----------


def test_task_dir_creates_locked_down_dir(tmp_path):
    store = _store(tmp_path)
    path = store.task_dir("abc123")
    assert path.is_dir()
    # Mode bits should be 0o700 for the task dir.
    mode = path.stat().st_mode & 0o777
    assert mode == 0o700


def test_task_dir_unsafe_names_rejected(tmp_path):
    store = _store(tmp_path)
    for bad in ("", "..", ".", "../escape", "a/b", ".hidden"):
        with pytest.raises(InvalidArtifactName):
            store.task_dir(bad)


def test_exists_and_delete_task(tmp_path):
    store = _store(tmp_path)
    store.task_dir("t1")
    assert store.exists("t1")
    store.delete_task("t1")
    assert not store.exists("t1")


# ---------- write + register + open ----------


def test_register_and_open_roundtrip(tmp_path):
    store = _store(tmp_path)
    path = store.resolve_write_path("t1", "emit_plugin/plugin.py")
    path.write_text("print('hello')\n")
    spec = store.register("t1", "plugin", "emit_plugin/plugin.py", media_type="text/x-python")
    assert spec.size == len("print('hello')\n")
    listed = store.list("t1")
    assert len(listed) == 1 and listed[0].name == "plugin"
    opened = store.open("t1", "plugin")
    assert opened.read_text() == "print('hello')\n"


def test_open_unknown_artifact_raises(tmp_path):
    store = _store(tmp_path)
    store.task_dir("t1")
    with pytest.raises(ArtifactNotFound):
        store.open("t1", "missing")


# ---------- traversal guards ----------


def test_relpath_traversal_blocked(tmp_path):
    store = _store(tmp_path)
    store.task_dir("t1")
    for bad in ("../escape.txt", "/abs.txt", "nested/../../oops.txt"):
        with pytest.raises(InvalidArtifactName):
            store.resolve_write_path("t1", bad)


def test_symlink_escape_blocked(tmp_path):
    store = _store(tmp_path)
    base = store.task_dir("t1")
    target = tmp_path / "outside.txt"
    target.write_text("forbidden")
    (base / "bad").symlink_to(target)
    # Register must refuse the symlink so the artifact never becomes
    # available to the download endpoint.
    with pytest.raises(InvalidArtifactName):
        store.register("t1", "bad", "bad", media_type="text/plain")


# ---------- quota-based GC ----------


def test_total_bytes_sums_files(tmp_path):
    store = _store(tmp_path)
    store.resolve_write_path("t1", "a.bin").write_bytes(b"x" * 1000)
    store.resolve_write_path("t2", "b.bin").write_bytes(b"y" * 2000)
    assert store.total_bytes() == 3000


def test_gc_evicts_oldest_terminal_tasks(tmp_path):
    store = _store(tmp_path, quota=500)
    store.resolve_write_path("old", "a.bin").write_bytes(b"x" * 1000)
    time.sleep(0.01)
    store.resolve_write_path("new", "a.bin").write_bytes(b"x" * 1000)
    removed = store.gc(terminal_ids=["old", "new"], running_ids=[])
    # Oldest one got evicted first; once under quota, GC stops.
    assert "old" in removed
    assert not (store.root / "old").exists()


def test_gc_never_evicts_running_tasks(tmp_path):
    store = _store(tmp_path, quota=500)
    store.resolve_write_path("running", "a.bin").write_bytes(b"x" * 10000)
    removed = store.gc(terminal_ids=["running"], running_ids=["running"])
    assert removed == []
    assert (store.root / "running").exists()


def test_gc_noop_when_under_quota(tmp_path):
    store = _store(tmp_path, quota=10_000)
    store.resolve_write_path("t1", "a.bin").write_bytes(b"x" * 100)
    assert store.gc(terminal_ids=["t1"], running_ids=[]) == []


def test_store_root_locked_down(tmp_path):
    store = _store(tmp_path)
    mode = store.root.stat().st_mode & 0o777
    assert mode == 0o700
