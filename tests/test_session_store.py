"""Tests for engine/session_store.py — session save/load."""

import json
import gzip
import pytest
from pathlib import Path

from engine.session_store import (
    SessionSnapshot, SessionStore, snapshot_from_state,
    restore_state, CURRENT_SCHEMA_VERSION,
)


def test_snapshot_defaults():
    snap = SessionSnapshot()
    assert snap.schema_version == CURRENT_SCHEMA_VERSION
    assert snap.mode == "testing"
    assert snap.selected_libraries == []
    assert snap.bookmarks == []
    assert snap.analysis_result is None


def test_save_load_roundtrip(tmp_path):
    snap = SessionSnapshot(
        session_name="test_session",
        input_mode="dataset",
        dataset_root="/tmp/test",
        protocol_name="TLS",
        protocol_version="13",
        scenario="default",
        selected_libraries=["openssl", "boringssl"],
        selected_phase="post_handshake",
        algorithm="exact_match",
        mode="research",
        max_runs=5,
    )
    path = tmp_path / "test.memdiver"
    saved = SessionStore.save(snap, path)
    assert saved.exists()

    loaded = SessionStore.load(saved)
    assert loaded.session_name == "test_session"
    assert loaded.input_mode == "dataset"
    assert loaded.protocol_version == "13"
    assert loaded.selected_libraries == ["openssl", "boringssl"]
    assert loaded.mode == "research"
    assert loaded.max_runs == 5


def test_save_compressed(tmp_path):
    snap = SessionSnapshot(session_name="compressed")
    path = SessionStore.save(snap, tmp_path / "c.memdiver", compress=True)
    raw = path.read_bytes()
    assert raw[:2] == b"\x1f\x8b"  # gzip magic


def test_save_uncompressed(tmp_path):
    snap = SessionSnapshot(session_name="plain")
    path = SessionStore.save(snap, tmp_path / "p.memdiver", compress=False)
    data = json.loads(path.read_text())
    assert data["_memdiver_session"] is True
    assert data["session_name"] == "plain"


def test_load_uncompressed(tmp_path):
    data = {"_memdiver_session": True, "schema_version": 1,
            "session_name": "raw", "mode": "testing",
            "selected_libraries": [], "bookmarks": []}
    path = tmp_path / "raw.memdiver"
    path.write_text(json.dumps(data))
    snap = SessionStore.load(path)
    assert snap.session_name == "raw"


def test_load_rejects_non_session(tmp_path):
    path = tmp_path / "bad.memdiver"
    path.write_text(json.dumps({"not_a_session": True}))
    with pytest.raises(ValueError, match="Not a MemDiver"):
        SessionStore.load(path)


def test_load_rejects_future_version(tmp_path):
    data = {"_memdiver_session": True, "schema_version": 999}
    path = tmp_path / "future.memdiver"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="newer than supported"):
        SessionStore.load(path)


def test_load_ignores_unknown_fields(tmp_path):
    data = {"_memdiver_session": True, "schema_version": 1,
            "session_name": "compat", "future_field": "ignored"}
    path = tmp_path / "compat.memdiver"
    path.write_text(json.dumps(data))
    snap = SessionStore.load(path)
    assert snap.session_name == "compat"


def test_auto_save_path():
    path = SessionStore.auto_save_path("test")
    assert path.suffix == ".memdiver"
    assert "test" in path.stem


def test_list_sessions(tmp_path):
    for name in ["a", "b", "c"]:
        snap = SessionSnapshot(session_name=name)
        SessionStore.save(snap, tmp_path / f"{name}.memdiver")
    sessions = SessionStore.list_sessions(tmp_path)
    assert len(sessions) == 3
    names = [s["name"] for s in sessions]
    assert "a" in names


def test_snapshot_from_state():
    from ui.state import AppState
    state = AppState()
    state.dataset_root = "/tmp/data"
    state.protocol_name = "TLS"
    state.protocol_version = "12"
    state.mode = "research"
    snap = snapshot_from_state(state)
    assert snap.dataset_root == "/tmp/data"
    assert snap.mode == "research"


def test_restore_state():
    from ui.state import AppState
    from ui.mode import ModeManager
    state = AppState()
    mgr = ModeManager()
    snap = SessionSnapshot(
        protocol_name="TLS", protocol_version="13",
        mode="research", scenario="test_scenario",
    )
    restore_state(state, snap, mgr)
    assert state.protocol_version == "13"
    assert state.scenario == "test_scenario"
    assert mgr.mode == "research"


def test_bookmarks_roundtrip(tmp_path):
    snap = SessionSnapshot(
        session_name="bm",
        bookmarks=[{"offset": 100, "length": 32, "label": "master_secret"}],
    )
    path = SessionStore.save(snap, tmp_path / "bm.memdiver")
    loaded = SessionStore.load(path)
    assert len(loaded.bookmarks) == 1
    assert loaded.bookmarks[0]["label"] == "master_secret"
