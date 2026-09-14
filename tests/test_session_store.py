"""Tests for engine/session_store.py — session save/load."""

import json
import gzip
import pytest
from pathlib import Path

from memdiver.engine.session_store import (
    SessionSnapshot, SessionStore, snapshot_from_state,
    restore_state, CURRENT_SCHEMA_VERSION, MIN_READABLE_SCHEMA_VERSION,
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
    from memdiver.ui.state import AppState
    state = AppState()
    state.dataset_root = "/tmp/data"
    state.protocol_name = "TLS"
    state.protocol_version = "12"
    state.mode = "research"
    snap = snapshot_from_state(state)
    assert snap.dataset_root == "/tmp/data"
    assert snap.mode == "research"


def test_restore_state():
    from memdiver.ui.state import AppState
    from memdiver.ui.mode import ModeManager
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


# ---------------------------------------------------------------------------
# Schema v2 — multi-dump workspace fields
# ---------------------------------------------------------------------------


def test_current_schema_version_is_two():
    assert CURRENT_SCHEMA_VERSION == 2
    assert MIN_READABLE_SCHEMA_VERSION == 1


def test_snapshot_v2_defaults():
    snap = SessionSnapshot()
    assert snap.dumps == []
    assert snap.active_dump_path == ""
    assert snap.selected_dump_paths == []
    assert snap.collapsed_dump_paths == []
    assert snap.origin_dump_path == ""
    assert snap.main_view == "single"
    assert snap.aslr_normalize is False
    assert snap.dump_weights == {}
    assert snap.excluded_dump_paths == []
    assert snap.solo_dump_path == ""
    assert snap.rail_collapsed is False


def test_save_stamps_schema_version_two(tmp_path):
    path = SessionStore.save(SessionSnapshot(session_name="v2"),
                             tmp_path / "v2.memdiver", compress=False)
    data = json.loads(path.read_text())
    assert data["schema_version"] == 2


def test_load_v1_file_without_dumps_key_uses_defaults(tmp_path):
    """A literal v1 file needs no migration shim — defaults fill in."""
    data = {"_memdiver_session": True, "schema_version": 1,
            "session_name": "legacy_v1", "mode": "testing",
            "input_path": "/tmp/old.msl",
            "selected_libraries": [], "bookmarks": []}
    path = tmp_path / "legacy.memdiver"
    path.write_text(json.dumps(data))

    snap = SessionStore.load(path)
    assert snap.session_name == "legacy_v1"
    assert snap.input_path == "/tmp/old.msl"
    # The file's own version is preserved, not silently rewritten on load.
    assert snap.schema_version == 1
    # Every v2 field falls back to its default.
    assert snap.dumps == []
    assert snap.main_view == "single"
    assert snap.dump_weights == {}
    assert snap.rail_collapsed is False


def test_load_rejects_too_old_version(tmp_path):
    data = {"_memdiver_session": True, "schema_version": 0}
    path = tmp_path / "ancient.memdiver"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="older than supported"):
        SessionStore.load(path)


def test_dumps_weights_solo_roundtrip(tmp_path):
    snap = SessionSnapshot(
        session_name="workspace",
        dumps=[
            {"path": "/d/a.msl", "name": "a.msl", "size": 1024, "format": "msl"},
            {"path": "/d/b.raw", "name": "b.raw", "size": 2048, "format": "raw"},
        ],
        active_dump_path="/d/b.raw",
        selected_dump_paths=["/d/a.msl", "/d/b.raw"],
        collapsed_dump_paths=["/d/a.msl"],
        origin_dump_path="/d/a.msl",
        main_view="overlay",
        aslr_normalize=True,
        dump_weights={"/d/a.msl": 0.5, "/d/b.raw": 2.0},
        excluded_dump_paths=["/d/b.raw"],
        solo_dump_path="/d/a.msl",
        rail_collapsed=True,
    )
    path = SessionStore.save(snap, tmp_path / "ws.memdiver")
    loaded = SessionStore.load(path)

    assert loaded.dumps == snap.dumps
    assert loaded.active_dump_path == "/d/b.raw"
    assert loaded.selected_dump_paths == ["/d/a.msl", "/d/b.raw"]
    assert loaded.collapsed_dump_paths == ["/d/a.msl"]
    assert loaded.origin_dump_path == "/d/a.msl"
    assert loaded.main_view == "overlay"
    assert loaded.aslr_normalize is True
    assert loaded.dump_weights == {"/d/a.msl": 0.5, "/d/b.raw": 2.0}
    assert loaded.excluded_dump_paths == ["/d/b.raw"]
    assert loaded.solo_dump_path == "/d/a.msl"
    assert loaded.rail_collapsed is True
    assert loaded.schema_version == CURRENT_SCHEMA_VERSION


def test_list_sessions_reports_dump_count(tmp_path):
    SessionStore.save(
        SessionSnapshot(
            session_name="two_dumps",
            dumps=[{"path": "/d/a", "name": "a", "size": 1, "format": "raw"},
                   {"path": "/d/b", "name": "b", "size": 2, "format": "raw"}],
        ),
        tmp_path / "two_dumps.memdiver",
    )
    SessionStore.save(SessionSnapshot(session_name="no_dumps"),
                      tmp_path / "no_dumps.memdiver")
    # A literal v1 file, which has no `dumps` key at all.
    (tmp_path / "legacy.memdiver").write_text(json.dumps(
        {"_memdiver_session": True, "schema_version": 1,
         "session_name": "legacy"}
    ))

    by_name = {s["name"]: s for s in SessionStore.list_sessions(tmp_path)}
    assert by_name["two_dumps"]["dump_count"] == 2
    assert by_name["no_dumps"]["dump_count"] == 0
    assert by_name["legacy"]["dump_count"] == 0


def test_list_sessions_corrupt_file_reports_zero_dump_count(tmp_path):
    (tmp_path / "corrupt.memdiver").write_bytes(b"\x1f\x8b not really gzip")
    listed = SessionStore.list_sessions(tmp_path)
    assert len(listed) == 1
    assert listed[0]["name"] == "corrupt"
    assert listed[0]["dump_count"] == 0
