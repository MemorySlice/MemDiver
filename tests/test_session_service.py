"""Unit tests for ``api.services.session_service``.

Pins the contract that used to live inline inside the sessions router
so a router refactor or a transport swap cannot silently drop fields on
save. Complements the HTTP-level coverage in ``test_session_roundtrip.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.services import session_service
from engine.session_store import CURRENT_SCHEMA_VERSION, SessionSnapshot, SessionStore


FULL_PAYLOAD = {
    "schema_version": 42,  # client-sent; must be ignored — server stamps own
    "session_name": "svc_unit",
    "input_mode": "file",
    "input_path": "/tmp/x.msl",
    "dataset_root": "/tmp/ds",
    "keylog_filename": "my.csv",
    "template_name": "TLS1.3",
    "protocol_name": "TLS",
    "protocol_version": "13",
    "scenario": "abort",
    "selected_libraries": ["boringssl"],
    "selected_phase": "pre_abort",
    "algorithm": "exact_match",
    "mode": "testing",
    "max_runs": 5,
    "normalize_phases": True,
    "single_file_format": "msl",
    "ground_truth_mode": "manual",
    "selected_algorithms": ["entropy_scan", "differential"],
    "analysis_result": {"sentinel": "svc"},
    "bookmarks": [{"offset": 16, "length": 4, "label": "b"}],
    "investigation_offset": 128,
}


def test_payload_to_snapshot_maps_every_field():
    snap = session_service.payload_to_snapshot(FULL_PAYLOAD, memdiver_version="x.y")
    assert isinstance(snap, SessionSnapshot)
    # Every data field must round-trip.
    for key in FULL_PAYLOAD:
        if key == "schema_version":
            continue  # server-authoritative
        assert getattr(snap, key) == FULL_PAYLOAD[key], key
    # Server-stamped metadata.
    assert snap.schema_version == CURRENT_SCHEMA_VERSION
    assert snap.memdiver_version == "x.y"
    assert snap.created_at != ""


def test_payload_to_snapshot_ignores_unknown_keys():
    payload = dict(FULL_PAYLOAD)
    payload["not_a_real_field"] = "nope"
    snap = session_service.payload_to_snapshot(payload)
    # Should not raise and should ignore the unknown.
    assert snap.session_name == FULL_PAYLOAD["session_name"]


def test_payload_to_snapshot_stamps_schema_version_even_if_client_sent_one():
    snap = session_service.payload_to_snapshot({"schema_version": 99})
    assert snap.schema_version == CURRENT_SCHEMA_VERSION


def test_save_and_load_round_trip(tmp_path):
    saved_path = session_service.save_session(
        FULL_PAYLOAD, tmp_path, memdiver_version="0.0.0",
    )
    assert saved_path.exists()
    loaded = session_service.load_session("svc_unit", tmp_path)

    for key in FULL_PAYLOAD:
        if key == "schema_version":
            continue
        assert getattr(loaded, key) == FULL_PAYLOAD[key], key


def test_save_with_empty_session_name_defaults_to_session(tmp_path):
    payload = dict(FULL_PAYLOAD)
    payload["session_name"] = ""
    saved = session_service.save_session(payload, tmp_path)
    assert saved.name == "session.memdiver"


def test_load_missing_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        session_service.load_session("nope", tmp_path)


def test_delete_happy_path(tmp_path):
    session_service.save_session(FULL_PAYLOAD, tmp_path)
    path = tmp_path / "svc_unit.memdiver"
    assert path.exists()
    session_service.delete_session("svc_unit", tmp_path)
    assert not path.exists()


def test_delete_missing_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        session_service.delete_session("never_saved", tmp_path)


def test_list_sessions_empty(tmp_path):
    assert session_service.list_sessions(tmp_path) == []


def test_list_sessions_contains_saved(tmp_path):
    session_service.save_session(FULL_PAYLOAD, tmp_path)
    listed = session_service.list_sessions(tmp_path)
    assert len(listed) == 1
    assert listed[0]["name"] == "svc_unit"


def test_session_store_delete_static_method(tmp_path):
    session_service.save_session(FULL_PAYLOAD, tmp_path)
    # Exercise SessionStore.delete directly, not via the service.
    SessionStore.delete("svc_unit", tmp_path)
    assert not (tmp_path / "svc_unit.memdiver").exists()


def test_session_store_delete_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        SessionStore.delete("ghost", tmp_path)
