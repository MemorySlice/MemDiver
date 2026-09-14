"""Unit tests for ``api.services.session_service``.

Pins the contract that used to live inline inside the sessions router
so a router refactor or a transport swap cannot silently drop fields on
save. Complements the HTTP-level coverage in ``test_session_roundtrip.py``.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.api.services import session_service
from memdiver.engine.session_store import CURRENT_SCHEMA_VERSION, SessionSnapshot, SessionStore


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
    # Schema v2 multi-dump workspace. Every entry carries EXACTLY the four
    # persistable keys, so the sanitiser is an identity here and the
    # iterate-the-payload assertions below extend for free.
    "dumps": [
        {"path": "/d/a.msl", "name": "a.msl", "size": 1024, "format": "msl"},
        {"path": "/d/b.raw", "name": "b.raw", "size": 2048, "format": "raw"},
    ],
    "active_dump_path": "/d/b.raw",
    "selected_dump_paths": ["/d/a.msl", "/d/b.raw"],
    "collapsed_dump_paths": ["/d/a.msl"],
    "origin_dump_path": "/d/a.msl",
    "main_view": "overlay",
    "aslr_normalize": True,
    "dump_weights": {"/d/a.msl": 0.5, "/d/b.raw": 2.0},
    "excluded_dump_paths": ["/d/b.raw"],
    "solo_dump_path": "/d/a.msl",
    "rail_collapsed": True,
}

# The complete set of keys a persisted dump entry is allowed to carry.
PERSISTABLE_DUMP_KEYS = {"path", "name", "size", "format"}

# A dump entry as the frontend's DumpEntry could naively serialize it: the
# four legal keys plus PLAINTEXT recovered secrets.
DUMP_WITH_SECRETS = {
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
    "id": "b0f3a1e2-0000-4000-8000-000000000000",
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


# ---------------------------------------------------------------------------
# Security: the dump-entry key whitelist
# ---------------------------------------------------------------------------


def test_sanitize_dumps_drops_key_material_and_passphrase():
    sanitized = session_service._sanitize_dumps([DUMP_WITH_SECRETS])
    assert len(sanitized) == 1
    assert set(sanitized[0]) == PERSISTABLE_DUMP_KEYS
    assert sanitized[0]["path"] == "/d/secret.msl"
    assert "hunter2" not in str(sanitized)


def test_sanitize_dumps_tolerates_junk():
    assert session_service._sanitize_dumps(None) == []
    assert session_service._sanitize_dumps("not-a-list") == []
    # Non-mapping entries are skipped, not fatal.
    assert session_service._sanitize_dumps([None, 42, {"path": "/ok"}]) == [
        {"path": "/ok", "name": "", "size": 0, "format": ""}
    ]


def test_payload_to_snapshot_strips_secrets_from_dumps():
    """Direct (non-HTTP) callers cannot smuggle key material onto the snapshot."""
    payload = dict(FULL_PAYLOAD)
    payload["dumps"] = [DUMP_WITH_SECRETS]
    snap = session_service.payload_to_snapshot(payload)

    assert len(snap.dumps) == 1
    assert set(snap.dumps[0]) == PERSISTABLE_DUMP_KEYS
    assert "hunter2" not in str(snap.dumps)


def test_save_session_never_writes_secrets_to_disk(tmp_path):
    """The whitelist holds all the way to the bytes on disk."""
    payload = dict(FULL_PAYLOAD)
    payload["session_name"] = "secret_free"
    payload["dumps"] = [DUMP_WITH_SECRETS]
    saved = session_service.save_session(payload, tmp_path)

    text = gzip.decompress(saved.read_bytes()).decode("utf-8")
    assert "hunter2" not in text
    assert "deadbeef" not in text
    assert "cafebabe" not in text
    assert "key_material" not in text
    # The legal part survived.
    assert "/d/secret.msl" in text

    persisted = json.loads(text)
    assert [set(d) for d in persisted["dumps"]] == [PERSISTABLE_DUMP_KEYS]


def test_save_session_without_dumps_still_works(tmp_path):
    payload = {k: v for k, v in FULL_PAYLOAD.items() if k != "dumps"}
    payload["session_name"] = "no_dumps"
    session_service.save_session(payload, tmp_path)
    loaded = session_service.load_session("no_dumps", tmp_path)
    assert loaded.dumps == []
