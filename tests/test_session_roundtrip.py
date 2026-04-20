"""Backend round-trip regression test for the /api/sessions/ endpoint.

Posts a SessionPayload with all 21 data fields populated with non-default
values, then GETs the saved session back and asserts field equality. This
is the guard against the silent-field-drop class of bug flagged in
.claude-work/plans/curried-jumping-lantern.md (PR 1 Session round-trip).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.config import Settings
from api.dependencies import get_api_settings
from api.main import create_app


@pytest.fixture
def client_with_tmp_sessions(tmp_path):
    """TestClient whose session_dir is redirected into tmp_path."""
    app = create_app()

    def _override() -> Settings:
        return Settings(session_dir=tmp_path)

    app.dependency_overrides[get_api_settings] = _override
    return TestClient(app)


# Non-default values for every field the backend SessionSnapshot dataclass
# persists. If any of these is silently dropped on the save path, the GET
# comparison below will fail with a concrete field name.
FULL_PAYLOAD = {
    "schema_version": 1,
    "session_name": "roundtrip_all_fields",
    "input_mode": "file",
    "input_path": "/tmp/fixture_dump.msl",
    "dataset_root": "/tmp/fixture_dataset",
    "keylog_filename": "custom_keylog.csv",
    "template_name": "TLS1.3",
    "protocol_name": "TLS",
    "protocol_version": "13",
    "scenario": "100_iterations_Abort_KeyUpdate",
    "selected_libraries": ["boringssl", "wolfssl"],
    "selected_phase": "pre_abort",
    "algorithm": "exact_match",
    "mode": "exploration",
    "max_runs": 7,
    "normalize_phases": True,
    "single_file_format": "msl",
    "ground_truth_mode": "manual",
    "selected_algorithms": ["entropy_scan", "differential", "pattern_match"],
    "analysis_result": {"sentinel": "round_trip", "nested": {"k": 1}},
    "bookmarks": [
        {"offset": 256, "length": 32, "label": "candidate_a"},
        {"offset": 4096, "length": 16, "label": "candidate_b"},
    ],
    "investigation_offset": 1024,
}


def test_session_full_field_roundtrip(client_with_tmp_sessions):
    """Every field POSTed must survive the save → load round trip intact."""
    client = client_with_tmp_sessions

    save_resp = client.post("/api/sessions/", json=FULL_PAYLOAD)
    assert save_resp.status_code == 200, save_resp.text
    saved = save_resp.json()
    assert saved["status"] == "ok"
    stem = saved["name"]

    load_resp = client.get(f"/api/sessions/{stem}")
    assert load_resp.status_code == 200, load_resp.text
    loaded = load_resp.json()

    # Every field from FULL_PAYLOAD must be present and equal in the loaded
    # snapshot. Server-stamped fields (created_at, memdiver_version) are
    # ignored. schema_version is checked separately because the backend
    # overwrites the client value with CURRENT_SCHEMA_VERSION.
    mismatches = []
    for field_name, expected in FULL_PAYLOAD.items():
        if field_name == "schema_version":
            continue  # server authoritative, asserted below
        actual = loaded.get(field_name)
        if actual != expected:
            mismatches.append((field_name, expected, actual))

    assert not mismatches, (
        "Round-trip field drift — the following fields were lost or mutated "
        "between save and load:\n"
        + "\n".join(
            f"  {name}: expected={exp!r}, got={got!r}"
            for name, exp, got in mismatches
        )
    )

    # Server stamps schema_version — must be at least 1 and not None.
    assert loaded.get("schema_version") is not None
    assert loaded["schema_version"] >= 1


def test_session_omitted_fields_use_defaults(client_with_tmp_sessions):
    """Omitting optional fields must not 422; defaults should fill in."""
    client = client_with_tmp_sessions

    resp = client.post("/api/sessions/", json={"session_name": "minimal"})
    assert resp.status_code == 200, resp.text

    load_resp = client.get("/api/sessions/minimal")
    assert load_resp.status_code == 200
    loaded = load_resp.json()
    assert loaded["session_name"] == "minimal"
    # schema_version is always stamped by the server regardless of client input.
    assert loaded.get("schema_version") is not None


def test_session_schema_version_is_optional_on_wire(client_with_tmp_sessions):
    """SessionPayload must accept a body that omits schema_version (it is
    optional on the wire; the server stamps CURRENT_SCHEMA_VERSION into the
    persisted snapshot)."""
    client = client_with_tmp_sessions
    body = dict(FULL_PAYLOAD)
    body.pop("schema_version")
    body["session_name"] = "no_schema_version"

    resp = client.post("/api/sessions/", json=body)
    assert resp.status_code == 200, resp.text
    load_resp = client.get("/api/sessions/no_schema_version")
    assert load_resp.status_code == 200
    assert load_resp.json().get("schema_version") is not None
