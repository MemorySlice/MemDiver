"""HTTP-layer tests for api.routers.architect.

Exercise the public REST contract of the architect endpoints with a real
TestClient. Production code is untouched -- we synthesise small dump files
on disk and POST them via the documented payloads.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import get_settings
from api.main import create_app


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


@pytest.fixture
def synthetic_dumps(tmp_path: Path) -> list[str]:
    """Two tiny dumps that share a 16-byte static prefix and diverge after."""
    prefix = bytes(range(16))
    dump_a = prefix + b"\x00" * 16
    dump_b = prefix + b"\xFF" * 16
    paths: list[str] = []
    for i, data in enumerate((dump_a, dump_b)):
        p = tmp_path / f"dump_{i}.bin"
        p.write_bytes(data)
        paths.append(str(p))
    return paths


# ---------------------------------------------------------------------------
# /api/architect/check-static
# ---------------------------------------------------------------------------


def test_check_static_happy_path(client, synthetic_dumps):
    """check-static returns mask + reference hex + ratio + anchors."""
    r = client.post(
        "/api/architect/check-static",
        json={"dump_paths": synthetic_dumps, "offset": 0, "length": 32},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "static_mask" in body
    assert "reference_hex" in body
    assert "static_ratio" in body
    assert "anchors" in body
    assert len(body["static_mask"]) == 32
    # First 16 bytes are identical across both dumps -> all True.
    assert all(body["static_mask"][:16])
    # Last 16 bytes differ -> all False.
    assert not any(body["static_mask"][16:])


def test_check_static_404_on_missing_dump(client, tmp_path):
    """check-static returns 404 if any dump path doesn't exist."""
    missing = str(tmp_path / "does_not_exist.bin")
    r = client.post(
        "/api/architect/check-static",
        json={"dump_paths": [missing, missing], "offset": 0, "length": 16},
    )
    assert r.status_code == 404
    assert "does_not_exist" in r.json()["detail"]


# ---------------------------------------------------------------------------
# /api/architect/generate-pattern
# ---------------------------------------------------------------------------


def test_generate_pattern_happy_path(client):
    """generate-pattern returns the pattern dict on a sufficient-static input."""
    reference = bytes(range(16))
    payload = {
        "reference_hex": reference.hex(),
        "static_mask": [True] * 16,
        "name": "api_test",
        "min_static_ratio": 0.3,
    }
    r = client.post("/api/architect/generate-pattern", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "api_test"
    assert body["length"] == 16
    assert "wildcard_pattern" in body


def test_generate_pattern_422_on_invalid_payload(client):
    """Missing required fields trigger Pydantic 422 before the handler runs."""
    r = client.post(
        "/api/architect/generate-pattern",
        json={"reference_hex": "deadbeef"},  # static_mask is required
    )
    assert r.status_code == 422


def test_generate_pattern_400_on_below_threshold(client):
    """Below-threshold static ratio surfaces as a 400 with a clear detail."""
    reference = b"\x00" * 32
    payload = {
        "reference_hex": reference.hex(),
        "static_mask": [True] * 5 + [False] * 27,  # ~15% static, below 0.3
        "name": "below",
        "min_static_ratio": 0.3,
    }
    r = client.post("/api/architect/generate-pattern", json=payload)
    assert r.status_code == 400
    assert "static" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# /api/architect/export
# ---------------------------------------------------------------------------


def test_export_yara_happy_path(client):
    """export with format=yara returns a YARA rule string."""
    pattern = {
        "name": "exp_test",
        "length": 8,
        "hex_pattern": "00 01 02 03 04 05 06 07",
        "wildcard_pattern": "00 01 02 03 04 05 06 07",
        "static_ratio": 1.0,
        "static_count": 8,
        "volatile_count": 0,
    }
    r = client.post(
        "/api/architect/export",
        json={"pattern": pattern, "format": "yara", "rule_name": "exported"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["format"] == "yara"
    assert "rule exported" in body["content"]


def test_export_400_on_unknown_format(client):
    """Unknown format strings raise a 400 with a list of supported values."""
    pattern = {"name": "x", "length": 0, "wildcard_pattern": ""}
    r = client.post(
        "/api/architect/export",
        json={"pattern": pattern, "format": "invalid_format"},
    )
    assert r.status_code == 400
    assert "Unknown format" in r.json()["detail"]
