"""Tests for the ``GET /api/inspect/format`` endpoint (force_format + suggestions)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from tests.fixtures.generate_msl_fixtures import generate_msl_file


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture
def msl_path(tmp_path):
    p = tmp_path / "format_endpoint_test.msl"
    p.write_bytes(generate_msl_file())
    return str(p)


def test_detect_format_returns_msl(client, msl_path):
    resp = client.get("/api/inspect/format", params={"dump_path": msl_path})
    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "msl"
    assert body["detected_format"] == "msl"
    assert body["forced"] is False
    # Must not leak ELF-style program-header overlays onto an MSL file.
    overlays = body.get("overlays") or {}
    fields = overlays.get("fields") or []
    for fld in fields:
        assert "phdr" not in fld.get("field_name", "").lower()
        assert "phdr" not in fld.get("path", "").lower()


def test_force_elf64_on_msl(client, msl_path):
    resp = client.get(
        "/api/inspect/format",
        params={"dump_path": msl_path, "force_format": "elf64"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "elf64"
    assert body["detected_format"] == "msl"
    assert body["forced"] is True


def test_unknown_force_format_400(client, msl_path):
    resp = client.get(
        "/api/inspect/format",
        params={"dump_path": msl_path, "force_format": "bogus"},
    )
    assert resp.status_code == 400


def test_suggested_and_available_populated(client, msl_path):
    resp = client.get("/api/inspect/format", params={"dump_path": msl_path})
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["suggested_formats"], list)
    assert any(s["format"] == "msl" for s in body["suggested_formats"])
    assert "msl" in body["available_formats"]
