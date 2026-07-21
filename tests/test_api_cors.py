"""CORS configuration tests for the MemDiver FastAPI app.

Pairing a wildcard origin ("*") with ``allow_credentials=True`` is rejected by
browsers and unsafe, and a wildcard ``allow_methods`` / ``allow_headers`` is
broader than the SPA needs. ``create_app`` (see api/main.py) therefore:

* strips any literal "*" from the configured origins (falling back to the
  localhost dev origin), and
* narrows methods to GET/POST/DELETE (+ the OPTIONS preflight) and headers to
  ``Content-Type``.

These tests exercise that via CORS preflight responses rather than reaching
into Starlette middleware internals.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app

DEV_ORIGIN = "http://localhost:5173"


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch):
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


def _preflight(client: TestClient, origin: str, method: str = "GET"):
    return client.options(
        "/api/sessions/",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": method,
        },
    )


def test_dev_origin_allowed_but_not_wildcarded(isolated_env, monkeypatch):
    """The localhost dev origin is echoed back — never a bare "*" — with creds."""
    monkeypatch.setenv("MEMDIVER_CORS_ORIGINS", f'["{DEV_ORIGIN}"]')
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        resp = _preflight(client, DEV_ORIGIN)
    assert resp.status_code == 200
    # Credentialed CORS must echo the concrete origin, not "*".
    assert resp.headers.get("access-control-allow-origin") == DEV_ORIGIN
    assert resp.headers.get("access-control-allow-credentials") == "true"


def test_allowed_methods_are_narrowed(isolated_env, monkeypatch):
    """Preflight advertises only the verbs the SPA uses (no PUT/PATCH)."""
    monkeypatch.setenv("MEMDIVER_CORS_ORIGINS", f'["{DEV_ORIGIN}"]')
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        resp = _preflight(client, DEV_ORIGIN)
    allowed = resp.headers.get("access-control-allow-methods", "")
    granted = {m.strip() for m in allowed.split(",") if m.strip()}
    assert granted == {"GET", "POST", "DELETE", "OPTIONS"}
    assert "PUT" not in granted and "PATCH" not in granted
    assert "*" not in granted


def test_allowed_headers_are_narrowed(isolated_env, monkeypatch):
    """Only Content-Type is granted, not a wildcard header set."""
    monkeypatch.setenv("MEMDIVER_CORS_ORIGINS", f'["{DEV_ORIGIN}"]')
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        resp = client.options(
            "/api/sessions/",
            headers={
                "Origin": DEV_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
    granted = resp.headers.get("access-control-allow-headers", "")
    assert "content-type" in granted.lower()
    assert "*" not in granted


def test_wildcard_origin_is_stripped(isolated_env, monkeypatch):
    """A configured "*" origin is dropped (unsafe with credentials).

    With credentials on, "*" must never be honored: an arbitrary attacker
    origin is not allowed, and the response never returns a bare "*".
    """
    monkeypatch.setenv("MEMDIVER_CORS_ORIGINS", '["*"]')
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        # An arbitrary evil origin must not be granted.
        evil = _preflight(client, "http://evil.example")
        assert evil.headers.get("access-control-allow-origin") not in (
            "*",
            "http://evil.example",
        )
        # The dev fallback origin still works.
        ok = _preflight(client, DEV_ORIGIN)
        assert ok.headers.get("access-control-allow-origin") == DEV_ORIGIN
