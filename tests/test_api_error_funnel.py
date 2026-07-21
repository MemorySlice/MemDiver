"""Tests for the Phase 3 API error funnel and logging setup.

Covers two things that used to be implicit:

1. ``api/main.py``'s global ``CapabilityError`` exception handler: any
   propagating core/service error becomes a structured JSON response whose
   status comes from ``exc.status`` and whose body is ``exc.to_dict()``, with
   only ``ErrorCategory.INTERNAL`` errors logged via ``logger.exception``.
2. ``core/log.py``'s ``setup_logging()``: it is idempotent (calling it twice
   never adds a duplicate handler), which is what lets ``create_app()`` call
   it unconditionally on every app build (as the test suite does repeatedly)
   without leaking duplicate log lines.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from memdiver.api.main import create_app
from memdiver.core.log import setup_logging
from memdiver.core.service_errors import CapabilityError, ErrorCategory


# ---------------------------------------------------------------------------
# Real endpoint path: api/services/key_material.py raises CapabilityError,
# which propagates out of the route (it is raised before the router's own
# try/except-and-downgrade block even runs) and is caught by the global
# handler registered in create_app().
# ---------------------------------------------------------------------------


def test_key_material_error_funnels_through_global_handler():
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get(
            "/api/inspect/hex",
            params={
                "dump_path": "/nonexistent.msl",
                "offset": 0,
                "length": 8,
                "key_hex": "not-hex",
            },
        )
    assert resp.status_code == 400
    assert resp.json() == {
        "error": "Invalid key material encoding",
        "code": None,
        "category": "INVALID_INPUT",
    }


# ---------------------------------------------------------------------------
# Throwaway route on a fresh create_app() instance: exercises the handler
# directly for categories/statuses the real routes don't conveniently raise,
# and confirms the INTERNAL-only logging rule.
# ---------------------------------------------------------------------------


@pytest.fixture
def app_with_probe_routes():
    app = create_app()

    def _raise(category: str):
        raise CapabilityError(
            f"boom-{category}",
            category=ErrorCategory[category],
            code="TEST_CODE",
        )

    app.add_api_route(
        "/__test__/capability-error/{category}", _raise, methods=["GET"]
    )
    # When a built frontend/dist/ exists, create_app() mounts StaticFiles at
    # "/" -- a catch-all that would otherwise shadow any route appended
    # afterwards (Starlette matches routes in list order). Move the probe
    # route to the front so this test behaves the same with or without a
    # built frontend.
    probe_route = app.router.routes.pop()
    app.router.routes.insert(0, probe_route)

    return app


@pytest.mark.parametrize(
    "category,expected_status",
    [
        ("NOT_FOUND", 404),
        ("INVALID_INPUT", 400),
        ("PRECONDITION", 400),
        ("UNSUPPORTED", 400),
        ("INTERNAL", 500),
    ],
)
def test_handler_uses_exc_status_and_to_dict_body(
    app_with_probe_routes, category, expected_status
):
    with TestClient(app_with_probe_routes, raise_server_exceptions=False) as client:
        resp = client.get(f"/__test__/capability-error/{category}")
    assert resp.status_code == expected_status
    assert resp.json() == {
        "error": f"boom-{category}",
        "code": "TEST_CODE",
        "category": category,
    }


def test_only_internal_category_is_logged(app_with_probe_routes, monkeypatch):
    import memdiver.api.main as main_module

    logged: list[str] = []
    monkeypatch.setattr(
        main_module._logger, "exception", lambda msg, *a: logged.append(msg % a)
    )

    with TestClient(app_with_probe_routes, raise_server_exceptions=False) as client:
        client.get("/__test__/capability-error/INVALID_INPUT")
        assert logged == []

        client.get("/__test__/capability-error/INTERNAL")
        assert len(logged) == 1
        assert "boom-INTERNAL" in logged[0]


# ---------------------------------------------------------------------------
# core/log.py: setup_logging() must be safe to call repeatedly (create_app()
# calls it on every build, and the test suite builds the app many times).
# ---------------------------------------------------------------------------


def test_setup_logging_is_idempotent():
    logger = logging.getLogger("memdiver")
    original_handlers = list(logger.handlers)
    try:
        logger.handlers = []
        setup_logging()
        first_count = len(logger.handlers)
        assert first_count > 0

        setup_logging()
        setup_logging()
        assert len(logger.handlers) == first_count
    finally:
        logger.handlers = original_handlers
