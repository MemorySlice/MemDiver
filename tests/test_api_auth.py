"""Tests for API token auth (api/security.py) and the bind guardrail.

Token auth is opt-in: with no ``MEMDIVER_API_TOKEN`` configured the API
stays fully open (the historical no-auth posture every other test fixture
relies on). Once a token is set, ``ApiTokenAuthMiddleware`` enforces it on
every HTTP route under ``/api``, ``/ws``, and ``/notebook``, while
``/health``, ``/docs``, ``/redoc``, ``/openapi.json``, and the static SPA
bundle stay reachable without credentials. The WebSocket endpoint enforces
its own ``?token=`` query-param check separately (HTTP middleware never
sees websocket-scope connections).

We reuse the ``isolated_env``/``client`` convention from
``tests/test_api_dataset.py`` (redirect every settings-controlled directory
into ``tmp_path``) and layer a second ``client_with_token`` fixture on top
for the enforcing-path tests, keeping the base fixtures token-free so the
default open posture keeps getting exercised too.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient
from starlette.routing import Mount, Route, WebSocketRoute

from memdiver.api.config import Settings, get_settings
from memdiver.api.main import create_app
from memdiver.api.security import (
    InsecureBindError,
    _ALWAYS_EXEMPT_PATHS,
    _PROTECTED_PREFIXES,
    _is_protected_path,
    check_credentials,
    check_ws_token,
    enforce_bind_guardrail,
    guard_notebook_websocket,
)

API_TOKEN = "s3cr3t-token"

# ---------------------------------------------------------------------------
# Fixtures (mirror tests/test_api_dataset.py)
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
    """A token-free TestClient — the default, backward-compatible, open posture."""
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client_with_token(isolated_env, monkeypatch):
    """A TestClient with MEMDIVER_API_TOKEN configured, for the enforcing path."""
    monkeypatch.setenv("MEMDIVER_API_TOKEN", API_TOKEN)
    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# HTTP: token configured — data routes must be enforced
# ---------------------------------------------------------------------------


def test_data_route_no_credentials_returns_401(client_with_token):
    r = client_with_token.get("/api/tasks/whatever/events", params={"since": 0})
    assert r.status_code == 401
    assert r.json()["detail"] == "Missing or invalid API credentials"
    assert r.headers["www-authenticate"] == "Bearer"


def test_data_route_correct_bearer_token_returns_200(client_with_token):
    r = client_with_token.get(
        "/api/tasks/whatever/events",
        params={"since": 0},
        headers={"Authorization": f"Bearer {API_TOKEN}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["task_id"] == "whatever"
    assert r.json()["events"] == []


def test_data_route_correct_x_api_key_returns_200(client_with_token):
    r = client_with_token.get(
        "/api/tasks/whatever/events",
        params={"since": 0},
        headers={"X-API-Key": API_TOKEN},
    )
    assert r.status_code == 200, r.text
    assert r.json()["events"] == []


def test_data_route_wrong_bearer_token_returns_401(client_with_token):
    r = client_with_token.get(
        "/api/tasks/whatever/events",
        params={"since": 0},
        headers={"Authorization": "Bearer wrong"},
    )
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_data_route_wrong_x_api_key_returns_401(client_with_token):
    r = client_with_token.get(
        "/api/tasks/whatever/events",
        params={"since": 0},
        headers={"X-API-Key": "wrong"},
    )
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


# ---------------------------------------------------------------------------
# HTTP: no token configured — critical regression guard for the open default
# ---------------------------------------------------------------------------


def test_data_route_open_when_no_token_configured(client):
    r = client.get("/api/tasks/whatever/events", params={"since": 0})
    assert r.status_code == 200, r.text
    assert r.json()["events"] == []


# ---------------------------------------------------------------------------
# Exempt paths — reachable with no credentials in both modes
# ---------------------------------------------------------------------------


def test_health_reachable_without_token_configured(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_health_reachable_with_token_configured_and_no_credentials(client_with_token):
    r = client_with_token.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_docs_reachable_without_token_configured(client):
    r = client.get("/docs")
    assert r.status_code == 200


def test_docs_reachable_with_token_configured_and_no_credentials(client_with_token):
    r = client_with_token.get("/docs")
    assert r.status_code == 200


def test_openapi_json_reachable_without_token_configured(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200


def test_openapi_json_reachable_with_token_configured_and_no_credentials(client_with_token):
    r = client_with_token.get("/openapi.json")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


def test_ws_correct_token_reaches_normal_handler_logic(client_with_token):
    """A valid ``?token=`` passes the auth check and the request proceeds
    into the existing unknown-task-id handling (accept + error frame)."""
    with client_with_token.websocket_connect(
        f"/ws/tasks/whatever?token={API_TOKEN}"
    ) as ws:
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert frame["task_id"] == "whatever"
    assert frame["error"] == "unknown task"


def test_ws_missing_token_disconnects_with_policy_violation(client_with_token):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client_with_token.websocket_connect("/ws/tasks/whatever") as ws:
            ws.receive_json()
    assert exc_info.value.code == 1008


def test_ws_wrong_token_disconnects_with_policy_violation(client_with_token):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client_with_token.websocket_connect(
            "/ws/tasks/whatever?token=wrong"
        ) as ws:
            ws.receive_json()
    assert exc_info.value.code == 1008


def test_ws_open_when_no_token_configured(client):
    """No MEMDIVER_API_TOKEN configured: the WS auth check is a no-op and
    normal handler behavior (accept + unknown-task error frame) applies."""
    with client.websocket_connect("/ws/tasks/whatever") as ws:
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert frame["task_id"] == "whatever"
    assert frame["error"] == "unknown task"


# ---------------------------------------------------------------------------
# Notebook WebSocket guard (guard_notebook_websocket) — the Marimo kernel WS
# bypasses the HTTP-only ApiTokenAuthMiddleware, so it is guarded at the mount.
# ---------------------------------------------------------------------------


def _guarded_with(settings):
    """Build a guarded app whose inner records whether it was invoked."""
    state = {"called": False}

    async def inner(scope, receive, send):
        state["called"] = True

    return guard_notebook_websocket(inner, settings), state


def test_notebook_ws_rejected_without_token_when_configured():
    import asyncio

    guarded, state = _guarded_with(Settings(api_token=API_TOKEN))
    sent: list = []

    async def receive():
        return {"type": "websocket.connect"}

    async def send(msg):
        sent.append(msg)

    asyncio.run(guarded({"type": "websocket", "query_string": b""}, receive, send))
    assert state["called"] is False
    assert sent == [{"type": "websocket.close", "code": 1008}]


def test_notebook_ws_rejected_with_wrong_token_when_configured():
    import asyncio

    guarded, state = _guarded_with(Settings(api_token=API_TOKEN))
    sent: list = []

    async def receive():
        return {"type": "websocket.connect"}

    async def send(msg):
        sent.append(msg)

    asyncio.run(
        guarded({"type": "websocket", "query_string": b"token=wrong"}, receive, send)
    )
    assert state["called"] is False
    assert sent == [{"type": "websocket.close", "code": 1008}]


def test_notebook_ws_passes_through_with_correct_token():
    import asyncio

    guarded, state = _guarded_with(Settings(api_token=API_TOKEN))

    async def receive():
        return {"type": "websocket.connect"}

    async def send(msg):
        pass

    qs = f"token={API_TOKEN}".encode()
    asyncio.run(guarded({"type": "websocket", "query_string": qs}, receive, send))
    assert state["called"] is True


def test_notebook_ws_open_when_no_token_configured():
    import asyncio

    guarded, state = _guarded_with(Settings(api_token=None))

    async def receive():
        return {"type": "websocket.connect"}

    async def send(msg):
        pass

    asyncio.run(guarded({"type": "websocket", "query_string": b""}, receive, send))
    assert state["called"] is True


def test_notebook_http_scope_always_passes_through_to_inner():
    """HTTP scope is left to the outer middleware; the guard only gates WS."""
    import asyncio

    guarded, state = _guarded_with(Settings(api_token=API_TOKEN))

    async def receive():
        return {"type": "http.request"}

    async def send(msg):
        pass

    asyncio.run(guarded({"type": "http", "query_string": b""}, receive, send))
    assert state["called"] is True


# ---------------------------------------------------------------------------
# Bind guardrail (api.security.enforce_bind_guardrail)
# ---------------------------------------------------------------------------


def test_bind_guardrail_refuses_non_loopback_without_token_or_override():
    settings = Settings(api_token=None, allow_insecure=False)
    with pytest.raises(InsecureBindError) as exc_info:
        enforce_bind_guardrail("0.0.0.0", settings)
    assert str(exc_info.value) == (
        "Refusing to bind 0.0.0.0 without MEMDIVER_API_TOKEN. Set a token, "
        "or MEMDIVER_API_ALLOW_INSECURE=1 to override."
    )


def test_bind_guardrail_allows_non_loopback_with_token():
    settings = Settings(api_token=API_TOKEN, allow_insecure=False)
    enforce_bind_guardrail("0.0.0.0", settings)  # must not raise


def test_bind_guardrail_allows_non_loopback_with_explicit_override():
    settings = Settings(api_token=None, allow_insecure=True)
    enforce_bind_guardrail("0.0.0.0", settings)  # must not raise


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", ""])
def test_bind_guardrail_allows_loopback_hosts_without_token(host):
    settings = Settings(api_token=None, allow_insecure=False)
    enforce_bind_guardrail(host, settings)  # must not raise


def test_insecure_bind_error_funnels_through_cli_error_mapper(capsys):
    """P3.8: InsecureBindError is a CapabilityError(PRECONDITION), so the CLI
    routes it through to_cli_exit — a ``memdiver: ERROR — …`` prefixed message
    and a category exit code (2), instead of the pre-P3.8 raw print + exit 1."""
    from memdiver.cli import to_cli_exit
    from memdiver.core.service_errors import CapabilityError, ErrorCategory

    err = InsecureBindError(
        "Refusing to bind 0.0.0.0 without MEMDIVER_API_TOKEN. Set a token, "
        "or MEMDIVER_API_ALLOW_INSECURE=1 to override."
    )
    assert isinstance(err, CapabilityError)
    assert err.category is ErrorCategory.PRECONDITION
    assert err.code == "insecure_bind"

    exit_code = to_cli_exit(err)
    assert exit_code == 2  # PRECONDITION -> 2 (was a hard-coded 1 pre-P3.8)
    assert "memdiver: ERROR — Refusing to bind 0.0.0.0" in capsys.readouterr().err


def test_cmd_web_routes_insecure_bind_through_funnel(monkeypatch, capsys):
    """The ``web`` command's guardrail refusal returns the category exit code
    via to_cli_exit (2), not the old bespoke exit 1."""
    pytest.importorskip("uvicorn")
    import argparse

    import memdiver.api.security as security
    from memdiver.cli.dataset import _cmd_web

    def _refuse(host, settings):
        # Raise the *live* module's class (some suite tests reload
        # memdiver.api.security) so it matches what _cmd_web's own fresh import
        # will catch — otherwise a stale class object would slip past the except.
        raise security.InsecureBindError(
            "Refusing to bind 0.0.0.0 without MEMDIVER_API_TOKEN. Set a token, "
            "or MEMDIVER_API_ALLOW_INSECURE=1 to override."
        )

    monkeypatch.setattr(security, "enforce_bind_guardrail", _refuse)
    rc = _cmd_web(argparse.Namespace(port=8080))
    assert rc == 2
    assert "memdiver: ERROR —" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# check_credentials / check_ws_token — pure-function guards
# ---------------------------------------------------------------------------


def test_check_credentials_returns_false_for_none_and_empty_candidates():
    assert check_credentials(API_TOKEN, None, None) is False
    assert check_credentials(API_TOKEN, "", "") is False
    assert check_credentials(API_TOKEN, "Bearer ", None) is False


def test_check_ws_token_returns_false_for_none_and_empty_candidates():
    assert check_ws_token(API_TOKEN, None) is False
    assert check_ws_token(API_TOKEN, "") is False


# ---------------------------------------------------------------------------
# Fail-open guard — every real route must be protected or deliberately open
# ---------------------------------------------------------------------------


def test_all_routes_are_protected_or_intentionally_open():
    """Enumerate every route registered on the real app and require each one
    to either fall under ``_is_protected_path`` (so the token middleware
    enforces it) or sit on a small, deliberate open allowlist (health check,
    OpenAPI/docs UI, the static SPA mount).

    This is a regression guard against fail-open-by-omission: if someone
    later adds a new top-level data route outside ``/api``/``/ws``/
    ``/notebook`` (or forgets to extend ``_PROTECTED_PREFIXES``), this test
    fails and names the offending path instead of silently shipping an
    unauthenticated route.
    """
    app = create_app()
    for route in app.routes:
        if isinstance(route, Mount):
            # The static SPA bundle mounted at the root — intentionally
            # open by design; it serves the frontend, not API data, so
            # there is nothing to recurse into.
            continue

        assert isinstance(route, (Route, WebSocketRoute)), (
            f"Unexpected route type {type(route)!r} on {route!r}; teach "
            "this test about it before trusting the app's route table."
        )
        path = route.path
        methods = getattr(route, "methods", None)

        if _is_protected_path(path):
            continue
        if path in _ALWAYS_EXEMPT_PATHS:
            continue
        if path.startswith("/docs"):
            # FastAPI's docs UI registers more than the exact "/docs" path
            # (e.g. "/docs/oauth2-redirect"); all of it is safe-by-design.
            continue

        pytest.fail(
            f"Route {path!r} (methods={methods}) is neither protected by "
            "_is_protected_path nor on the intentional open allowlist. If "
            "this is a genuine new data route, give it a prefix in "
            f"{_PROTECTED_PREFIXES}; if it's meant to be open, extend the "
            "allowlist in this test deliberately."
        )


# ---------------------------------------------------------------------------
# OPTIONS preflight bypass (Change 1) — preflight is exempt, GET is not
# ---------------------------------------------------------------------------


def test_options_preflight_bypasses_auth_but_get_on_same_route_still_401s(
    client_with_token,
):
    """CORS preflight (OPTIONS) must not 401 even without credentials, but
    the actual GET on the same protected route still requires the token —
    documenting the OPTIONS-vs-GET contrast on one route in one place."""
    options_response = client_with_token.options("/api/tasks/whatever/events")
    assert options_response.status_code != 401

    get_response = client_with_token.get(
        "/api/tasks/whatever/events", params={"since": 0}
    )
    assert get_response.status_code == 401
