"""API token authentication and bind-safety guardrails.

Token auth is entirely OPT-IN: when ``MEMDIVER_API_TOKEN`` is unset the API
stays open, preserving the historical no-auth behavior every existing test
fixture and local single-user workflow relies on (see the localhost trust
model note in ``api/main.py::create_app``). Once a token is configured, every
data route — HTTP under ``/api``/``/ws``/``/notebook``, and the task-progress
WebSocket — must present it via ``Authorization: Bearer <token>``,
``X-API-Key: <token>``, or (WebSocket only) a ``?token=<token>`` query param.
Only the health check, the OpenAPI/docs endpoints, and the static frontend
bundle stay reachable without a token.

All comparisons are constant-time (:func:`hmac.compare_digest`) so response
timing cannot be used to brute-force the token.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Any, Iterable
from urllib.parse import parse_qs

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from memdiver.api.config import Settings
from memdiver.core.service_errors import CapabilityError, ErrorCategory

logger = logging.getLogger("memdiver.api.security")

# Reachable without a token even when one is configured: health checks and
# the OpenAPI/docs UI. Everything else NOT matched by _PROTECTED_PREFIXES
# below (i.e. the static frontend bundle served from the "/" catch-all mount)
# is implicitly exempt too.
_ALWAYS_EXEMPT_PATHS = frozenset({"/health", "/docs", "/redoc", "/openapi.json"})

# Data routes and the notebook's live code-execution surface: never exempt.
_PROTECTED_PREFIXES = ("/api", "/ws", "/notebook")

# Hosts considered loopback-only (safe to bind with no token configured).
# "" is included because an unset/blank host is not an operator's deliberate
# choice to expose the API — treat it the same as the loopback default.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", ""})


def _is_protected_path(path: str) -> bool:
    """Return True if *path* requires a token when one is configured."""
    if path in _ALWAYS_EXEMPT_PATHS:
        return False
    return any(path == prefix or path.startswith(prefix + "/") for prefix in _PROTECTED_PREFIXES)


def _constant_time_eq(candidate: str | None, token: str) -> bool:
    """Constant-time compare *candidate* against *token*; False if missing."""
    if not candidate:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), token.encode("utf-8"))


def _extract_bearer(authorization: str | None) -> str | None:
    """Return the token from an ``Authorization: Bearer <token>`` header."""
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value


def check_credentials(token: str, authorization: str | None, x_api_key: str | None) -> bool:
    """Return True if either header form carries the configured *token*."""
    return _constant_time_eq(_extract_bearer(authorization), token) or _constant_time_eq(
        x_api_key, token
    )


def check_ws_token(token: str, candidate: str | None) -> bool:
    """Return True if the WebSocket ``?token=`` query param matches *token*."""
    return _constant_time_eq(candidate, token)


class ApiTokenAuthMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated HTTP requests to protected routes.

    A no-op when ``settings.api_token`` is unset. WebSocket auth is handled
    separately inside the WS endpoint itself (Starlette's HTTP middleware
    never sees websocket-scope connections).
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings

    async def dispatch(self, request: Request, call_next) -> Response:
        # CORS preflight requests are sent by browsers without credentials
        # (per the Fetch/CORS spec) and carry no data of their own — they
        # only negotiate which headers/methods a following real request may
        # use. Gating them behind the token would make a cross-origin
        # frontend's preflight fail with 401 before the browser ever gets to
        # send the real, credentialed request, so let OPTIONS through
        # unauthenticated here; the actual GET/POST/... is still enforced
        # below on its own request.
        if request.method == "OPTIONS":
            return await call_next(request)
        token = self._settings.api_token
        if token and _is_protected_path(request.url.path):
            authorized = check_credentials(
                token,
                request.headers.get("authorization"),
                request.headers.get("x-api-key"),
            )
            if not authorized:
                return JSONResponse(
                    {"detail": "Missing or invalid API credentials"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return await call_next(request)


def _ws_query_token(scope: Scope) -> str | None:
    """Extract a ``?token=`` value from a WebSocket connection scope."""
    raw = scope.get("query_string", b"") or b""
    values = parse_qs(raw.decode("latin-1")).get("token")
    return values[0] if values else None


def guard_notebook_websocket(inner: ASGIApp, settings: Settings) -> ASGIApp:
    """Wrap the mounted Marimo notebook so its kernel WebSocket can't bypass auth.

    :class:`ApiTokenAuthMiddleware` is HTTP-only (``BaseHTTPMiddleware`` never
    runs for websocket-scope connections), so the notebook's live
    code-execution kernel WS would otherwise be reachable with no token — an
    unauthenticated remote-code-execution surface whenever the server is bound
    to a network interface with a token configured. When a token IS configured,
    reject any notebook websocket that does not present a valid ``?token=`` at
    the handshake. HTTP scope is left to the outer middleware, and when no token
    is set (the loopback single-user default) this is a transparent pass-through
    so the local notebook keeps working exactly as before.
    """

    async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "websocket"
            and settings.api_token
            and not check_ws_token(settings.api_token, _ws_query_token(scope))
        ):
            # Consume the initial connect event, then reject the handshake
            # (a close before accept surfaces as an HTTP 403 to the client).
            await receive()
            await send({"type": "websocket.close", "code": 1008})
            return
        await inner(scope, receive, send)

    return wrapped


class InsecureBindError(CapabilityError):
    """Raised when refusing to bind a non-loopback host without a token.

    A ``CapabilityError`` (category ``PRECONDITION``) so it flows through the
    same funnel as every other surfaced error: the CLI ``web`` command routes
    it to :func:`cli._shared.to_cli_exit` (``memdiver: ERROR — …`` + a
    category exit code) instead of a bespoke print, and — were it ever raised
    inside a request — the API's ``CapabilityError`` handler would map it to
    HTTP 400. It is a misconfiguration precondition, not bad user input.
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("category", ErrorCategory.PRECONDITION)
        kwargs.setdefault("code", "insecure_bind")
        super().__init__(message, **kwargs)


def enforce_bind_guardrail(host: str, settings: Settings) -> None:
    """Refuse a non-loopback bind that has no auth and no explicit override.

    MemDiver is meant to be reachable only from the operator's own machine
    (see the localhost trust model note in ``api/main.py::create_app``):
    request handlers deliberately trust free-form filesystem paths on that
    assumption. Binding a non-loopback interface with neither an API token
    nor ``MEMDIVER_ALLOW_INSECURE=1`` would expose every forensic data
    route to the network with no auth at all, so that combination is refused
    outright. Loopback hosts are always allowed regardless of token state,
    matching the existing (pre-auth) default posture.
    """
    if host in _LOOPBACK_HOSTS:
        return
    if settings.api_token:
        return
    if settings.allow_insecure:
        logger.warning(
            "Binding %s with MEMDIVER_ALLOW_INSECURE=1 and no "
            "MEMDIVER_API_TOKEN set: the API is reachable from the network "
            "with NO authentication. Set MEMDIVER_API_TOKEN to secure it.",
            host,
        )
        return
    raise InsecureBindError(
        f"Refusing to bind {host} without MEMDIVER_API_TOKEN. Set a token, "
        "or MEMDIVER_ALLOW_INSECURE=1 to override."
    )


def agent_chat_refusal(settings: Settings) -> str | None:
    """Why the in-UI agent chat must refuse to run, or ``None`` when it may.

    The chat drives a model that can call tools which write files and run
    caller-supplied code (after the analyst's approval) on this host, so it is
    held to a stricter rule than the data routes: a non-loopback bind needs an
    API token. ``MEMDIVER_ALLOW_INSECURE=1`` does NOT lift this.
    """
    if (settings.host or "").strip().strip("[]").lower() in _LOOPBACK_HOSTS:
        return None
    if settings.api_token:
        return None
    return (
        f"the agent chat is disabled: the server is bound to {settings.host} "
        "without MEMDIVER_API_TOKEN. Set a token, or bind a loopback host."
    )


# ---------------------------------------------------------------------------
# Request-origin hardening (always on)
# ---------------------------------------------------------------------------
#
# Binding 127.0.0.1 keeps OTHER MACHINES out, but not other WEBSITES: any page
# the operator visits can make the browser send requests to
# http://127.0.0.1:8080. Two attacks follow, and the two pure-ASGI middlewares
# below close them (they cover http AND websocket scope, unlike
# BaseHTTPMiddleware):
#
# * DNS rebinding — evil.example re-resolves to 127.0.0.1, after which the
#   page is "same-origin" with the API and CORS no longer applies. The request
#   still carries ``Host: evil.example``, so HostAllowListMiddleware refuses any
#   Host that is not loopback or explicitly configured.
# * Cross-site request forgery — CORS only hides RESPONSES; a "simple" POST
#   (text/plain, form-urlencoded, multipart) is still delivered and executed.
#   CrossSiteRequestGuard refuses state-changing requests whose
#   ``Sec-Fetch-Site`` / ``Origin`` say they came from another site, and
#   refuses the body types a cross-site form/fetch can send without a CORS
#   preflight. Requests with no Origin at all (curl, the CLI, TestClient) are
#   not browser-originated and pass.

#: Host-header names that are always accepted (any port).
_LOOPBACK_HOST_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})

#: Methods that must not change state, and so skip the cross-site checks.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

#: Body media types a browser sends cross-site WITHOUT a CORS preflight that
#: no JSON route accepts. multipart/form-data is also preflight-free but is how
#: uploads arrive, so it relies on the Origin / Sec-Fetch-Site checks instead.
_SIMPLE_BODY_TYPES = frozenset({"text/plain", "application/x-www-form-urlencoded"})

#: Prefixes exempt from the body Content-Type rule (NOT from the origin
#: checks): the mounted Marimo app owns its own request formats.
_CONTENT_TYPE_EXEMPT_PREFIXES = ("/notebook",)


def _header(scope: Scope, name: bytes) -> str | None:
    """Return the first value of header *name* (lower-case bytes) in *scope*."""
    for key, value in scope.get("headers") or ():
        if key == name:
            return value.decode("latin-1")
    return None


def _host_name(host_header: str) -> str:
    """Return the host part of a Host header value, lower-cased, sans port."""
    value = host_header.strip().lower()
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value  # bare name, or an unbracketed IPv6 literal such as ::1


def allowed_host_names(settings: Settings) -> frozenset[str]:
    """Return every Host name (port-less, lower-case) the API answers to.

    Loopback names, plus ``MEMDIVER_ALLOWED_HOSTS``, plus the bind host itself
    when it is a non-loopback interface that passed
    :func:`enforce_bind_guardrail` (token set, or the explicit insecure
    override) — otherwise a deliberate network bind could not be reached.
    ``"*"`` in ``MEMDIVER_ALLOWED_HOSTS`` disables the check (not recommended).
    """
    from memdiver.api.config import split_list_setting

    names = set(_LOOPBACK_HOST_NAMES)
    names.update(h.lower() for h in split_list_setting(settings.allowed_hosts))
    bind = (settings.host or "").strip().lower().strip("[]")
    if bind and bind not in _LOOPBACK_HOSTS and (settings.api_token or settings.allow_insecure):
        names.add(bind)
    return frozenset(names)


async def _reject(scope: Scope, receive: Receive, send: Send, status: int, detail: str) -> None:
    """Refuse an http request with JSON, or a websocket before its accept."""
    if scope["type"] == "websocket":
        await receive()  # the websocket.connect event
        await send({"type": "websocket.close", "code": 1008})
        return
    await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)


class HostAllowListMiddleware:
    """Refuse requests whose ``Host`` header is not an allowed name (DNS rebinding)."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self._allowed = allowed_host_names(settings)
        self._wildcard = "*" in self._allowed

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket") and not self._wildcard:
            host = _header(scope, b"host")
            if host is None or _host_name(host) not in self._allowed:
                logger.warning("Rejected request with Host %r", host)
                await _reject(scope, receive, send, 421,
                              "Host header not allowed (see MEMDIVER_ALLOWED_HOSTS)")
                return
        await self.app(scope, receive, send)


def _normalise_origin(origin: str) -> str:
    return origin.strip().rstrip("/").lower()


#: Environment variables naming the Vite dev server port, first match wins.
#: ``FRONTEND_PORT`` is what tests/e2e/playwright.config.ts uses.
_DEV_FRONTEND_PORT_ENVS = ("MEMDIVER_FRONTEND_PORT", "FRONTEND_PORT")

#: Vite's default ``server.port`` (frontend/vite.config.ts).
_DEFAULT_DEV_FRONTEND_PORT = "5173"


def dev_frontend_origins() -> tuple[str, ...]:
    """Return the Vite dev server origins trusted in addition to ``cors_origins``.

    Both ``http://localhost:<port>`` and ``http://127.0.0.1:<port>`` for the
    port in ``MEMDIVER_FRONTEND_PORT`` / ``FRONTEND_PORT`` (default 5173). A
    non-numeric value is ignored. Any other origin must be listed in
    ``MEMDIVER_CORS_ORIGINS`` or be same-origin with the request's Host.
    """
    port = _DEFAULT_DEV_FRONTEND_PORT
    for name in _DEV_FRONTEND_PORT_ENVS:
        value = (os.environ.get(name) or "").strip()
        if value:
            port = value
            break
    if not port.isdigit():
        return ()
    return (f"http://localhost:{port}", f"http://127.0.0.1:{port}")


class CrossSiteRequestGuard:
    """Refuse cross-site state-changing requests and preflight-free JSON bodies.

    Applies to non-safe HTTP methods and to every websocket handshake:

    1. ``Sec-Fetch-Site: cross-site`` -> 403.
    2. An ``Origin`` that is neither same-origin with the request's ``Host``
       (which covers the Vite dev proxy: it runs with ``changeOrigin: false``
       so Host stays the dev server's), nor one of the configured
       ``cors_origins``, nor a Vite dev origin from
       :func:`dev_frontend_origins` -> 403. A loopback Origin on some OTHER
       port is refused like any other origin: another local web service
       (a notebook, a second dev server) must not drive MemDiver.
       ``Origin: null``, sent by sandboxed frames and file:// pages, is
       never allowed.
    3. HTTP only: a request carrying a body with no Content-Type, or with
       ``text/plain`` / ``application/x-www-form-urlencoded`` -> 415. JSON
       routes need ``application/json``; multipart uploads are covered by 1-2.
    """

    def __init__(self, app: ASGIApp, cors_origins: Iterable[str]) -> None:
        self.app = app
        trusted = [*cors_origins, *dev_frontend_origins()]
        self._trusted_origins = frozenset(_normalise_origin(o) for o in trusted)

    def _origin_problem(self, scope: Scope) -> str | None:
        if (_header(scope, b"sec-fetch-site") or "").lower() == "cross-site":
            return "cross-site request refused"
        origin = _header(scope, b"origin")
        if origin is None:
            return None
        normalised = _normalise_origin(origin)
        if normalised in self._trusted_origins:
            return None
        host = (_header(scope, b"host") or "").strip().lower()
        _, sep, netloc = normalised.partition("://")
        if sep and host and netloc == host:
            return None
        return "cross-origin request refused"

    @staticmethod
    def _content_type_problem(scope: Scope) -> str | None:
        path = scope.get("path", "")
        if any(path == p or path.startswith(p + "/") for p in _CONTENT_TYPE_EXEMPT_PREFIXES):
            return None
        length = _header(scope, b"content-length")
        chunked = "chunked" in (_header(scope, b"transfer-encoding") or "").lower()
        has_body = chunked or (length is not None and length.strip() not in ("", "0"))
        if not has_body:
            return None
        media_type = (_header(scope, b"content-type") or "").split(";", 1)[0].strip().lower()
        if not media_type or media_type in _SIMPLE_BODY_TYPES:
            return "request body must be application/json (or multipart/form-data for uploads)"
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        guarded = scope["type"] == "websocket" or (
            scope["type"] == "http" and scope.get("method", "GET").upper() not in _SAFE_METHODS
        )
        if guarded:
            problem = self._origin_problem(scope)
            if problem:
                logger.warning("%s: %s %s", problem, scope.get("method", "WS"), scope.get("path"))
                await _reject(scope, receive, send, 403, problem)
                return
            if scope["type"] == "http":
                problem = self._content_type_problem(scope)
                if problem:
                    await _reject(scope, receive, send, 415, problem)
                    return
        await self.app(scope, receive, send)
