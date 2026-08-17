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

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from memdiver.api.config import Settings

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


class InsecureBindError(RuntimeError):
    """Raised when refusing to bind a non-loopback host without a token."""


def enforce_bind_guardrail(host: str, settings: Settings) -> None:
    """Refuse a non-loopback bind that has no auth and no explicit override.

    MemDiver is meant to be reachable only from the operator's own machine
    (see the localhost trust model note in ``api/main.py::create_app``):
    request handlers deliberately trust free-form filesystem paths on that
    assumption. Binding a non-loopback interface with neither an API token
    nor ``MEMDIVER_API_ALLOW_INSECURE=1`` would expose every forensic data
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
            "Binding %s with MEMDIVER_API_ALLOW_INSECURE=1 and no "
            "MEMDIVER_API_TOKEN set: the API is reachable from the network "
            "with NO authentication. Set MEMDIVER_API_TOKEN to secure it.",
            host,
        )
        return
    raise InsecureBindError(
        f"Refusing to bind {host} without MEMDIVER_API_TOKEN. Set a token, "
        "or MEMDIVER_API_ALLOW_INSECURE=1 to override."
    )
