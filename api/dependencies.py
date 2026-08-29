"""FastAPI dependency injection for MemDiver."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import HTTPException

from memdiver.api.config import Settings, get_settings
from memdiver.app.composition import build_tool_session
from memdiver.app.session import ToolSession

logger = logging.getLogger("memdiver.api.dependencies")

_tool_session: ToolSession | None = None


def get_tool_session() -> ToolSession:
    """Return a singleton ToolSession for the API lifetime."""
    global _tool_session
    if _tool_session is None:
        _tool_session = build_tool_session()
        logger.info("Created ToolSession singleton")
    return _tool_session


def get_api_settings() -> Settings:
    """Return the cached Settings singleton."""
    return get_settings()


def task_manager_or_503():
    """Return the TaskManager singleton, or raise HTTP 503 if uninitialized."""
    from memdiver.api.services.task_manager import get_task_manager

    try:
        return get_task_manager()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


#: Machine-readable prefix on the 409 detail string, so the frontend can tell
#: "you have not chosen an upload directory yet" apart from any other conflict
#: without parsing prose. Mirrored in
#: frontend/src/components/settings/upload-dir-error.ts.
UPLOAD_DIR_UNCONFIGURED = "upload_dir_unconfigured"


def upload_dir_or_409() -> Path:
    """Return the configured upload dir, creating it 0o700 if absent.

    Raises HTTP 409 when unconfigured. ``upload_dir`` is configure-on-first-use
    (see api/config.py): there is deliberately no fallback, because the field is
    also the containment root for every write-path check, so a permissive
    default would silently widen those checks instead of failing.

    409 and not 400 (the request is perfectly well-formed — the *server* is
    unconfigured) and not 500 (nothing is broken; the user just has to choose).
    The frontend keys off this exact status.

    Raised as an ``HTTPException`` rather than a ``CapabilityError``: the global
    handler in api/main.py renders the latter as ``{error, code, category}``,
    which the frontend's ``uploadFile`` cannot unwrap, whereas all three
    consumer routers already speak ``{"detail": ...}``. The detail is a
    token-prefixed plain STRING, not a dict — ``client.ts`` does
    ``JSON.parse(body).detail ?? body`` into a ``string``, so a dict would
    render as ``[object Object]``.

    Usable both as a FastAPI ``Depends`` (pcaps, which always needs it) and as
    a plain call inside a conditional branch (dumps / export-keylog, which need
    it only when the caller supplied an output path).
    """
    from memdiver.api.upload_dir import ensure_ready

    settings = get_settings()
    if settings.upload_dir is None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{UPLOAD_DIR_UNCONFIGURED}: no upload directory configured; "
                "choose one in Settings -> Storage"
            ),
        )
    return ensure_ready(settings.upload_dir)


def oracle_registry_or_503():
    """Return the OracleRegistry singleton, or raise HTTP 503 if uninitialized."""
    from memdiver.api.services.oracle_registry import get_oracle_registry

    try:
        return get_oracle_registry()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
