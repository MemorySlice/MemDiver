"""FastAPI dependency injection for MemDiver."""

from __future__ import annotations

import logging

from fastapi import HTTPException

from api.config import Settings, get_settings
from mcp_server.session import ToolSession

logger = logging.getLogger("memdiver.api.dependencies")

_tool_session: ToolSession | None = None


def get_tool_session() -> ToolSession:
    """Return a singleton ToolSession for the API lifetime."""
    global _tool_session
    if _tool_session is None:
        _tool_session = ToolSession()
        logger.info("Created ToolSession singleton")
    return _tool_session


def get_api_settings() -> Settings:
    """Return the cached Settings singleton."""
    return get_settings()


def task_manager_or_503():
    """Return the TaskManager singleton, or raise HTTP 503 if uninitialized."""
    from api.services.task_manager import get_task_manager

    try:
        return get_task_manager()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def oracle_registry_or_503():
    """Return the OracleRegistry singleton, or raise HTTP 503 if uninitialized."""
    from api.services.oracle_registry import get_oracle_registry

    try:
        return get_oracle_registry()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
