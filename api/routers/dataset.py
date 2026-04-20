"""Dataset discovery router — scan, protocols, phases."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from api.dependencies import get_tool_session
from api.models import ScanRequest
from mcp_server import tools
from mcp_server.session import ToolSession

logger = logging.getLogger("memdiver.api.routers.dataset")

router = APIRouter()


@router.post("/scan")
def scan_dataset(
    request: ScanRequest,
    session: ToolSession = Depends(get_tool_session),
):
    """Scan a dataset directory for protocols, libraries, and phases."""
    return tools.scan_dataset(
        session, request.root, request.keylog_filename, request.protocols,
    )


@router.get("/protocols")
def list_protocols(
    session: ToolSession = Depends(get_tool_session),
):
    """List all registered protocol descriptors."""
    return tools.list_protocols(session)


@router.get("/phases")
def list_phases(
    library_dir: str,
    session: ToolSession = Depends(get_tool_session),
):
    """List available lifecycle phases for a library directory."""
    return tools.list_phases(session, library_dir)
