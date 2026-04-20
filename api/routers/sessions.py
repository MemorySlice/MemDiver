"""Sessions router — list, load, delete saved analysis sessions.

Thin HTTP adapter over ``api.services.session_service``. All mapping
between ``SessionPayload`` (wire) and ``SessionSnapshot`` (storage)
lives in one place in the service so adding a new field is a single-
site change.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.config import Settings
from api.dependencies import get_api_settings
from api.services import session_service
from engine.session_store import SessionStore

logger = logging.getLogger("memdiver.api.routers.sessions")

router = APIRouter()


class SessionPayload(BaseModel):
    """Full session state sent from the frontend on save."""

    # Optional on the wire for backward compat; the server stamps the
    # authoritative schema_version into the persisted SessionSnapshot. Accepting
    # it lets forward-dated clients round-trip a version tag through the API.
    schema_version: Optional[int] = None

    session_name: str = ""
    input_mode: str = ""
    input_path: str = ""
    dataset_root: str = ""
    keylog_filename: str = ""
    template_name: str = ""
    protocol_name: str = ""
    protocol_version: str = ""
    scenario: str = ""
    selected_libraries: List[str] = []
    selected_phase: str = ""
    algorithm: str = ""
    mode: str = "verification"
    max_runs: int = 10
    normalize_phases: bool = False
    single_file_format: str = ""
    ground_truth_mode: str = "auto"
    selected_algorithms: List[str] = []
    analysis_result: Optional[Dict[str, Any]] = None
    bookmarks: List[Dict[str, Any]] = []
    investigation_offset: Optional[int] = None


@router.get("/")
def list_sessions(settings: Settings = Depends(get_api_settings)):
    """List available saved sessions with basic metadata."""
    return {"sessions": session_service.list_sessions(settings.session_dir)}


@router.get("/{name}")
def load_session(
    name: str,
    settings: Settings = Depends(get_api_settings),
):
    """Load a session by stem name."""
    try:
        snapshot = session_service.load_session(name, settings.session_dir)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Session not found: {name}")
    return asdict(snapshot)


@router.post("/")
def save_session(
    payload: SessionPayload,
    settings: Settings = Depends(get_api_settings),
):
    """Save full session state from the frontend."""
    saved = session_service.save_session(
        payload.model_dump(),
        settings.session_dir,
    )
    logger.info("Session saved: %s", saved)
    return {
        "path": str(saved),
        "name": payload.session_name or saved.stem,
        "status": "ok",
    }


@router.delete("/{name}")
def delete_session(
    name: str,
    settings: Settings = Depends(get_api_settings),
):
    """Delete a saved session by stem name."""
    try:
        session_service.delete_session(name, settings.session_dir)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Session not found: {name}")
    logger.info("Deleted session: %s", name)
    return {"deleted": name, "status": "ok"}
