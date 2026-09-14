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
from pydantic import BaseModel, ConfigDict, field_validator

from memdiver import __version__ as _MEMDIVER_VERSION
from memdiver.api.config import Settings
from memdiver.api.dependencies import get_api_settings
from memdiver.api.services import session_service
from memdiver.engine.session_store import SessionStore

logger = logging.getLogger("memdiver.api.routers.sessions")

router = APIRouter()


class SessionDumpEntry(BaseModel):
    """One loaded dump, as it is allowed to be persisted in a session file.

    SECURITY BOUNDARY — this model is a whitelist, not a convenience shape.
    The frontend's ``DumpEntry`` also carries a ``keyMaterial`` block
    (``passphrase`` / ``key_hex`` / ``kem_key_hex``) holding PLAINTEXT
    recovered secrets, and session files are unprotected gzipped JSON under
    ``~/.memdiver/sessions/``. Declaring exactly these four fields with
    ``extra="ignore"`` means any additional key a client sends — today's
    ``keyMaterial``/``tagStatus`` or tomorrow's — is dropped here rather than
    written to disk.

    ``tagStatus`` is deliberately absent too: a persisted ``"valid"`` without
    its key would make the UI claim "unlocked" after the key is long gone.

    This is one of three independent whitelists (the others are the explicit
    destructure in the frontend's ``buildSessionSnapshot`` and
    ``session_service._sanitize_dumps`` for direct, non-HTTP callers).
    """

    model_config = ConfigDict(extra="ignore")

    path: str = ""
    name: str = ""
    size: int = 0
    format: str = ""


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

    # --- Multi-dump workspace (schema v2) -----------------------------------
    # Mirrors the additive SessionSnapshot fields. All optional on the wire so
    # a pre-v2 client (or a wizard-only save with no dumps yet) still POSTs
    # successfully.
    dumps: List[SessionDumpEntry] = []
    active_dump_path: str = ""
    selected_dump_paths: List[str] = []
    collapsed_dump_paths: List[str] = []
    origin_dump_path: str = ""
    main_view: str = "single"
    aslr_normalize: bool = False
    dump_weights: Dict[str, float] = {}
    excluded_dump_paths: List[str] = []
    solo_dump_path: str = ""
    rail_collapsed: bool = False

    @field_validator(
        "session_name",
        "input_mode",
        "input_path",
        "dataset_root",
        "keylog_filename",
        "template_name",
        "protocol_name",
        "protocol_version",
        "scenario",
        "selected_phase",
        "algorithm",
        "single_file_format",
        "active_dump_path",
        "origin_dump_path",
        "solo_dump_path",
        mode="before",
    )
    @classmethod
    def _null_means_empty(cls, value: Any) -> Any:
        """Accept ``null`` for any "absent string" field and store ``""``.

        These fields model "nothing selected", which a JavaScript client
        naturally expresses as ``null`` -- ``soloPath`` and ``originDumpId`` are
        literally typed ``string | null`` in the frontend stores. Rejecting that
        produced a 422 that neither test suite could see: the frontend tests
        mock this endpoint, and the backend tests send ``""``. Only saving a
        session from the real browser reached it.
        """
        return "" if value is None else value


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
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return asdict(snapshot)


@router.post("/")
def save_session(
    payload: SessionPayload,
    settings: Settings = Depends(get_api_settings),
):
    """Save full session state from the frontend."""
    try:
        saved = session_service.save_session(
            payload.model_dump(),
            settings.session_dir,
            memdiver_version=_MEMDIVER_VERSION,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
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
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    logger.info("Deleted session: %s", name)
    return {"deleted": name, "status": "ok"}
