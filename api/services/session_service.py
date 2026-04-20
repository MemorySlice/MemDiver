"""Session service — build/save/load/delete SessionSnapshot instances.

Kills the field-mapping duplication that used to live inline inside
``api/routers/sessions.py::save_session``. Before PR 4 the router
constructed a ``SessionSnapshot`` by re-listing every field from the
wire-side ``SessionPayload`` — any new field added to the snapshot had
to be added in three places (dataclass, wire model, router mapper) or
it would be silently dropped on save. The service function now owns the
single mapping step, so the router is a thin adapter and adding a field
only touches the data class and the wire model.
"""

from __future__ import annotations

import datetime
import logging
from pathlib import Path
from typing import Any, Mapping, Optional

from engine.session_store import SessionSnapshot, SessionStore

logger = logging.getLogger("memdiver.api.services.session_service")


def payload_to_snapshot(
    payload: Mapping[str, Any],
    *,
    memdiver_version: str = "",
) -> SessionSnapshot:
    """Build a server-authoritative ``SessionSnapshot`` from a payload dict.

    Stamps ``created_at`` and ``memdiver_version`` on the snapshot. The
    payload's ``schema_version`` field (if any) is ignored — the server
    is the source of truth for the persisted schema version, so clients
    cannot forge a future version by wire.

    Unknown keys in ``payload`` are ignored rather than rejected. This
    mirrors ``SessionStore.load`` which also filters to dataclass fields.
    """
    fields = SessionSnapshot.__dataclass_fields__
    data = {k: v for k, v in payload.items() if k in fields}
    data.setdefault("created_at", datetime.datetime.now().isoformat())
    data["memdiver_version"] = memdiver_version
    # Server stamps the schema version regardless of what the client sent.
    data.pop("schema_version", None)
    snapshot = SessionSnapshot(**data)
    return snapshot


def save_session(
    payload: Mapping[str, Any],
    directory: Path,
    *,
    memdiver_version: str = "",
) -> Path:
    """Persist a session payload. Returns the file path written."""
    snapshot = payload_to_snapshot(payload, memdiver_version=memdiver_version)
    stem = snapshot.session_name or "session"
    path = Path(directory) / f"{stem}.memdiver"
    return SessionStore.save(snapshot, path)


def load_session(name: str, directory: Path) -> SessionSnapshot:
    """Load a session snapshot by stem name.

    Raises:
        FileNotFoundError: if no matching session file exists.
    """
    path = Path(directory) / f"{name}.memdiver"
    if not path.is_file():
        raise FileNotFoundError(f"Session not found: {name}")
    return SessionStore.load(path)


def delete_session(name: str, directory: Path) -> None:
    """Delete a session by stem name.

    Raises:
        FileNotFoundError: if no matching session file exists.
    """
    SessionStore.delete(name, directory)


def list_sessions(directory: Optional[Path] = None) -> list:
    """Thin passthrough for symmetry with the other service helpers."""
    return SessionStore.list_sessions(directory)
