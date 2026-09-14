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
from collections.abc import Mapping as _MappingABC
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from memdiver.api.path_safety import safe_filename
from memdiver.engine.session_store import _EXT as _SESSION_EXT
from memdiver.engine.session_store import SessionSnapshot, SessionStore

logger = logging.getLogger("memdiver.api.services.session_service")

# The ONLY keys a persisted dump entry may carry. This is a whitelist, and it
# is a security control rather than a tidiness one: the frontend's DumpEntry
# also holds a `keyMaterial` block (passphrase / key_hex / kem_key_hex) of
# PLAINTEXT recovered secrets, and session files are unprotected gzipped JSON
# under ~/.memdiver/sessions/.
#
# `api.routers.sessions.SessionDumpEntry` already filters the HTTP path. This
# second, independent filter covers every DIRECT caller of the service — the
# Marimo notebook, the library API, tests — which never passes through
# Pydantic. Two guards, because one guard that someone can route around is
# not a guard.
_DUMP_ENTRY_DEFAULTS: Dict[str, Any] = {
    "path": "",
    "name": "",
    "size": 0,
    "format": "",
}


def _sanitize_dumps(dumps: Any) -> List[Dict[str, Any]]:
    """Reduce each dump entry to exactly the four persistable keys.

    Anything else — ``key_material``, ``passphrase``, ``tag_status``, an
    unknown future key — is dropped. Non-mapping entries are skipped rather
    than raising: a malformed dump list must not fail an otherwise valid save.
    """
    if not isinstance(dumps, (list, tuple)):
        return []
    sanitized: List[Dict[str, Any]] = []
    for entry in dumps:
        if not isinstance(entry, _MappingABC):
            continue
        sanitized.append({
            key: entry.get(key, default)
            for key, default in _DUMP_ENTRY_DEFAULTS.items()
        })
    return sanitized



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

    ``dumps`` entries are additionally reduced to the four persistable keys
    by :func:`_sanitize_dumps` — see its docstring for why that matters.
    """
    fields = SessionSnapshot.__dataclass_fields__
    data = {k: v for k, v in payload.items() if k in fields}
    data["dumps"] = _sanitize_dumps(data.get("dumps"))
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
    # Contain the client-supplied session name to a bare filename inside the
    # session directory — reject path separators / traversal (ValueError).
    path = safe_filename(directory, stem, _SESSION_EXT)
    return SessionStore.save(snapshot, path)


def load_session(name: str, directory: Path) -> SessionSnapshot:
    """Load a session snapshot by stem name.

    Raises:
        FileNotFoundError: if no matching session file exists.
    """
    path = safe_filename(directory, name, _SESSION_EXT)
    if not path.is_file():
        raise FileNotFoundError(f"Session not found: {name}")
    return SessionStore.load(path)


def delete_session(name: str, directory: Path) -> None:
    """Delete a session by stem name.

    Raises:
        FileNotFoundError: if no matching session file exists.
        ValueError: if *name* is not a bare filename (path traversal attempt).
    """
    # Validate containment before SessionStore.delete builds the path itself.
    safe_filename(directory, name, _SESSION_EXT)
    SessionStore.delete(name, directory)


def list_sessions(directory: Optional[Path] = None) -> list:
    """Thin passthrough for symmetry with the other service helpers."""
    return SessionStore.list_sessions(directory)
