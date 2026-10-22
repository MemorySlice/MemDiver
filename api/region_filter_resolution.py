"""Which region view filter an analysis request runs under.

ONE rule, applied at every REST entry point that accepts ``region_filter``:

1. The request set ``region_filter`` explicitly -> that value wins. This
   includes ``"all"`` and ``null``, both of which mean "no filter" (the model
   validator has already normalised ``"all"`` to ``None``).
2. Otherwise, the request names a saved session (``session_name``) -> that
   session's persisted ``region_filter`` applies.
3. Otherwise -> no filter (the historical behaviour).

"Set explicitly" is pydantic's ``model_fields_set``: a field the client sent,
as opposed to one left at its default. That is the only way to tell an
explicit ``"all"`` (normalised to ``None``) from an omitted field.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException

__all__ = ["effective_region_filter", "request_region_filter"]


def effective_region_filter(
    requested: Optional[str],
    *,
    explicitly_set: bool,
    session_filter: Optional[str],
) -> Optional[str]:
    """Pure precedence rule: explicit request value, else the session's."""
    from memdiver.core.region_view_filter import region_filter_note

    if explicitly_set:
        return region_filter_note(requested)
    return region_filter_note(session_filter)


def _session_region_filter(session_name: str, session_dir: Path) -> Optional[str]:
    """Load *session_name* and return its persisted filter (404 if absent)."""
    from memdiver.api.services import session_service

    try:
        snapshot = session_service.load_session(session_name, session_dir)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:  # path traversal / bad name
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return getattr(snapshot, "region_filter", None)


def _default_session_dir() -> Path:
    from memdiver.api.dependencies import get_api_settings

    return Path(get_api_settings().session_dir)


def request_region_filter(
    request: Any, session_dir: Optional[Path] = None,
) -> Optional[str]:
    """Resolve the filter for a request carrying ``RegionFilterFields``.

    Only touches the session store when the request did NOT set the field and
    DID name a session, so an unfiltered request without ``session_name`` is
    exactly as cheap as before. ``session_dir`` defaults to the API settings'
    session directory.
    """
    explicitly_set = "region_filter" in getattr(request, "model_fields_set", set())
    session_name = getattr(request, "session_name", None)
    session_filter = None
    if not explicitly_set and session_name:
        directory = Path(session_dir) if session_dir is not None else _default_session_dir()
        session_filter = _session_region_filter(session_name, directory)
    return effective_region_filter(
        getattr(request, "region_filter", None),
        explicitly_set=explicitly_set,
        session_filter=session_filter,
    )
