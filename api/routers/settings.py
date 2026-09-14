"""Settings router — the server-side settings a user chooses in the UI.

Two resources, both persisted in ``memdiver_home()/config.json``:

* ``upload-dir`` — configure-on-first-use (see api/config.py and
  api/upload_dir.py): there is no silent default, so this is the endpoint the
  first-run flow uses to let the user choose where uploaded packet captures and
  memory dumps are stored.
* ``favourites`` / ``last-dir`` — the file browser's saved directories and the
  place it should reopen on (see api/favourites.py). Server-side rather than in
  the browser because ``localStorage`` is keyed by origin, so a different
  ``--port`` or a cleared cache would silently empty the list.

The handlers stay thin: every rule lives in the module that owns the setting.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from memdiver.api.config import get_settings
from memdiver.api.favourites import (
    add_favourite,
    read_favourites,
    read_last_dir,
    remove_favourite,
    write_last_dir,
)
from memdiver.api.upload_dir import (
    legacy_dir_report,
    migrate_legacy,
    validate_candidate,
    write_user_upload_dir,
)

logger = logging.getLogger("memdiver.api.routers.settings")

router = APIRouter()

ENV_VAR = "MEMDIVER_UPLOAD_DIR"


class UploadDirRequest(BaseModel):
    """Body for ``POST /api/settings/upload-dir``."""

    path: str = Field(..., description="Absolute directory to store uploads in")
    migrate_legacy: bool = Field(
        False, description="Also move files out of the legacy /tmp upload dir"
    )


class FavouriteRequest(BaseModel):
    """Body for ``POST /api/settings/favourites``."""

    path: str = Field(..., description="Absolute directory to save as a favourite")
    label: str | None = Field(
        None, description="Display name; defaults to the directory's own name"
    )


class LastDirRequest(BaseModel):
    """Body for ``PUT /api/settings/last-dir``."""

    path: str = Field(..., description="Directory the file browser was last used in")


def _env_pinned() -> bool:
    """Return True if the upload dir is pinned outside the UI's control.

    Checks the process environment *and* the ``.env`` file, because
    pydantic-settings applies both ahead of the user config file — persisting a
    value that would then be silently shadowed forever is worse than refusing.
    """
    if os.environ.get(ENV_VAR, "").strip():
        return True
    env_file = Path(get_settings().model_config.get("env_file") or ".env")
    try:
        for line in env_file.read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() == ENV_VAR and value.strip().strip("'\""):
                return True
    except OSError:
        pass
    return False


def _status() -> dict:
    """Build the current upload-dir status payload."""
    settings = get_settings()
    configured = settings.upload_dir is not None
    env_pinned = _env_pinned()
    if not configured:
        source = None
    elif env_pinned:
        source = "env"
    else:
        source = "user_config"
    payload: dict = {
        "configured": configured,
        "path": str(settings.upload_dir) if configured else None,
        "source": source,
        "env_pinned": env_pinned,
        "quota_bytes": settings.pcap_quota_bytes,
    }
    legacy = legacy_dir_report()
    if legacy is not None:
        payload["legacy"] = legacy
    return payload


@router.get("/upload-dir")
def get_upload_dir() -> dict:
    """Report where uploads are stored, and whether that is configured at all.

    Always 200: "not configured" is a legitimate state the UI renders, not an
    error.
    """
    return _status()


@router.post("/upload-dir")
def set_upload_dir(req: UploadDirRequest) -> dict:
    """Choose the upload directory, persisting it for future runs.

    Ordered strictly: validate (which also mkdirs and proves writability) ->
    persist the user config file -> mutate the in-memory Settings. A failed
    write must never leave memory and disk disagreeing.
    """
    if _env_pinned():
        raise HTTPException(
            status_code=409,
            detail=(
                f"upload_dir is pinned by {ENV_VAR}; "
                "unset it to configure the directory from the UI"
            ),
        )

    try:
        resolved = validate_candidate(req.path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    migrated = 0
    skipped = 0
    if req.migrate_legacy:
        migrated, skipped = migrate_legacy(resolved)

    write_user_upload_dir(resolved)

    # Mutate the cached Settings IN PLACE — never get_settings.cache_clear().
    # get_settings() is @lru_cache(maxsize=1) and ApiTokenAuthMiddleware (built
    # once in create_app) plus the startup ArtifactStore hold a reference to
    # this exact instance; rebuilding would strand them on a stale object.
    # Settings has validate_assignment off, so plain assignment is enough.
    get_settings().upload_dir = resolved
    logger.info("upload_dir configured to %s", resolved)

    status = _status()
    status["migrated"] = migrated
    status["skipped"] = skipped
    return status


# ---------------------------------------------------------------------------
# File browser: favourite directories and the last place it was
# ---------------------------------------------------------------------------
#
# Every mutation answers with the WHOLE list rather than with the entry it
# touched. The client then has nothing to merge — it adopts what the server
# says — so two browser tabs cannot drift into two different lists.


@router.get("/favourites")
def get_favourites() -> dict:
    """List the saved favourite directories."""
    return {"favourites": read_favourites()}


@router.post("/favourites")
def save_favourite(req: FavouriteRequest) -> dict:
    """Save a directory as a favourite, or relabel one already saved."""
    try:
        favourites = add_favourite(req.path, req.label)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"favourites": favourites}


@router.delete("/favourites")
def delete_favourite(path: str) -> dict:
    """Remove a favourite.

    Deliberately not validated: a favourite whose directory has since been
    deleted or unmounted is exactly the one a user most wants to remove, and
    refusing it would strand the entry forever.
    """
    return {"favourites": remove_favourite(path)}


@router.get("/last-dir")
def get_last_dir() -> dict:
    """Report the directory the file browser should reopen on."""
    return {"path": read_last_dir()}


@router.put("/last-dir")
def put_last_dir(req: LastDirRequest) -> dict:
    """Remember where the file browser was last used."""
    try:
        return {"path": write_last_dir(req.path)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
