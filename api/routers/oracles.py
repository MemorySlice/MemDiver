"""HTTP endpoints for the BYO oracle registry.

Contract (see the plan's B5 task):

* ``GET  /api/oracles/examples`` — list bundled example oracles from
  ``docs/oracle/examples/*.py``, including sha256 + detected shape, plus the
  parsed sibling ``.toml`` (if any) as a ``config_template`` the UI prefills
  its form from.
* ``POST /api/oracles/examples/{filename}/load`` — copy a bundled example into
  the oracle dir and register it through the *same* path an upload takes.
  Bundled is not trusted.
* ``GET  /api/oracles``            — list uploaded oracles.
* ``POST /api/oracles/upload``     — multipart upload; only when
  ``MEMDIVER_ORACLE_DIR`` is configured. Writes the file at
  ``0o600``, computes sha256, detects Shape 1 vs Shape 2, returns the
  registered :class:`OracleEntry` with ``armed: false``.
* ``POST /api/oracles/{id}/arm``   — body echoes the sha256 the client
  saw; server re-hashes on disk and refuses on mismatch.
* ``POST /api/oracles/{id}/dry-run`` — run the oracle against a list
  of base64-encoded sample candidates and report pass/fail counts.
* ``DELETE /api/oracles/{id}``     — remove the file and the registry
  entry. The oracle's ``__pycache__/`` is purged too.
* ``GET  /api/oracles/status``     — is the oracle dir enabled, where, and
  who decided (env var vs the user's own opt-in). Always 200.
* ``POST /api/oracles/enable``     — the user's explicit consent to store and
  execute oracle code, replacing the "set an env var and restart" ritual.

When ``MEMDIVER_ORACLE_DIR`` is unset the *upload* / *arm* / *delete*
endpoints return **503** with an explanatory detail. ``examples`` and
``dry-run`` on example oracles keep working because they don't write.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from memdiver.api.config import env_pinned, get_settings
from memdiver.api.dependencies import oracle_registry_or_503 as _registry
from memdiver.api.oracle_dir import (
    default_oracle_dir,
    validate_candidate,
    write_user_oracle_dir,
)
from memdiver.api.services.oracle_registry import (
    OracleDisabled,
    OracleNotArmed,
    OracleNotFound,
    OracleRegistryError,
    OracleShaMismatch,
)

logger = logging.getLogger("memdiver.api.routers.oracles")

router = APIRouter()

#: The variable that pins the oracle dir outside the UI's control.
ENV_VAR = "MEMDIVER_ORACLE_DIR"


def _map_registry_error(exc: OracleRegistryError) -> HTTPException:
    if isinstance(exc, OracleDisabled):
        return HTTPException(status_code=503, detail=str(exc))
    if isinstance(exc, OracleNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, OracleShaMismatch):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, OracleNotArmed):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


# ----- models --------------------------------------------------------------


class ArmRequest(BaseModel):
    sha256: str = Field(..., min_length=64, max_length=64)
    config: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "The oracle's own parameters (Shape 2). Sent here rather than on a "
            "separate endpoint because arming is already the user-intent gate: "
            "the config is stored and then replayed through the strict "
            "sandboxed load, so the same click that says 'run this' is the one "
            "that proves it loads. Omit to keep whatever is already stored."
        ),
    )


class LoadExampleRequest(BaseModel):
    """Body for ``POST /api/oracles/examples/{filename}/load`` (all optional)."""

    config: Optional[Dict[str, Any]] = None
    description: Optional[str] = None


class DryRunRequest(BaseModel):
    samples_b64: List[str] = Field(..., max_length=64)


class EnableRequest(BaseModel):
    """Body for ``POST /api/oracles/enable``; the whole body is optional."""

    path: Optional[str] = Field(
        None,
        description=(
            "Absolute directory to store oracles in; defaults to the "
            "per-user default_oracle_dir()"
        ),
    )


def _active_oracle_dir() -> Optional[Path]:
    """Return the dir oracles are actually stored in, or ``None`` if disabled.

    The live registry is asked first and ``Settings`` is only the fallback,
    because the registry is what actually gates ``/upload`` — reporting
    ``enabled: true`` from a setting the running registry never picked up would
    send the UI straight back into the 503 this endpoint exists to prevent.
    """
    try:
        registry = _registry()
    except HTTPException:
        # Registry singleton not built yet (server still starting). Fall back
        # to the configured value rather than failing the status call.
        return get_settings().oracle_dir
    try:
        return registry.require_enabled()
    except OracleRegistryError:
        return None


def _status() -> dict:
    """Build the oracle-directory status payload the UI renders."""
    path = _active_oracle_dir()
    pinned = env_pinned(ENV_VAR)
    if path is None:
        source = None
    elif pinned:
        source = "env"
    else:
        source = "user_config"
    return {
        "enabled": path is not None,
        "path": str(path) if path is not None else None,
        "source": source,
        "env_pinned": pinned,
        "default_path": str(default_oracle_dir()),
    }


# ----- routes --------------------------------------------------------------


@router.get("/examples")
def list_examples():
    registry = _registry()
    return {"examples": registry.list_examples()}


@router.post("/examples/{filename}/load")
def load_example_oracle(filename: str, request: Optional[LoadExampleRequest] = None):
    """Register a bundled example as if the user had uploaded it themselves.

    Deliberately NOT a shortcut around :meth:`OracleRegistry.upload`: the
    example's bytes are copied into the oracle dir and pushed through the
    identical pipeline (0o600, ``__pycache__`` purge, capped sandbox probe
    before any in-process import, shape detection). Shipping a file in the repo
    is not a trust decision.

    ``filename`` is matched against the enumerated example list inside the
    registry rather than joined onto the examples directory, so a traversal
    attempt is a 404 rather than a read.
    """
    registry = _registry()
    try:
        registry.require_enabled()
    except OracleRegistryError as exc:
        raise _map_registry_error(exc)
    try:
        entry = registry.load_example(
            filename,
            config=request.config if request is not None else None,
            description=request.description if request is not None else None,
        )
    except OracleRegistryError as exc:
        raise _map_registry_error(exc)
    return entry.to_dict()


@router.get("")
def list_oracles():
    registry = _registry()
    return {"oracles": [e.to_dict() for e in registry.list_entries()]}


# Both routes below are declared ahead of every ``/{oracle_id}`` path on
# purpose: FastAPI matches in declaration order, so a later literal segment
# would otherwise be swallowed as an oracle id.


@router.get("/status")
def oracle_status():
    """Report whether oracle storage is enabled, and who decided that.

    Always 200. "Disabled" is a state the UI renders (as a consent panel), not
    an error — the 503 belongs on the endpoints that would actually write or
    execute something.
    """
    return _status()


@router.post("/enable")
def enable_oracles(request: Optional[EnableRequest] = None):
    """Turn on oracle storage and execution, persisting the user's consent.

    Ordered strictly: refuse if pinned -> validate (which mkdirs, proves
    writability and pins 0o700) -> persist the user config file -> mutate the
    in-memory Settings -> point the live registry at it. A failed write must
    never leave disk and memory disagreeing, and nothing is persisted for a
    directory that turned out to be unusable.
    """
    registry = _registry()  # 503 early, before anything is written

    if env_pinned(ENV_VAR):
        raise HTTPException(
            status_code=409,
            detail=(
                f"oracle_dir is pinned by {ENV_VAR}; "
                "unset it to configure the directory from the UI"
            ),
        )

    raw = (request.path if request is not None else None) or str(default_oracle_dir())
    try:
        resolved = validate_candidate(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    write_user_oracle_dir(resolved)

    # Mutate the cached Settings IN PLACE — never get_settings.cache_clear().
    # get_settings() is @lru_cache(maxsize=1) and ApiTokenAuthMiddleware plus
    # the startup ArtifactStore hold a reference to this exact instance.
    get_settings().oracle_dir = resolved
    registry.enable(resolved)
    logger.info("oracle_dir enabled at %s", resolved)

    return _status()


@router.post("/upload")
async def upload_oracle(
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
):
    registry = _registry()
    try:
        registry.require_enabled()
    except OracleRegistryError as exc:
        raise _map_registry_error(exc)
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="empty upload")
    if len(content) > 1_000_000:
        raise HTTPException(status_code=413, detail="oracle file too large (>1 MB)")
    try:
        entry = registry.upload(
            filename=file.filename or "oracle.py",
            content=content,
            description=description,
        )
    except OracleRegistryError as exc:
        raise _map_registry_error(exc)
    return entry.to_dict()


@router.post("/{oracle_id}/arm")
def arm_oracle(oracle_id: str, request: ArmRequest):
    registry = _registry()
    try:
        entry = registry.arm(oracle_id, request.sha256, config=request.config)
    except OracleRegistryError as exc:
        raise _map_registry_error(exc)
    return entry.to_dict()


@router.post("/{oracle_id}/dry-run")
def dry_run_oracle(oracle_id: str, request: DryRunRequest):
    registry = _registry()
    try:
        samples = [base64.b64decode(s, validate=True) for s in request.samples_b64]
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400,
                            detail=f"invalid base64 sample: {exc}")
    try:
        return registry.dry_run(oracle_id, samples=samples)
    except OracleRegistryError as exc:
        raise _map_registry_error(exc)


@router.delete("/{oracle_id}")
def delete_oracle(oracle_id: str):
    registry = _registry()
    try:
        registry.delete(oracle_id)
    except OracleRegistryError as exc:
        raise _map_registry_error(exc)
    return {"oracle_id": oracle_id, "deleted": True}
