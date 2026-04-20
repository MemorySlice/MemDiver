"""HTTP endpoints for the BYO oracle registry.

Contract (see the plan's B5 task):

* ``GET  /api/oracles/examples`` — list bundled example oracles from
  ``docs/oracle_examples/*.py``, including sha256 + detected shape.
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

When ``MEMDIVER_ORACLE_DIR`` is unset the *upload* / *arm* / *delete*
endpoints return **503** with an explanatory detail. ``examples`` and
``dry-run`` on example oracles keep working because they don't write.
"""

from __future__ import annotations

import base64
import logging
from typing import List, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from api.dependencies import oracle_registry_or_503 as _registry
from api.services.oracle_registry import (
    OracleDisabled,
    OracleNotArmed,
    OracleNotFound,
    OracleRegistryError,
    OracleShaMismatch,
)

logger = logging.getLogger("memdiver.api.routers.oracles")

router = APIRouter()


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


class DryRunRequest(BaseModel):
    samples_b64: List[str] = Field(..., max_length=64)


# ----- routes --------------------------------------------------------------


@router.get("/examples")
def list_examples():
    registry = _registry()
    return {"examples": registry.list_examples()}


@router.get("")
def list_oracles():
    registry = _registry()
    return {"oracles": [e.to_dict() for e in registry.list_entries()]}


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
        entry = registry.arm(oracle_id, request.sha256)
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
