"""REST API for incremental consensus sessions (Welford-backed)."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from memdiver.api.models import MemoryOverrideFields, RegionFilterFields
from memdiver.api.region_filter_resolution import request_region_filter
from memdiver.api.services.consensus_session import (
    ConsensusSessionManager,
    get_consensus_manager,
)
from memdiver.app.composition import open_dump
from memdiver.core.memory_budget import GIB, check_budget, resolve_memory_budget
from memdiver.core.slab_variance import as_slab_reader
from memdiver.core.variance import count_classifications
from memdiver.engine.consensus import incremental_build_estimate

logger = logging.getLogger("memdiver.api.routers.consensus")

router = APIRouter()

#: Largest consensus width a session may request -- the same 4 GiB ceiling as
#: a dump upload (``api.routers.dumps.DUMP_UPLOAD_MAX_BYTES``; duplicated so
#: this router does not import the MCP tool layer that module pulls in).
CONSENSUS_SESSION_MAX_BYTES = 4 * GIB

#: Upload read granularity for ``add-upload``.
_UPLOAD_READ_CHUNK = 8 * 1024 * 1024


class BeginRequest(RegionFilterFields, MemoryOverrideFields):
    size: int = Field(..., gt=0, le=CONSENSUS_SESSION_MAX_BYTES,
                      description="Consensus width in bytes")
    force: bool = Field(False, description=(
        "Start even when the session's estimated peak memory exceeds the "
        "memory budget (otherwise HTTP 507 memory_budget_exceeded). "
        "``force_memory`` (from MemoryOverrideFields) is an accepted alias."))


class BeginResponse(BaseModel):
    session_id: str
    size: int
    #: View filter every ``add-path`` fold reads through (None = unfiltered).
    region_filter: Optional[str] = None


class AddPathRequest(BaseModel):
    path: str = Field(..., description="Server-side path to a .dump or .msl")
    label: Optional[str] = None


class AddResponse(BaseModel):
    session_id: str
    num_dumps: int
    live_stats: Dict[str, Any]


class SessionStatusResponse(BaseModel):
    session_id: str
    size: int
    num_dumps: int
    finalized: bool
    live_stats: Dict[str, Any]
    dump_labels: list[str]


class FinalizeResponse(BaseModel):
    session_id: str
    num_dumps: int
    size: int
    classification_counts: Dict[str, int]
    variance_summary: Dict[str, float]
    #: Offsets are filtered-view offsets when set (None = unfiltered).
    region_filter: Optional[str] = None


def _read_server_side_dump(
    path_str: str, size: int, region_filter: Optional[str] = None,
) -> bytes:
    try:
        with open_dump(Path(path_str), region_filter=region_filter) as source:
            # Reads only the first ``size`` bytes where the source's flat view
            # is sliceable (raw, complete .msl); otherwise ``read_all`` once.
            reader = as_slab_reader(source)
            if reader.size < size:
                raise HTTPException(
                    status_code=400,
                    detail=f"dump shorter than consensus size ({reader.size} < {size})",
                )
            return reader.read_prefix(size)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Not found: {path_str}")


async def _read_upload_prefix(file: UploadFile, size: int) -> bytearray:
    """Read the first *size* bytes of an upload in chunks, into one buffer.

    Replaces ``await file.read()`` + ``bytes(data[:size])``, which held the
    whole upload plus a truncated copy; the remainder is never read.
    """
    buf = bytearray(size)
    view = memoryview(buf)
    got = 0
    while got < size:
        chunk = await file.read(min(_UPLOAD_READ_CHUNK, size - got))
        if not chunk:
            break
        view[got:got + len(chunk)] = chunk
        got += len(chunk)
    if got < size:
        raise HTTPException(
            status_code=400,
            detail=f"dump shorter than consensus size ({got} < {size})",
        )
    return buf


@router.post("/begin", response_model=BeginResponse)
def begin_session(
    req: BeginRequest,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
) -> BeginResponse:
    from memdiver.api.config import get_settings
    check_budget(incremental_build_estimate(req.size),
                 force=req.force or req.force_memory,
                 budget=resolve_memory_budget(get_settings()))
    session = manager.begin(req.size, region_filter=request_region_filter(req))
    return BeginResponse(session_id=session.session_id, size=session.size,
                         region_filter=session.matrix.region_filter)


@router.post("/{session_id}/add-path", response_model=AddResponse)
def add_path(
    session_id: str,
    req: AddPathRequest,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
) -> AddResponse:
    session = manager.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    if session.finalized:
        raise HTTPException(status_code=409, detail="session already finalized")
    data = _read_server_side_dump(
        req.path, session.size, getattr(session.matrix, "region_filter", None))
    num, _mean, _max = manager.add_dump(session_id, data, label=req.label)
    return AddResponse(
        session_id=session_id,
        num_dumps=num,
        live_stats=session.live_stats(),
    )


@router.post("/{session_id}/add-upload", response_model=AddResponse)
async def add_upload(
    session_id: str,
    file: UploadFile = File(...),
    label: Optional[str] = Form(None),
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
) -> AddResponse:
    session = manager.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    if session.finalized:
        raise HTTPException(status_code=409, detail="session already finalized")
    data = await _read_upload_prefix(file, session.size)
    num, _mean, _max = await asyncio.to_thread(
        manager.add_dump,
        session_id,
        data,
        label or file.filename,
    )
    return AddResponse(
        session_id=session_id,
        num_dumps=num,
        live_stats=session.live_stats(),
    )


@router.get("/{session_id}", response_model=SessionStatusResponse)
def get_session(
    session_id: str,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
) -> SessionStatusResponse:
    session = manager.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    return SessionStatusResponse(
        session_id=session_id,
        size=session.size,
        num_dumps=session.matrix.num_dumps,
        finalized=session.finalized,
        live_stats=session.live_stats(),
        dump_labels=list(session.dump_labels),
    )


@router.post("/{session_id}/finalize", response_model=FinalizeResponse)
def finalize_session(
    session_id: str,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
) -> FinalizeResponse:
    session = manager.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    session = manager.finalize(session_id)
    variance = session.matrix.variance
    counts = count_classifications(session.matrix.classifications)
    return FinalizeResponse(
        session_id=session_id,
        num_dumps=session.matrix.num_dumps,
        size=session.size,
        classification_counts=counts,
        variance_summary={
            "mean": float(variance.mean()) if len(variance) else 0.0,
            "max": float(variance.max()) if len(variance) else 0.0,
            "min": float(variance.min()) if len(variance) else 0.0,
        },
        region_filter=getattr(session.matrix, "region_filter", None),
    )


@router.delete("/{session_id}")
def delete_session(
    session_id: str,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
) -> Dict[str, bool]:
    ok = manager.delete(session_id)
    if not ok:
        raise HTTPException(status_code=404, detail="session not found")
    return {"deleted": True}
