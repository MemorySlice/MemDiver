"""REST API for incremental consensus sessions (Welford-backed)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from api.services.consensus_session import (
    ConsensusSessionManager,
    get_consensus_manager,
)
from core.dump_source import open_dump
from core.variance import count_classifications

logger = logging.getLogger("memdiver.api.routers.consensus")

router = APIRouter()


class BeginRequest(BaseModel):
    size: int = Field(..., gt=0, description="Consensus width in bytes")


class BeginResponse(BaseModel):
    session_id: str
    size: int


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


def _read_server_side_dump(path_str: str, size: int) -> bytes:
    try:
        with open_dump(Path(path_str)) as source:
            data = source.read_all()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Not found: {path_str}")
    if len(data) < size:
        raise HTTPException(
            status_code=400,
            detail=f"dump shorter than consensus size ({len(data)} < {size})",
        )
    return bytes(data[:size])


@router.post("/begin", response_model=BeginResponse)
def begin_session(
    req: BeginRequest,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
) -> BeginResponse:
    session = manager.begin(req.size)
    return BeginResponse(session_id=session.session_id, size=session.size)


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
    data = _read_server_side_dump(req.path, session.size)
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
    data = await file.read()
    if len(data) < session.size:
        raise HTTPException(
            status_code=400,
            detail=f"dump shorter than consensus size ({len(data)} < {session.size})",
        )
    num, _mean, _max = manager.add_dump(
        session_id, bytes(data[: session.size]), label=label or file.filename,
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
