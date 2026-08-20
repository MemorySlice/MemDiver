"""Dumps router — import raw dumps with file upload support."""

from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from memdiver.api.config import Settings
from memdiver.api.dependencies import get_api_settings, get_tool_session
from memdiver.api.path_safety import ensure_within
from memdiver.app.session import ToolSession
from memdiver.mcp_server import tools

logger = logging.getLogger("memdiver.api.routers.dumps")

router = APIRouter()

DUMP_UPLOAD_MAX_BYTES = 4 * 1024 ** 3


@router.post("/upload")
async def upload_dump(
    file: UploadFile = File(...),
    output_dir: str = "",
    pid: int = 0,
    session: ToolSession = Depends(get_tool_session),
    settings: Settings = Depends(get_api_settings),
):
    """Upload a dump file and convert to MSL format.

    The uploaded file is saved to a temp directory, converted via
    ``tools.import_dump`` (which sniffs raw/.dump, ELF core, or minidump and
    dispatches accordingly), then the temp file is cleaned up.
    """
    suffix = Path(file.filename or "upload").suffix or ".dump"
    tmp_size = 0
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            while chunk := await file.read(1024 * 1024):
                tmp_size += len(chunk)
                if tmp_size > DUMP_UPLOAD_MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="dump exceeds 4 GiB cap",
                    )
                tmp.write(chunk)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    try:
        # A caller-supplied output_dir must stay inside the configured upload
        # directory; otherwise the converted .msl could be written anywhere the
        # server process can reach (arbitrary write). With no output_dir the
        # converted file lands next to the (server-chosen) temp upload.
        if output_dir:
            try:
                out_dir = ensure_within(settings.upload_dir, Path(output_dir))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            out_dir.mkdir(parents=True, exist_ok=True)
        else:
            out_dir = tmp_path.parent
        out_path = str(out_dir / (tmp_path.stem + ".msl"))
        result = await asyncio.to_thread(
            tools.import_dump, session, str(tmp_path), out_path, pid
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    return result
