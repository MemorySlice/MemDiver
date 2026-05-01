"""Dumps router — import raw dumps with file upload support."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from api.dependencies import get_tool_session
from mcp_server import tools
from mcp_server.session import ToolSession

logger = logging.getLogger("memdiver.api.routers.dumps")

router = APIRouter()

DUMP_UPLOAD_MAX_BYTES = 4 * 1024 ** 3


@router.post("/upload")
async def upload_dump(
    file: UploadFile = File(...),
    output_dir: str = "",
    pid: int = 0,
    session: ToolSession = Depends(get_tool_session),
):
    """Upload a raw dump file and convert to MSL format.

    The uploaded file is saved to a temp directory, converted via
    ``tools.import_raw_dump``, then the temp file is cleaned up.
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
        out_dir = output_dir or str(tmp_path.parent)
        out_path = str(Path(out_dir) / (tmp_path.stem + ".msl"))
        result = tools.import_raw_dump(session, str(tmp_path), out_path, pid)
    finally:
        tmp_path.unlink(missing_ok=True)

    return result
