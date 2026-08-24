"""Pcaps router — upload packet captures for later pipeline verification.

Exposes ``POST /api/pcaps/upload`` which streams a multipart capture to
``settings.upload_dir/pcaps/`` in 1 MiB chunks, enforces a 512 MiB size cap
(``PCAP_UPLOAD_MAX_BYTES``), and returns the persisted path.

Unlike the dumps router (which converts then discards its temp upload), the
stored capture is *persisted* on success: the verification pipeline re-reads
``pcap_path`` later. See the note on ``dest`` below for the disk posture.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from memdiver.api.config import Settings
from memdiver.api.dependencies import get_api_settings
from memdiver.api.path_safety import ensure_within

logger = logging.getLogger("memdiver.api.routers.pcaps")

router = APIRouter()

PCAP_UPLOAD_MAX_BYTES = 512 * 1024 ** 2

ALLOWED_PCAP_SUFFIXES = (".pcap", ".pcapng", ".cap")


def _prune_pcap_dir(pcap_dir: Path, quota_bytes: int, keep: Path) -> None:
    """Best-effort LRU prune of ``pcap_dir`` down to ``quota_bytes``.

    Deletes oldest files (by mtime) first until the aggregate size is under the
    quota. ``keep`` (the just-uploaded file) is never removed. ``quota_bytes``
    <= 0 disables pruning. Files vanishing mid-prune (racing request) are
    tolerated — the prune is advisory, not transactional.
    """
    if quota_bytes <= 0:
        return
    # Snapshot (mtime, size, path) tolerantly: a file vanishing here or below
    # (a concurrent upload/prune) is simply skipped, never fatal.
    stats = []
    for p in pcap_dir.iterdir():
        try:
            st = p.stat()
        except FileNotFoundError:
            continue
        if p.is_file():
            stats.append((st.st_mtime, st.st_size, p))
    total = sum(size for _, size, _ in stats)
    for _, size, p in sorted(stats):  # oldest mtime first
        if total <= quota_bytes:
            break
        if p == keep:  # never evict the just-uploaded capture
            continue
        try:
            p.unlink()
        except FileNotFoundError:
            continue
        total -= size
        logger.info("pruned oldest pcap %s to stay under quota", p.name)


@router.post("/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    settings: Settings = Depends(get_api_settings),
):
    """Upload a packet capture and persist it for pipeline verification.

    The capture is streamed in 1 MiB chunks to a uuid-named file under
    ``settings.upload_dir/pcaps/`` (0o600), preserving the original suffix.
    Uploads exceeding ``PCAP_UPLOAD_MAX_BYTES`` are rejected with 413 and any
    partial file is removed; a disallowed suffix is rejected with 400.
    """
    suffix = Path(file.filename or "upload").suffix.lower()
    if suffix not in ALLOWED_PCAP_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported capture suffix {suffix!r}; "
            f"expected one of {', '.join(ALLOWED_PCAP_SUFFIXES)}",
        )

    try:
        pcap_dir = ensure_within(settings.upload_dir, settings.upload_dir / "pcaps")
    except ValueError as exc:
        # Defensive: a planted symlink at upload_dir/pcaps escaping the base
        # would otherwise surface as a 500. Mirror validate_pcap's 400 handling
        # without disclosing the resolved absolute base path.
        raise HTTPException(
            status_code=400,
            detail="upload directory misconfigured: pcaps path escapes the upload directory",
        ) from exc
    pcap_dir.mkdir(parents=True, exist_ok=True)

    # upload_dir/pcaps/ is persisted (the verification pipeline re-reads
    # pcap_path later) but bounded: after the write we LRU-prune the dir back
    # under settings.pcap_quota_bytes (see _prune_pcap_dir).
    dest = pcap_dir / f"{uuid4().hex}{suffix}"
    size = 0
    try:
        # Create the destination already-0o600 (owner-only) via a custom opener
        # so the secret capture never briefly exists world/group-readable under
        # the process umask. O_EXCL guards against clobbering a pre-existing
        # name (the uuid makes a collision practically impossible anyway).
        def _open_private(path, flags):
            return os.open(
                path, flags | os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )

        with open(dest, "wb", opener=_open_private) as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > PCAP_UPLOAD_MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="pcap exceeds 512 MiB cap",
                    )
                out.write(chunk)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise

    # Bound the persisted pcaps dir: evict oldest captures (never `dest`) once
    # the aggregate exceeds the quota. Best-effort — a prune hiccup must not
    # fail an otherwise-successful upload.
    _prune_pcap_dir(pcap_dir, settings.pcap_quota_bytes, keep=dest)

    return {"pcap_path": str(dest), "filename": file.filename, "size": size}


class ValidatePcapRequest(BaseModel):
    """Body for ``POST /api/pcaps/validate``: a path to a persisted capture."""

    pcap_path: str


@router.post("/validate")
def validate_pcap(
    body: ValidatePcapRequest,
    settings: Settings = Depends(get_api_settings),
):
    """Arm/validate a persisted capture: summarise the TLS sessions it holds.

    The pcap verification flow's arm step. ``pcap_path`` must point inside
    ``settings.upload_dir`` (a previously :func:`upload_pcap`-persisted file);
    a path escaping that directory or a non-existent file is rejected with 400.
    The parse itself is delegated to the shared
    :func:`memdiver.app.tools_pipeline.inspect_pcap` producer, so a missing
    ``pcap`` extra or an unreadable capture surfaces as its ``CapabilityError``
    (translated to an HTTP response by the app's global handler).
    """
    from memdiver.app.tools_pipeline import inspect_pcap

    try:
        pcap_path = ensure_within(settings.upload_dir, Path(body.pcap_path))
    except ValueError as exc:
        # Do not echo the resolved absolute upload_dir (the ValueError message
        # embeds it) — that would disclose the server's on-disk layout.
        raise HTTPException(
            status_code=400,
            detail="pcap_path escapes the upload directory",
        ) from exc
    if not pcap_path.is_file():
        raise HTTPException(
            status_code=400,
            detail="capture not found under the upload directory",
        )

    return inspect_pcap(pcap_path=str(pcap_path))
