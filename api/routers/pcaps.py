"""Pcaps router — upload packet captures for later pipeline verification.

Exposes ``POST /api/pcaps/upload`` which streams a multipart capture to
``settings.upload_dir/pcaps/`` in 1 MiB chunks, enforces a 512 MiB size cap
(``PCAP_UPLOAD_MAX_BYTES``), and returns the persisted path.

Alongside it, ``POST /api/pcaps/validate`` arms a capture (the ``pcap.inspect``
capability) and ``POST /api/pcaps/locate-field`` runs the paired field search
(``analysis.locate_field_pairs``): N dumps, each searched for a handshake field
taken from the capture that belongs to it.

Unlike the dumps router (which converts then discards its temp upload), the
stored capture is *persisted* on success: the verification pipeline re-reads
``pcap_path`` later. See the note on ``dest`` below for the disk posture.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from memdiver.api.config import Settings
from memdiver.api.dependencies import get_api_settings, upload_dir_or_409
from memdiver.api.path_safety import ensure_within
from memdiver.api.storage_quota import prune_dir_to_quota
# The producer's own default, imported rather than re-literalled so the
# route's ``max_offsets`` cannot drift from the value every other surface
# defaults to.
from memdiver.engine.key_location import DEFAULT_MAX_KEY_OFFSETS

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
    # The LRU logic is shared with the imported-dump directory; see
    # api/storage_quota.py. Kept behind this name so the existing callers and
    # tests that reach for ``_prune_pcap_dir`` are unaffected.
    prune_dir_to_quota(pcap_dir, quota_bytes, keep=keep, label="pcap")


@router.post("/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    settings: Settings = Depends(get_api_settings),
    upload_dir: Path = Depends(upload_dir_or_409),
):
    """Upload a packet capture and persist it for pipeline verification.

    The capture is streamed in 1 MiB chunks to a uuid-named file under
    ``settings.upload_dir/pcaps/`` (0o600), preserving the original suffix.
    ``upload_dir`` is configure-on-first-use, so an unconfigured server answers
    409 here (``upload_dir_or_409``) — this endpoint ALWAYS needs the directory,
    which is why it is a hard dependency rather than a conditional call.
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
        pcap_dir = ensure_within(upload_dir, upload_dir / "pcaps")
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
    """Body for ``POST /api/pcaps/validate``: a path to a persisted capture.

    The two optional caps mirror ``POST /api/pipeline/run``'s fields of the same
    name. Pass the values the run will use so the returned ``caps`` and the
    ``records_truncated`` / ``challenges_truncated`` flags describe the caps
    actually in force rather than the resource defaults. ``ge=1`` matches the
    pipeline router: a cap below 1 verifies nothing, so it could only turn a
    real key into an unexplained "0 confirmed".

    ``include_fields`` opts into the byte-addressed view of each handshake — a
    ``fields`` list plus ``field_notes`` per session and a top-level
    ``field_index``. It defaults to ``False`` so the arm request the UI has
    always sent keeps its exact response; the field browser asks for it
    explicitly, because switching it on re-reads the capture.

    ``detect_protocols`` opts into the ``protocols`` inventory — what the
    capture holds and whether any registered resource can decrypt it. Also
    ``False`` by default, for the same reason: it is the answer to "the arm step
    said 0 sessions, so what IS this capture?", which is a question the operator
    asks after the fact rather than on every arm.
    """

    pcap_path: str
    pcap_max_records: Optional[int] = Field(default=None, ge=1)
    pcap_max_challenges: Optional[int] = Field(default=None, ge=1)
    include_fields: bool = False
    detect_protocols: bool = False


@router.post("/validate")
def validate_pcap(
    body: ValidatePcapRequest,
    settings: Settings = Depends(get_api_settings),
):
    """Arm/validate a capture: summarise the TLS sessions it holds.

    The pcap verification flow's arm step. ``pcap_path`` is a READ of a capture
    the operator chose — either one previously persisted by :func:`upload_pcap`
    or a server-side path they typed, which ``docs/oracle/pcap_oracle.md``
    documents as a supported alternative to uploading. It is therefore checked
    for existence only, matching ``POST /api/pipeline/run``, which runs the very
    same parameter through the pcap oracle.

    This deliberately does NOT contain the path to ``settings.upload_dir``.
    Doing so used to break the documented type-a-path flow: the UI's manual
    "Arm / re-validate" control routes through here, so an out-of-tree capture
    could not be armed even though ``/api/pipeline/run`` would happily run it.
    Read paths on this localhost API are an accepted, documented risk (see
    ``api/main.py`` and handoff item O-15); writes are not — cf. the containment
    on ``output_path`` in ``POST /api/analysis/export-keylog``.

    The parse itself is delegated to the shared
    :func:`memdiver.app.tools_pipeline.inspect_pcap` producer, so a missing
    ``pcap`` extra or an unreadable capture surfaces as its ``CapabilityError``
    (translated to an HTTP response by the app's global handler).
    """
    from memdiver.app.tools_pipeline import inspect_pcap

    pcap_path = Path(body.pcap_path).expanduser()
    if not pcap_path.is_file():
        raise HTTPException(status_code=400, detail="capture not found")

    return inspect_pcap(
        pcap_path=str(pcap_path),
        pcap_max_records=body.pcap_max_records,
        pcap_max_challenges=body.pcap_max_challenges,
        include_fields=body.include_fields,
        detect_protocols=body.detect_protocols,
    )


class LocateFieldPairsRequest(BaseModel):
    """Body for ``POST /api/pcaps/locate-field``: N ``(dump, capture)`` pairs.

    Supply exactly ONE of ``pairs`` or ``dump_paths``; the producer refuses both
    (and neither) with INVALID_INPUT, and this model deliberately does not
    pre-empt that with a validator so all four surfaces report the mistake in
    the same words.

    * ``pairs`` — explicit pairings, ``[{"dump_path", "pcap_path",
      "client_random"?}]``. Typed as a list of plain dicts rather than a nested
      model for exactly that reason: the producer owns the per-entry key
      validation, so a misspelt key yields its message rather than FastAPI's
      422.
    * ``dump_paths`` — discovery: each dump finds the capture of the run it
      lives in.

    ``field_id`` defaults to ``client_random``, the one field present in every
    TLS version and unique per handshake. The two caps mirror
    ``ValidatePcapRequest``'s and are carried through to the needle extraction,
    so the search runs under the caps the caller asked for.
    """

    pairs: Optional[List[Dict[str, str]]] = None
    dump_paths: Optional[List[str]] = None
    field_id: str = "client_random"
    view: Optional[str] = None
    max_offsets: int = Field(default=DEFAULT_MAX_KEY_OFFSETS, ge=1)
    pcap_max_records: Optional[int] = Field(default=None, ge=1)
    pcap_max_challenges: Optional[int] = Field(default=None, ge=1)


@router.post("/locate-field")
def locate_field(body: LocateFieldPairsRequest):
    """Search N dumps for a handshake field, each from ITS OWN capture.

    The web face of ``analysis.locate_field_pairs``. ``POST
    /api/analysis/locate-key`` answers "is THIS secret in these dumps"; this
    route answers the question a corpus can actually support — "for each dump,
    is the ``field_id`` of the capture belonging to that dump present in it, and
    where?" — with the needle read off the wire and no key log involved.

    Like :func:`validate_pcap`, the paths are READS of files the operator chose
    and are checked for existence by the producer only, matching ``POST
    /api/pipeline/run``; see that docstring for the documented localhost
    read-path posture.

    The compute is delegated to
    :func:`memdiver.app.tools_pipeline.locate_field_across_pairs` — the same
    producer the CLI ``locate-field-pairs`` command, the MCP
    ``locate_field_across_pairs`` tool and ``memdiver.services`` route to, so
    the four surfaces cannot drift. Every failure (both input forms, a malformed
    pair, a missing path, a locked container) surfaces as its
    ``CapabilityError``, translated by the app's global handler.
    """
    from memdiver.app.tools_pipeline import locate_field_across_pairs

    return locate_field_across_pairs(
        pairs=body.pairs,
        dump_paths=body.dump_paths,
        field_id=body.field_id,
        view=body.view,
        max_offsets=body.max_offsets,
        pcap_max_records=body.pcap_max_records,
        pcap_max_challenges=body.pcap_max_challenges,
    )
