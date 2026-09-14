"""Dumps router — import raw dumps with file upload support."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import NamedTuple
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from memdiver.api.config import Settings
from memdiver.api.dependencies import (
    get_api_settings,
    get_tool_session,
    upload_dir_or_409,
)
from memdiver.api.path_safety import ensure_within, safe_filename
from memdiver.api.storage_quota import prune_dir_to_quota
from memdiver.api.upload_dir import ensure_ready
from memdiver.app.session import ToolSession
from memdiver.core.constants import memdiver_home
from memdiver.mcp_server import tools

logger = logging.getLogger("memdiver.api.routers.dumps")

router = APIRouter()

DUMP_UPLOAD_MAX_BYTES = 4 * 1024 ** 3

#: Subdirectory imported ``.msl`` containers land in, under whichever base
#: :func:`_import_dir` resolves to.
IMPORTS_SUBDIR = "imports"


class ImportTarget(NamedTuple):
    """Where a converted ``.msl`` is written, and who owns that directory.

    ``server_owned`` is the whole point of this record. Two policies — the LRU
    quota prune and the unconditional ``0o700`` chmod — are only ever correct
    for a directory MemDiver itself created and manages (the ``imports/``
    subdirectory). Applied to a directory the caller named, both damage data
    the caller already had there. Deriving that distinction back out of the
    path at the call site would mean re-implementing the precedence rules
    below; :func:`_import_dir` states it instead.
    """

    path: Path
    server_owned: bool


def _ensure_caller_dir(path: Path) -> Path:
    """Create *path* if absent, without re-permissioning one that already exists.

    :func:`~memdiver.api.upload_dir.ensure_ready` chmods **unconditionally**,
    which is right for the directories MemDiver owns (the upload-dir root and
    ``imports/``) and wrong here: a caller-supplied ``output_dir`` may be a
    pre-existing corpus directory whose mode the user chose deliberately, and
    silently narrowing it to ``0o700`` is a side effect no import asked for.
    Nothing is lost by declining: the path is already forced to live inside the
    configured upload directory, which ``ensure_ready`` pinned to ``0o700``
    when it was validated — so its contents stay unreadable to other local
    users either way.

    A directory MemDiver *does* create here is still born ``0o700``: ``mkdir``'s
    mode is masked by the process umask, so it is chmod'd once, on creation
    only.
    """
    existed = path.is_dir()
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not existed:
        os.chmod(path, 0o700)
    return path


def _import_dir(output_dir: str, settings: Settings) -> ImportTarget:
    """Resolve the directory a converted ``.msl`` is written to.

    Precedence, most to least specific:

    1. A caller-supplied ``output_dir``, which must stay inside the configured
       upload directory; otherwise the converted ``.msl`` could be written
       anywhere the server process can reach (arbitrary write). This is the one
       branch that needs the containment root, and therefore the one branch
       that can answer 409 when no upload directory has been chosen. It is also
       the one branch MemDiver does **not** own — hence ``server_owned=False``.
    2. ``<upload_dir>/imports`` when an upload directory *is* configured —
       resolved from the injected settings rather than ``upload_dir_or_409``, so
       this branch never 409s.
    3. ``memdiver_home()/imports`` otherwise.

    2 and 3 exist because the converted file is handed back to the client as a
    server-side path and then re-read by every analysis endpoint for the life of
    the session. It previously landed beside the temp upload in the OS temp
    directory — a location the OS purges, and the very location
    ``upload_dir.validate_candidate`` refuses to accept as an upload root.
    """
    if output_dir:
        # upload_dir_or_409() is called HERE, not as a Depends, so the common
        # frontend flow (no output_dir) keeps working on a server where no
        # upload directory has been chosen yet.
        try:
            resolved = ensure_within(upload_dir_or_409(), Path(output_dir))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return ImportTarget(_ensure_caller_dir(resolved), server_owned=False)

    base = settings.upload_dir if settings.upload_dir is not None else memdiver_home()
    try:
        resolved = ensure_within(base, base / IMPORTS_SUBDIR)
    except ValueError as exc:
        # Defensive: a planted symlink at <base>/imports escaping the base would
        # otherwise surface as a 500. Mirrors the pcaps router's handling
        # without disclosing the resolved absolute base path.
        raise HTTPException(
            status_code=400,
            detail="upload directory misconfigured: imports path escapes the base directory",
        ) from exc
    return ImportTarget(ensure_ready(resolved), server_owned=True)


def _import_output_path(out_dir: Path, filename: str | None) -> Path:
    """Pick the ``.msl`` output path for an upload named *filename*.

    Two properties this must guarantee, both of which the previous
    ``tmp_path.stem + ".msl"`` derivation violated:

    * **It can never collide with the temp upload.** ``NamedTemporaryFile``
      takes its suffix from the uploaded name, so a file called
      ``memslicer.msl`` produced ``/tmp/tmpXXXX.msl`` as the *input* and the
      identical path as the output — and the ``finally`` that cleans up the
      input then deleted the converted result.
    * **It is unique.** Two uploads of ``a.dump`` used to resolve to the same
      output and silently clobbered each other.

    The stem comes from the uploaded name so the UI can label the pane
    ``memslicer-1a2b3c4d.msl`` instead of ``tmpvqb05sie.msl``. ``filename`` is
    client-controlled, so it is sanitised here *and* funnelled through
    :func:`~memdiver.api.path_safety.safe_filename`, which rejects anything that
    is not a direct child of *out_dir*.
    """
    raw_stem = Path(Path(filename or "upload").name).stem
    safe_stem = re.sub(r"[^A-Za-z0-9._-]", "_", raw_stem)[:64].lstrip(".") or "upload"
    try:
        return safe_filename(out_dir, f"{safe_stem}-{uuid4().hex[:8]}", ".msl")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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
    ``tools.import_dump`` (which sniffs raw/.dump, ELF core, minidump or an
    already-MSL container and dispatches accordingly), then the temp file is
    cleaned up. The converted ``.msl`` lands in :func:`_import_dir` — a durable
    directory, not the OS temp dir — because the client keeps using its path
    for the rest of the session.
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

    out_path: Path | None = None
    try:
        target = _import_dir(output_dir, settings)
        out_path = _import_output_path(target.path, file.filename)
        result = await asyncio.to_thread(
            tools.import_dump, session, str(tmp_path), str(out_path), pid
        )
    finally:
        # Guard the cleanup against ever deleting the output. The naming in
        # _import_output_path already makes the two disjoint; this is the
        # invariant that actually failed, so it is asserted rather than assumed.
        if out_path is None or tmp_path.resolve() != out_path.resolve():
            tmp_path.unlink(missing_ok=True)

    # Bound the imports dir: evict oldest containers (never this one) once the
    # aggregate exceeds the quota. Best-effort — a prune hiccup must not fail a
    # successful import.
    #
    # ONLY for the directory MemDiver owns. The quota was designed for the
    # server-managed ``imports/`` subdirectory, where every ``.msl`` was put
    # there by an import and evicting the oldest is a cache policy. A
    # caller-supplied ``output_dir`` is the caller's own directory — it may
    # already hold a corpus of ``.msl`` containers that nothing else will ever
    # re-create, and pruning it is silent, permanent data loss. The ``.msl``
    # suffix filter bounds the blast radius but cannot prevent that, because
    # ``.msl`` is exactly what such a corpus is made of.
    if target.server_owned:
        prune_dir_to_quota(
            target.path,
            settings.dump_quota_bytes,
            keep=out_path,
            label="imported dump",
            suffixes=(".msl",),
        )

    # Response shape is deliberately unchanged (source/output/regions_written/
    # key_hints_written/total_bytes). The client already holds the name the user
    # dropped and labels the dump with it, so echoing it here would only widen
    # the contract for nothing.
    return result
