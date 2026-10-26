"""Dumps router — import raw dumps with file upload support."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import NamedTuple, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from memdiver.api.config import Settings
from memdiver.api.dependencies import (
    get_api_settings,
    get_tool_session,
    upload_dir_or_409,
)
from memdiver.api.models import KeyMaterialFields
from memdiver.api.path_safety import ensure_within, safe_filename, write_denial_detail
from memdiver.api.services.key_material import decode_key_material
from memdiver.api.storage_quota import prune_dir_to_quota
from memdiver.api.upload_dir import ensure_ready
from memdiver.app.session import ToolSession
from memdiver.core.constants import memdiver_home
from memdiver.mcp_server import tools
from memdiver.msl.region_select import RegionSelection, parse_selection

logger = logging.getLogger("memdiver.api.routers.dumps")

router = APIRouter()

DUMP_UPLOAD_MAX_BYTES = 4 * 1024 ** 3
#: Cap of the optional ``maps`` sidecar upload (a maps listing is text).
MAPS_UPLOAD_MAX_BYTES = 16 * 1024 ** 2

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
            raise HTTPException(
                status_code=400,
                detail=write_denial_detail(
                    "output_dir", output_dir, [upload_dir_or_409()], "imports",
                    "upload directory"))
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


def _resolve_selection(
    regions: Optional[str], exclude_regions: Optional[str]
) -> Optional[RegionSelection]:
    """Parse the ``regions`` / ``exclude_regions`` spec, answering 422 on bad names.

    Empty strings count as "not given" (an HTML form sends ``""`` for an
    untouched field). ``None`` back means "no selection requested", which
    keeps the import-everything default. The ``ValueError`` message from
    :func:`parse_selection` already lists the valid category names.
    """
    try:
        return parse_selection(regions or None, exclude_regions or None)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


def _require_source_file(path: str) -> Path:
    """Admit a server-side dump path the way ``GET /api/path/info`` does.

    ``/api/path/info`` deliberately applies NO allowed-roots sandbox (see the
    localhost trust model in ``api/main.py``): the operator points MemDiver at
    arbitrary local dumps. This mirrors it — plain ``Path(path)`` existence and
    kind checks — and only turns its ``exists: False`` / ``is_file: False``
    answers into the 404 / 400 an action endpoint needs.
    """
    p = Path(path)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    if not p.is_file():
        raise HTTPException(status_code=400, detail=f"Not a file: {path}")
    return p


def _selection_kwargs(
    selection: Optional[RegionSelection], materialize: bool
) -> dict:
    """Extra ``tools.import_dump`` kwargs, empty when nothing was requested.

    Passing nothing in the default case keeps the original four-argument call
    (and so every existing caller/stub of ``import_dump``) untouched.
    """
    kwargs: dict = {}
    if selection is not None:
        kwargs["selection"] = selection
    if materialize:
        kwargs["materialize"] = True
    return kwargs


def _key_kwargs(
    passphrase: Optional[str],
    key_hex: Optional[str],
    kem_key_hex: Optional[str],
    decrypt_output: bool = False,
) -> dict:
    """Extra ``tools`` kwargs for an encrypted ``.msl``, empty when unused.

    Key material travels only in the POST body / form (never a query string),
    is decoded per request (malformed hex -> 400 via ``CapabilityError``) and is
    never logged or cached. Empty when nothing was supplied, like
    :func:`_selection_kwargs`, so plaintext imports keep the original call.
    """
    kwargs: dict = {}
    km = decode_key_material(passphrase or None, key_hex or None,
                             kem_key_hex or None)
    if km is not None:
        kwargs["key_material"] = km
    if decrypt_output:
        kwargs["decrypt_output"] = True
    return kwargs


async def _run_import(*args, **kwargs) -> dict:
    """``tools.import_dump`` off the event loop; ``ValueError`` -> 400.

    A malformed dump, or an encrypted ``.msl`` materialized without / with the
    wrong key material, raises ``ValueError`` (nothing is written). The message
    names the file and the failure, never the key bytes.
    """
    try:
        return await asyncio.to_thread(tools.import_dump, *args, **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


def _prune_if_server_owned(target: ImportTarget, out_path: Path, settings: Settings) -> None:
    """Bound the imports dir — ONLY for the directory MemDiver owns.

    The quota was designed for the server-managed ``imports/`` subdirectory,
    where every ``.msl`` was put there by an import and evicting the oldest is
    a cache policy. A caller-supplied ``output_dir`` is the caller's own
    directory — it may already hold a corpus of ``.msl`` containers that
    nothing else will ever re-create, and pruning it is silent, permanent data
    loss. The ``.msl`` suffix filter bounds the blast radius but cannot prevent
    that, because ``.msl`` is exactly what such a corpus is made of.
    Best-effort — a prune hiccup must not fail a successful import.
    """
    if target.server_owned:
        prune_dir_to_quota(
            target.path,
            settings.dump_quota_bytes,
            keep=out_path,
            label="imported dump",
            suffixes=(".msl",),
        )


class PreviewRequest(KeyMaterialFields):
    """Body of ``POST /api/dumps/preview``.

    Key-material fields (``passphrase`` / ``key_hex`` / ``kem_key_hex``) open
    an encrypted ``.msl`` so its regions can be listed.
    """

    path: str
    regions: Optional[str] = None
    exclude_regions: Optional[str] = None
    #: /proc/<pid>/maps-style memory map splitting a raw dump into regions
    #: (default: auto-detect a ``.maps`` sidecar next to ``path``).
    maps_path: Optional[str] = None


class ImportPathRequest(KeyMaterialFields):
    """Body of ``POST /api/dumps/import-path``.

    Key-material fields open an encrypted ``.msl`` for ``materialize``; the
    filtered copy is re-encrypted under the same key wrapping unless
    ``decrypt_output`` (explicit opt-in, adds a warning) writes plaintext.
    """

    path: str
    output_dir: str = ""
    pid: int = 0
    regions: Optional[str] = None
    exclude_regions: Optional[str] = None
    materialize: bool = False
    decrypt_output: bool = False
    #: Same as :attr:`PreviewRequest.maps_path`.
    maps_path: Optional[str] = None


def _maps_kwargs(maps_path: Optional[str]) -> dict:
    """``maps_path`` tools kwarg (admitted like a source), empty when unset."""
    if not maps_path:
        return {}
    return {"maps_path": str(_require_source_file(maps_path))}


@router.post("/preview")
def preview_dump(
    body: PreviewRequest,
    session: ToolSession = Depends(get_tool_session),
):
    """Metadata-only preview of the regions importing ``body.path`` would emit.

    Returns ``ImportPreview.to_dict(selection)``: ``format``, ``is_msl``,
    per-region ``regions`` (with ``category``), per-category ``totals``, the
    included/excluded ``summary`` for the requested selection, and ``notes``.
    Also ``platform`` / ``platform_source``, ``runtime_count`` /
    ``runtime_bytes`` (the name-classified ``runtime`` category, not in the
    default selection) and each region's mapping ``name``.
    Reads no region payloads and writes nothing.
    """
    selection = _resolve_selection(body.regions, body.exclude_regions)
    src = _require_source_file(body.path)
    return tools.preview_import(
        session, str(src), selection,
        **_key_kwargs(body.passphrase, body.key_hex, body.kem_key_hex),
        **_maps_kwargs(body.maps_path),
    )


@router.post("/import-path")
async def import_dump_path(
    body: ImportPathRequest,
    session: ToolSession = Depends(get_tool_session),
    settings: Settings = Depends(get_api_settings),
):
    """Convert a dump that already lives on the server (no upload) to ``.msl``.

    Same output-directory rules as ``/upload`` (:func:`_import_dir`) and the
    same source-path admission as ``/preview``. The source is never modified
    or removed — unlike an upload, it is the caller's file, not a temp copy.
    """
    selection = _resolve_selection(body.regions, body.exclude_regions)
    src = _require_source_file(body.path)
    maps_kwargs = _maps_kwargs(body.maps_path)
    target = _import_dir(body.output_dir, settings)
    out_path = _import_output_path(target.path, src.name)
    result = await _run_import(
        session, str(src), str(out_path), body.pid,
        **_selection_kwargs(selection, body.materialize),
        **_key_kwargs(body.passphrase, body.key_hex, body.kem_key_hex,
                      body.decrypt_output),
        **maps_kwargs,
    )
    _prune_if_server_owned(target, out_path, settings)
    return result


async def _spool_upload(upload: UploadFile, suffix: str, cap: int,
                        too_large: str) -> Path:
    """Stream *upload* into a temp file (413 past *cap*); returns its path."""
    size = 0
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            while chunk := await upload.read(1024 * 1024):
                size += len(chunk)
                if size > cap:
                    raise HTTPException(status_code=413, detail=too_large)
                tmp.write(chunk)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
    return tmp_path


@router.post("/upload")
async def upload_dump(
    file: UploadFile = File(...),
    output_dir: str = "",
    pid: int = 0,
    regions: Optional[str] = Form(None),
    exclude_regions: Optional[str] = Form(None),
    materialize: bool = Form(False),
    passphrase: Optional[str] = Form(None),
    key_hex: Optional[str] = Form(None),
    kem_key_hex: Optional[str] = Form(None),
    decrypt_output: bool = Form(False),
    maps: Optional[UploadFile] = File(None),
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

    Optional form fields ``regions`` / ``exclude_regions`` (category specs such
    as ``"heap,stack"``) restrict the import, and ``materialize`` makes an
    ``.msl`` upload a filtered copy instead of the verbatim default. Omitting
    them all imports everything, exactly as before.

    Optional form fields ``passphrase`` / ``key_hex`` / ``kem_key_hex`` (same
    semantics as :class:`KeyMaterialFields`) open an encrypted ``.msl`` upload;
    ``decrypt_output`` makes its materialized copy plaintext.

    Optional second file field ``maps`` (a ``/proc/<pid>/maps``-style listing,
    at most 16 MiB) splits a raw dump upload into real regions. The upload is
    stored under a temp name, so a sidecar is never auto-detected here.
    """
    selection = _resolve_selection(regions, exclude_regions)
    key_kwargs = _key_kwargs(passphrase, key_hex, kem_key_hex, decrypt_output)
    suffix = Path(file.filename or "upload").suffix or ".dump"
    tmp_path = await _spool_upload(file, suffix, DUMP_UPLOAD_MAX_BYTES,
                                   "dump exceeds 4 GiB cap")
    maps_tmp: Path | None = None
    out_path: Path | None = None
    try:
        if maps is not None:
            maps_tmp = await _spool_upload(maps, ".maps", MAPS_UPLOAD_MAX_BYTES,
                                           "maps exceeds 16 MiB cap")
        target = _import_dir(output_dir, settings)
        out_path = _import_output_path(target.path, file.filename)
        result = await _run_import(
            session, str(tmp_path), str(out_path), pid,
            **_selection_kwargs(selection, materialize), **key_kwargs,
            **({"maps_path": str(maps_tmp)} if maps_tmp else {}),
        )
    finally:
        # Guard the cleanup against ever deleting the output. The naming in
        # _import_output_path already makes the two disjoint; this is the
        # invariant that actually failed, so it is asserted rather than assumed.
        if out_path is None or tmp_path.resolve() != out_path.resolve():
            tmp_path.unlink(missing_ok=True)
        if maps_tmp is not None:
            maps_tmp.unlink(missing_ok=True)

    # Bound the imports dir: evict oldest containers (never this one) once the
    # aggregate exceeds the quota — see _prune_if_server_owned for why only the
    # server-owned imports/ directory is ever pruned.
    _prune_if_server_owned(target, out_path, settings)

    # Response shape is deliberately unchanged (source/output/regions_written/
    # key_hints_written/total_bytes) when no selection was requested; with one,
    # tools.import_dump adds the selection summary fields and ``warnings``. The
    # client already holds the name the user dropped and labels the dump with
    # it, so echoing it here would only widen the contract for nothing.
    return result
