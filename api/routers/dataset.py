"""Dataset discovery router — scan, protocols, phases, runs."""

from __future__ import annotations

import logging
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from memdiver.api.dependencies import get_tool_session
from memdiver.api.models import ScanRequest
from memdiver.app.session import ToolSession
from memdiver.core.dataset_metadata import DatasetMeta, load_run_meta
from memdiver.core.models import DumpFile, RunDirectory
from memdiver.mcp_server import tools

logger = logging.getLogger("memdiver.api.routers.dataset")

router = APIRouter()


@router.post("/scan")
def scan_dataset(
    request: ScanRequest,
    session: ToolSession = Depends(get_tool_session),
):
    """Scan a dataset directory for protocols, libraries, and phases."""
    return tools.scan_dataset(
        session, request.root, request.keylog_filename, request.protocols,
    )


@router.get("/protocols")
def list_protocols(
    session: ToolSession = Depends(get_tool_session),
):
    """List all registered protocol descriptors."""
    return tools.list_protocols(session)


@router.get("/phases")
def list_phases(
    library_dir: str,
    session: ToolSession = Depends(get_tool_session),
):
    """List available lifecycle phases for a library directory."""
    return tools.list_phases(session, library_dir)


@router.get("/runs")
def list_runs(
    root: str,
    limit: int | None = None,
    offset: int = 0,
    session: ToolSession = Depends(get_tool_session),  # noqa: ARG001
) -> Dict[str, Any]:
    """Enumerate run directories under ``root`` with their dumps + meta.json.

    Designed for the dataset-browsing UI: returns one entry per detected
    run directory (anything that parses as a legacy ``<lib>_run_<ver>_<n>``
    directory OR contains a ``meta.json`` / known dataset dump).

    Candidate directories are enumerated cheaply first; only the requested
    ``offset:offset+limit`` slice is loaded via the expensive per-run parse.
    ``limit=None`` loads every run from ``offset`` onward (backward
    compatible) while still reporting ``total``.
    """
    root_path = Path(root)
    if not root_path.is_dir():
        raise HTTPException(
            status_code=404,
            detail=f"Not a directory: {root}",
        )

    candidates = sorted(_iter_run_dirs(root_path))
    total = len(candidates)

    # Clamp pagination args: never a negative offset; a negative limit means
    # "no rows" rather than an accidental tail slice.
    offset = max(offset, 0)
    if limit is None:
        page = candidates[offset:]
    elif limit <= 0:
        page = []
    else:
        page = candidates[offset:offset + limit]

    runs: List[Dict[str, Any]] = []
    for candidate in page:
        run = _load_run_entry(candidate)
        if run is not None:
            runs.append(run)
    return {"runs": runs, "total": total, "offset": offset, "limit": limit}


# -- Helpers ------------------------------------------------------------------


def _iter_run_dirs(root: Path) -> List[Path]:
    """Return every immediate child of ``root`` that is a run directory.

    Also returns ``root`` itself if it already looks like a single run.
    """
    from memdiver.core.discovery import RunDiscovery

    candidates: List[Path] = []
    if RunDiscovery._looks_like_dataset_run(root) or RunDiscovery.parse_run_dirname(root.name):  # noqa: SLF001
        candidates.append(root)
    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        if RunDiscovery.parse_run_dirname(child.name):
            candidates.append(child)
            continue
        if RunDiscovery._looks_like_dataset_run(child):  # noqa: SLF001
            candidates.append(child)
    return candidates


def _load_run_entry(run_path: Path) -> Dict[str, Any] | None:
    """Shape a single run directory as a JSON-serialisable dict."""
    from memdiver.core.discovery import RunDiscovery

    try:
        # The browsing endpoint never returns secrets, so skip the expensive
        # per-run keylog / MSL key-hint extraction entirely.
        run = RunDiscovery.load_run_directory(run_path, extract_secrets=False)
    except Exception:  # pragma: no cover — defensive
        logger.exception("Failed to load run directory %s", run_path)
        run = None

    if run is None:
        # Surface dataset-style runs even if they lack the legacy naming.
        meta = load_run_meta(run_path)
        if meta is None:
            return None
        run = RunDirectory(
            path=run_path,
            library=run_path.name,
            protocol_version="unknown",
            run_number=0,
            meta=meta,
        )
        # load_run_directory would have probed for us; this hand-built fallback
        # has to, or the run would always report an "absent" capture.
        run.capture_path, run.capture_status = RunDiscovery._find_capture(  # noqa: SLF001
            run_path, meta
        )

    # Prefer dump sizes already recorded in meta.json to avoid re-stat()-ing
    # every dump over a slow filesystem.
    size_by_kind: Dict[str, int] = {}
    if run.meta is not None:
        size_by_kind = {kind: ref.size for kind, ref in run.meta.dumps.items()}

    return {
        "path": str(run.path),
        "meta": _meta_to_dict(run.meta),
        "dumps": [_dump_to_dict(d, size_by_kind) for d in run.dumps],
        "capture": _capture_to_dict(run),
    }


def _capture_to_dict(run: RunDirectory) -> Dict[str, Any]:
    """Serialise the run's packet capture for the API response.

    ``status`` carries the full three-state verdict, so the UI can distinguish
    a run that has no capture ("absent") from one whose capture is there but
    unusable ("unreadable") -- the latter is a corpus defect worth surfacing.
    """
    return {
        "path": str(run.capture_path) if run.capture_path else None,
        "status": run.capture_status,
    }


def _dump_to_dict(dump: DumpFile, size_by_kind: Dict[str, int] | None = None) -> Dict[str, Any]:
    """Serialise a :class:`DumpFile` for the API response.

    Prefers the size declared in ``meta.json`` (via ``size_by_kind``) and only
    falls back to ``stat()`` when meta carries no usable size for this kind.
    """
    meta_size = (size_by_kind or {}).get(dump.kind)
    if meta_size is not None and meta_size > 0:
        size = meta_size
    else:
        try:
            size = dump.path.stat().st_size if dump.path.exists() else 0
        except OSError:
            size = 0
    return {
        "path": str(dump.path),
        "kind": dump.kind,
        "size": size,
        "phase": dump.full_phase,
    }


def _meta_to_dict(meta: DatasetMeta | None) -> Dict[str, Any] | None:
    """Serialise a :class:`DatasetMeta` for JSON; bytes become hex."""
    if meta is None:
        return None
    if not is_dataclass(meta):
        return None
    payload = asdict(meta)
    # bytes -> hex; Path -> str
    payload["master_key"] = meta.master_key_hex
    payload["source_path"] = str(meta.source_path)
    dumps_out: Dict[str, Any] = {}
    for kind, ref in meta.dumps.items():
        dumps_out[kind] = {"path": str(ref.path), "size": ref.size}
    payload["dumps"] = dumps_out
    return payload
