"""Dataset discovery router — scan, protocols, phases, runs."""

from __future__ import annotations

import logging
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_tool_session
from api.models import ScanRequest
from core.dataset_metadata import DatasetMeta, load_run_meta
from core.models import DumpFile, RunDirectory
from mcp_server import tools
from mcp_server.session import ToolSession

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
    session: ToolSession = Depends(get_tool_session),  # noqa: ARG001
) -> Dict[str, Any]:
    """Enumerate run directories under ``root`` with their dumps + meta.json.

    Designed for the dataset-browsing UI: returns one entry per detected
    run directory (anything that parses as a legacy ``<lib>_run_<ver>_<n>``
    directory OR contains a ``meta.json`` / known dataset dump).
    """
    root_path = Path(root)
    if not root_path.is_dir():
        raise HTTPException(
            status_code=404,
            detail=f"Not a directory: {root}",
        )

    runs: List[Dict[str, Any]] = []
    for candidate in sorted(_iter_run_dirs(root_path)):
        run = _load_run_entry(candidate)
        if run is not None:
            runs.append(run)
    return {"runs": runs}


# -- Helpers ------------------------------------------------------------------


def _iter_run_dirs(root: Path) -> List[Path]:
    """Return every immediate child of ``root`` that is a run directory.

    Also returns ``root`` itself if it already looks like a single run.
    """
    from core.discovery import RunDiscovery

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
    from core.discovery import RunDiscovery

    try:
        run = RunDiscovery.load_run_directory(run_path)
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

    return {
        "path": str(run.path),
        "meta": _meta_to_dict(run.meta),
        "dumps": [_dump_to_dict(d) for d in run.dumps],
    }


def _dump_to_dict(dump: DumpFile) -> Dict[str, Any]:
    """Serialise a :class:`DumpFile` for the API response."""
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
