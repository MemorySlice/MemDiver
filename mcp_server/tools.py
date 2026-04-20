"""Pure tool functions for MemDiver — dataset discovery and analysis.

Each function takes a ToolSession + explicit params and returns a dict.
The MCP server and future web gateway both call these directly.
"""

import logging
from pathlib import Path
from typing import List, Optional

from core.discovery import RunDiscovery
from core.input_schemas import AnalyzeRequest
from core.protocols import REGISTRY
from engine.batch import run_analysis_request
from engine.serializer import serialize_result

from .session import ToolSession

logger = logging.getLogger("memdiver.mcp_server.tools")


def scan_dataset(
    session: ToolSession,
    root: str,
    keylog_filename: str = "keylog.csv",
    protocols: Optional[List[str]] = None,
) -> dict:
    """Scan a dataset directory for available protocols, libraries, and phases."""
    session.set_dataset(root)
    return session.get_or_scan(keylog_filename, protocols)


def list_phases(session: ToolSession, library_dir: str) -> dict:
    """List available lifecycle phases for a library directory."""
    path = Path(library_dir)
    if not path.is_dir():
        return {"error": f"Directory not found: {library_dir}"}

    runs = RunDiscovery.discover_library_runs(path)
    if not runs:
        return {"library_dir": library_dir, "phases": [], "runs": 0}

    phases = sorted({p for run in runs for p in run.available_phases()})
    return {
        "library_dir": library_dir,
        "library": runs[0].library,
        "phases": phases,
        "runs": len(runs),
    }


def list_protocols(session: ToolSession) -> dict:
    """List all registered protocol descriptors."""
    result = []
    for name in REGISTRY.list_protocols():
        desc = REGISTRY.get(name)
        if desc is None:
            continue
        result.append({
            "name": desc.name,
            "versions": desc.versions,
            "secret_types": {v: sorted(types) for v, types in desc.secret_types.items()},
            "dir_prefix": desc.dir_prefix,
        })
    return {"protocols": result}


def analyze_library(
    session: ToolSession,
    library_dirs: List[str],
    phase: str,
    protocol_version: str,
    keylog_filename: str = "keylog.csv",
    template_name: str = "Auto-detect",
    max_runs: int = 10,
    normalize: bool = False,
    expand_keys: bool = True,
    algorithms: Optional[List[str]] = None,
) -> dict:
    """Run the full analysis pipeline on library directories."""
    lib_paths = [Path(d) for d in library_dirs]
    for p in lib_paths:
        if not p.is_dir():
            return {"error": f"Directory not found: {p}"}

    try:
        request = AnalyzeRequest(
            library_dirs=lib_paths,
            phase=phase,
            protocol_version=protocol_version,
            keylog_filename=keylog_filename,
            template_name=template_name,
            max_runs=max_runs,
            normalize=normalize,
            expand_keys=expand_keys,
            algorithms=algorithms,
        )
    except ValueError as exc:
        return {"error": str(exc)}

    result = run_analysis_request(request)
    return serialize_result(result)


def import_raw_dump(
    session: ToolSession,
    raw_path: str,
    output_path: str,
    pid: int = 0,
) -> dict:
    """Import a raw .dump file to .msl format."""
    src = Path(raw_path)
    if not src.is_file():
        return {"error": f"File not found: {raw_path}"}

    from msl.importer import import_raw_dump as _import

    result = _import(src, Path(output_path), pid=pid)
    return {
        "source": str(result.source_path),
        "output": str(result.output_path),
        "regions_written": result.regions_written,
        "key_hints_written": result.key_hints_written,
        "total_bytes": result.total_bytes,
    }
