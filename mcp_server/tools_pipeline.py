"""Pure MCP-tool wrappers for the Phase 25 pipeline stages.

Lets an AI agent drive the individual stages (``search_reduce``,
``brute_force``, ``n_sweep``, ``emit_plugin``) without going through
the web-ui orchestrator. Each wrapper:

* Takes a plain dict of params (JSON-friendly, no numpy / dataclass
  types in or out).
* Calls the engine function directly; does not start a worker pool.
* Writes its output artifact(s) to a caller-supplied ``output_dir``
  so the AI can chain the stages by reference.
* Returns a dict summarizing what it did.

Security: ``brute_force`` and ``n_sweep`` still load arbitrary user
Python via ``engine.oracle.load_oracle``, which runs its own safe-path
+ sha256 audit. Do not expose these tools to untrusted prompts —
they're intended for local operator use.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

logger = logging.getLogger("memdiver.mcp_server.tools_pipeline")


def _ensure_dir(path: Path) -> Path:
    path = Path(path).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _dump_json(payload: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


# ----------------------------------------------------------------------
# search-reduce
# ----------------------------------------------------------------------


def search_reduce(
    *,
    variance_path: str,
    reference_path: str,
    num_dumps: int,
    output_dir: str,
    alignment: int = 8,
    block_size: int = 32,
    density_threshold: float = 0.5,
    min_variance: float = 3000.0,
    entropy_window: int = 32,
    entropy_threshold: float = 4.5,
    min_region: int = 16,
) -> Dict[str, Any]:
    """Reduce consensus variance to a region list via the Phase 25 filter chain."""
    from engine.candidate_pipeline import reduce_search_space

    variance = np.load(variance_path)
    reference = Path(reference_path).read_bytes()
    result = reduce_search_space(
        variance, reference, num_dumps=num_dumps,
        alignment=alignment, block_size=block_size,
        density_threshold=density_threshold,
        min_variance=min_variance,
        entropy_window=entropy_window,
        entropy_threshold=entropy_threshold,
        min_region=min_region,
    )
    out = _ensure_dir(Path(output_dir))
    candidates_path = out / "candidates.json"
    _dump_json(result.to_dict(), candidates_path)
    return {
        "candidates_path": str(candidates_path),
        "num_regions": len(result.regions),
        "stages": result.stages.to_dict(),
        "fallback_entropy_only": result.fallback_entropy_only,
    }


# ----------------------------------------------------------------------
# brute-force
# ----------------------------------------------------------------------


def brute_force(
    *,
    candidates_path: str,
    reference_path: str,
    oracle_path: str,
    output_dir: str,
    oracle_config_path: Optional[str] = None,
    key_sizes: Sequence[int] = (32,),
    stride: int = 8,
    jobs: int = 1,
    exhaustive: bool = True,
    state_path: Optional[str] = None,
    top_k: int = 10,
) -> Dict[str, Any]:
    """Iterate surviving candidates through a BYO oracle and persist hits.json."""
    from engine.brute_force import run_brute_force

    reference = Path(reference_path).read_bytes()
    result = run_brute_force(
        Path(candidates_path),
        reference,
        Path(oracle_path),
        oracle_config_path=Path(oracle_config_path) if oracle_config_path else None,
        key_sizes=tuple(key_sizes),
        stride=stride,
        jobs=jobs,
        exhaustive=exhaustive,
        state_path=Path(state_path) if state_path else None,
        top_k=top_k,
    )
    out = _ensure_dir(Path(output_dir))
    hits_path = out / "hits.json"
    _dump_json(result.to_dict(), hits_path)
    return {
        "hits_path": str(hits_path),
        "verified_count": result.verified_count,
        "total_candidates": result.total_candidates,
        "exit_code": result.exit_code,
        "hits": [h.to_dict() for h in result.hits],
    }


# ----------------------------------------------------------------------
# n-sweep
# ----------------------------------------------------------------------


def n_sweep(
    *,
    source_paths: List[str],
    oracle_path: str,
    output_dir: str,
    n_values: List[int],
    reduce_kwargs: Optional[Dict[str, Any]] = None,
    key_sizes: Sequence[int] = (32,),
    stride: int = 8,
    exhaustive: bool = True,
    oracle_config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the N-scaling harness and emit report.{json,md,html}."""
    from core.dump_source import open_dump
    from engine.nsweep import run_nsweep, write_nsweep_artifacts
    from engine.oracle import load_oracle, load_oracle_config

    sources = []
    try:
        for path in source_paths:
            src = open_dump(Path(path))
            src.open()
            sources.append(src)
        config = load_oracle_config(Path(oracle_config_path) if oracle_config_path else None)
        oracle = load_oracle(Path(oracle_path), config=config)
        result = run_nsweep(
            sources,
            n_values=list(n_values),
            reduce_kwargs=dict(reduce_kwargs or {}),
            oracle=oracle,
            key_sizes=tuple(key_sizes),
            stride=stride,
            exhaustive=exhaustive,
        )
    finally:
        for src in sources:
            try:
                src.close()
            except Exception:  # pragma: no cover
                pass

    out = _ensure_dir(Path(output_dir))
    paths = write_nsweep_artifacts(result, out)
    return {
        "report_json": str(paths["json"]),
        "report_md": str(paths["md"]),
        "report_html": str(paths["html"]),
        "first_hit_n": result.first_hit_n,
        "first_hit_offset": result.first_hit_offset,
        "total_dumps": result.total_dumps,
        "headline": result.headline(),
    }


# ----------------------------------------------------------------------
# emit-plugin
# ----------------------------------------------------------------------


def emit_plugin(
    *,
    hits_path: str,
    reference_path: str,
    name: str,
    output_dir: str,
    description: Optional[str] = None,
    hit_index: int = 0,
    min_static_ratio: float = 0.3,
) -> Dict[str, Any]:
    """Emit a Volatility 3 plugin from a hit's neighborhood variance."""
    from engine.vol3_emit import emit_plugin_from_hits_file

    reference = Path(reference_path).read_bytes()
    out = _ensure_dir(Path(output_dir))
    output_path = out / f"{name}.py"
    emit_plugin_from_hits_file(
        Path(hits_path),
        reference,
        name=name,
        output_path=output_path,
        hit_index=hit_index,
        description=description,
    )
    return {
        "plugin_path": str(output_path),
        "size": output_path.stat().st_size,
        "name": name,
    }
