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

from .key_material import key_material_kwargs

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
    from memdiver.engine.candidate_pipeline import reduce_search_space

    try:
        variance = np.load(variance_path)
        reference = Path(reference_path).read_bytes()
    except FileNotFoundError as exc:
        return {"error": f"File not found: {exc.filename or exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Invalid input: {exc}"}
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
    from memdiver.engine.brute_force import run_brute_force

    try:
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
    except FileNotFoundError as exc:
        return {"error": f"File not found: {exc.filename or exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Invalid input: {exc}"}
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
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the N-scaling harness and emit report.{json,md,html}.

    Encrypted ``.msl`` inputs are decrypted when key material is supplied.
    """
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.nsweep import run_nsweep, write_nsweep_artifacts
    from memdiver.engine.oracle import load_oracle, load_oracle_config

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    sources = []
    try:
        for path in source_paths:
            src = open_dump(Path(path), **km)
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
    except FileNotFoundError as exc:
        return {"error": f"File not found: {exc.filename or exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Invalid input: {exc}"}
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
    variance_threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """Emit a Volatility 3 plugin from a hit's neighborhood variance."""
    from memdiver.engine.vol3_emit import emit_plugin_from_hits_file

    try:
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
            variance_threshold=variance_threshold,
        )
    except FileNotFoundError as exc:
        return {"error": f"File not found: {exc.filename or exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Invalid input: {exc}"}
    return {
        "plugin_path": str(output_path),
        "size": output_path.stat().st_size,
        "name": name,
    }


# ----------------------------------------------------------------------
# consensus  (originates the pipeline: writes variance.npy for search_reduce)
# ----------------------------------------------------------------------


def consensus(
    *,
    dump_paths: List[str],
    output_dir: str,
    normalize: bool = False,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a per-byte consensus variance vector across N dumps.

    This is the pipeline's origin stage: it writes ``variance.npy`` (the
    float32 per-byte variance) and ``reference.bin`` (the parallel
    reference bytes, same offset space as the variance) into
    ``output_dir``. The returned ``variance_path`` + ``num_dumps`` feed
    straight into ``search_reduce``, and ``reference_path`` is the
    reference that stage consumes — so an agent driving purely via MCP can
    originate the whole chain (consensus → search_reduce → brute_force →
    emit_plugin) without the web-UI orchestrator.

    Encrypted ``.msl`` inputs are decrypted when key material is supplied.
    """
    from memdiver.engine.consensus_service import build_consensus

    paths = [Path(p) for p in dump_paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        return {"error": f"File not found: {', '.join(missing)}"}
    if len(paths) < 2:
        return {"error": f"Need at least 2 dumps, got {len(paths)}"}

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        cm = build_consensus(paths, normalize=normalize, key_material=km)
    except (OSError, ValueError) as exc:
        return {"error": f"Invalid input: {exc}"}

    if cm.size == 0:
        return {"error": "Consensus produced an empty variance vector "
                         "(empty or mismatched dumps)"}

    out = _ensure_dir(Path(output_dir))
    variance_path = out / "variance.npy"
    np.save(variance_path, np.asarray(cm.variance, dtype=np.float32))
    reference_path = out / "reference.bin"
    reference_path.write_bytes(cm.reference_bytes)

    meta = {
        "num_dumps": cm.num_dumps,
        "size": cm.size,
        "variance_path": str(variance_path),
        "reference_path": str(reference_path),
        "classification_counts": cm.classification_counts(),
        "normalize": normalize,
    }
    _dump_json(meta, out / "consensus.json")
    return meta


# ----------------------------------------------------------------------
# auto-floor  (ground-truth-free variance-floor verdict)
# ----------------------------------------------------------------------


def auto_floor(
    *,
    variance_path: str,
    reference_path: str,
    oracle_path: str,
    output_dir: str,
    num_dumps: int,
    oracle_config_path: Optional[str] = None,
    key_sizes: Sequence[int] = (32,),
    stride: int = 8,
    reduce_kwargs: Optional[Dict[str, Any]] = None,
    coverage: Optional[float] = None,
    correspondence: Optional[float] = None,
    filter_recall: Optional[float] = None,
    min_coverage: float = 0.80,
    positive_control_hex: Optional[str] = None,
    phi0_method: str = "pmin",
    p_min: float = 0.35,
    self_test_trials: int = 8,
    oracle_budget: Optional[int] = None,
    alignment_quality: Optional[float] = None,
    min_alignment: float = 0.5,
    managed_region: bool = False,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Automated oracle-arbitrated variance-floor selection → single verdict.

    Mirrors ``cli._cmd_auto_floor`` but takes paths/params: a ``variance.npy``
    (as produced by ``consensus``), a reference dump/bytes file (opened via
    ``open_dump``, truncated to the variance length), a BYO oracle, and
    ``num_dumps``. Writes ``verdict.json`` + ``report.md`` into ``output_dir``
    and returns the verdict dict.

    Encrypted ``.msl`` references are decrypted when key material is supplied.
    """
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.auto_floor import run_auto_floor, write_auto_floor_artifacts
    from memdiver.engine.oracle import load_oracle, load_oracle_config

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        variance = np.load(variance_path)
        with open_dump(Path(reference_path), **km) as source:
            source.open()
            reference_data = source.read_all()[: len(variance)]
        oracle = load_oracle(
            Path(oracle_path),
            load_oracle_config(Path(oracle_config_path) if oracle_config_path else None),
        )
    except FileNotFoundError as exc:
        return {"error": f"File not found: {exc.filename or exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Invalid input: {exc}"}

    positive_control = bytes.fromhex(positive_control_hex) if positive_control_hex else None
    result = run_auto_floor(
        variance, reference_data, num_dumps, oracle,
        reduce_kwargs=dict(reduce_kwargs or {}), key_sizes=tuple(key_sizes),
        stride=stride, coverage=coverage, correspondence=correspondence,
        filter_recall=filter_recall, min_coverage=min_coverage,
        positive_control=positive_control, phi0_method=phi0_method,
        p_min=p_min, self_test_trials=self_test_trials,
        oracle_budget=oracle_budget, alignment_quality=alignment_quality,
        min_alignment=min_alignment, managed_region=managed_region,
    )
    out = _ensure_dir(Path(output_dir))
    paths = write_auto_floor_artifacts(result, out)
    verdict = result.to_dict()
    verdict["artifacts"] = {k: str(v) for k, v in paths.items()}
    return verdict


# ----------------------------------------------------------------------
# export-pattern  (YARA / JSON / Volatility3 from a consensus auto-region)
# ----------------------------------------------------------------------


def export_pattern(
    *,
    dump_paths: List[str],
    output_dir: Optional[str] = None,
    fmt: str = "volatility3",
    name: str = "memdiver_pattern",
    align: bool = True,
    context: int = 32,
    min_static_ratio: float = 0.3,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Auto-detect a volatile region across N dumps and export a pattern.

    Thin wrapper over ``api.services.analysis_service.auto_export_pattern``,
    covering ``yara`` / ``json`` / ``volatility3`` formats — the same
    pipeline the CLI ``export --auto`` and the HTTP ``/auto-export`` route
    use. When ``output_dir`` is given the rendered pattern is written to a
    file there; the content is always returned inline too.

    Encrypted ``.msl`` inputs are decrypted when key material is supplied.
    """
    from memdiver.api.services.analysis_service import (
        AnalysisServiceError,
        auto_export_pattern,
    )

    paths = [Path(p) for p in dump_paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        return {"error": f"File not found: {', '.join(missing)}"}
    if len(paths) < 2:
        return {"error": f"Need at least 2 dumps, got {len(paths)}"}

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        result = auto_export_pattern(
            paths, fmt=fmt, name=name, align=align, context=context,
            min_static_ratio=min_static_ratio, key_material=km,
        )
    except AnalysisServiceError as exc:
        return {"error": str(exc)}

    payload: Dict[str, Any] = {
        "format": result["format"],
        "content": result["content"],
        "region": result["region"],
    }
    if output_dir:
        ext = {"yara": "yar", "json": "json", "volatility3": "py"}.get(
            result["format"], "txt")
        out = _ensure_dir(Path(output_dir))
        pattern_path = out / f"{name}.{ext}"
        pattern_path.write_text(result["content"])
        payload["pattern_path"] = str(pattern_path)
    return payload
