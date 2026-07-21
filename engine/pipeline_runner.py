"""Phase 25 end-to-end pipeline orchestrator.

Runs ``consensus → search-reduce → brute-force → n-sweep → emit-plugin``
inside a worker process dispatched by :class:`api.services.task_manager.TaskManager`.
The entry point :func:`run_pipeline` is deliberately top-level so it
pickles cleanly under ``mp_context="spawn"`` (closures, lambdas, and
instance methods do not).

Contract:

* ``params`` is a JSON-friendly dict built from the Pydantic
  ``PipelineRunRequest`` in ``api/routers/pipeline.py``. The router is
  the only authoritative place parameters are validated.
* ``ctx`` is the :class:`api.services.task_manager.WorkerContext`
  passed in by ``_worker_entry``; it exposes ``emit`` (put a dict on
  the progress mp.Queue) and ``is_cancelled`` (read the Manager
  cancel Event).
* Every stage is wrapped in ``stage_start`` / ``stage_end`` emits so
  the TaskManager can maintain per-stage records. Engine functions
  themselves emit fine-grained progress via the ``progress_callback``
  bridge installed here.

Artifacts written per stage (relative to ``artifact_dir``):

    consensus/variance.npy
    consensus/reference.bin
    search_reduce/candidates.json
    brute_force/hits.json
    nsweep/report.json
    nsweep/report.html
    nsweep/report.md
    emit_plugin/<name>.py

The orchestrator never touches ``task_manager`` or ``progress_bus``
directly — it only emits dicts onto ``ctx.progress_queue`` and relies
on the drain task in the parent process to translate them into bus
events. This keeps the worker stdlib-only beyond engine/.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from memdiver.engine.auto_floor import AutoFloorResult

logger = logging.getLogger("memdiver.engine.pipeline_runner")

# Default oracle probe config for Shape-2 oracles at pipeline time.
_EMPTY_CONFIG: Dict[str, Any] = {}


class _CancelledByContext(Exception):
    """Raised internally when ctx.is_cancelled() flips mid-stage."""


def _bridge(ctx, stage_prefix: str) -> Callable:
    """Return a ``progress_callback`` forwarding engine events to ctx.emit.

    Adapts the :class:`engine.progress.ProgressEvent` signature to the
    TaskManager worker-side JSON contract (plain dicts on an mp.Queue).
    The ``event.extra`` dict is passed by reference — it gets pickled
    across the queue boundary, so the child never mutates the original.
    """
    def _fn(event) -> None:
        stage = event.stage
        if ":" not in stage:
            stage = f"{stage_prefix}:{stage}"
        ctx.emit(
            "progress",
            stage=stage,
            pct=event.pct if event.pct >= 0 else None,
            msg=event.msg,
            extra=event.extra or None,
        )
    return _fn


def _register_artifact(
    artifacts: List[Dict[str, Any]],
    artifact_dir: Path,
    *,
    name: str,
    relpath: str,
    media_type: str = "application/octet-stream",
) -> Dict[str, Any]:
    """Compute size + sha256 of a written artifact and append a record."""
    full = artifact_dir / relpath
    try:
        size = full.stat().st_size
    except OSError:
        size = 0
    sha = hashlib.sha256(full.read_bytes()).hexdigest() if full.is_file() else None
    spec = {
        "name": name,
        "relpath": relpath,
        "media_type": media_type,
        "size": size,
        "sha256": sha,
    }
    artifacts.append(spec)
    return spec


def _load_sources(source_paths: List[str]):
    """Open each dump path via the DumpSource factory and context-manage them."""
    from memdiver.core.dump_source import open_dump

    opened = []
    for path in source_paths:
        src = open_dump(Path(path))
        src.open()
        opened.append(src)
    return opened


def _close_sources(sources: List) -> None:
    for src in sources:
        try:
            src.close()
        except Exception:  # pragma: no cover
            pass


def _is_msl(source) -> bool:
    return getattr(source, "format_name", "") == "msl"


def _persist_welford_state(
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
    *,
    mean_arr,
    m2_arr,
    total: int,
    n_welford: int,
) -> Path:
    """Persist the Welford accumulators + a state.json pointer, register it.

    Extracted verbatim from :func:`_build_consensus`; brute-force reads
    these to compute ``neighborhood_variance`` and the refine workflow
    folds more dumps on top of them. Callers must have created the
    ``consensus`` subdirectory first.
    """
    import numpy as np

    mean_path = artifact_dir / "consensus" / "mean.npy"
    m2_path = artifact_dir / "consensus" / "m2.npy"
    state_json_path = artifact_dir / "consensus" / "state.json"
    np.save(mean_path, mean_arr)
    np.save(m2_path, m2_arr)
    state_json_path.write_text(json.dumps({
        "size": int(total),
        "num_dumps": int(n_welford),
        "mean_path": str(mean_path),
        "m2_path": str(m2_path),
    }, indent=2))
    _register_artifact(
        artifacts, artifact_dir,
        name="consensus_state",
        relpath="consensus/state.json",
        media_type="application/json",
    )
    return state_json_path


def _build_consensus(
    sources: List,
    *,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Fold N sources into a variance matrix + reference slab.

    Emits progress per-fold so the UI sees the matrix accumulating.
    """
    from memdiver.engine.consensus_msl import MslIncrementalBuilder, build_msl_consensus
    from memdiver.engine.consensus import ConsensusVector

    import numpy as np

    n = len(sources)
    if n == 0:
        raise ValueError("pipeline: no consensus sources provided")

    ctx.emit("stage_start", stage="consensus", pct=0.0,
             msg=f"folding {n} dumps")

    if all(_is_msl(s) for s in sources):
        # ASLR-aware incremental path for native MSL sources.
        builder = MslIncrementalBuilder.from_sources(sources)
        for i in range(n):
            if ctx.is_cancelled():
                raise _CancelledByContext()
            builder.fold_next(i)
            ctx.emit(
                "progress",
                stage="consensus",
                pct=(i + 1) / n,
                msg=f"folded {i + 1}/{n}",
                extra={"dumps_folded": i + 1, "total_dumps": n},
            )
        variance = builder.get_live_variance()
        reference = builder.get_reference()
        total = builder.total_bytes
        mean_arr, m2_arr, n_welford = builder.welford_state()
    else:
        # Raw .dump path: use the flat ConsensusVector incremental API.
        # Read each source exactly once (read_all() re-reads the whole dump
        # for non-mmap sources), then derive every downstream value from the
        # cached buffers. We probe the minimum size so later dumps don't
        # overflow.
        cached_data = [s.read_all() for s in sources]
        min_size = min(len(buf) for buf in cached_data)
        matrix = ConsensusVector()
        matrix.build_incremental(min_size)
        for i, buf in enumerate(cached_data):
            if ctx.is_cancelled():
                raise _CancelledByContext()
            matrix.add_source(buf[:min_size])
            ctx.emit(
                "progress",
                stage="consensus",
                pct=(i + 1) / n,
                msg=f"folded {i + 1}/{n}",
                extra={"dumps_folded": i + 1, "total_dumps": n},
            )
        # Extract Welford state BEFORE finalize() destroys it.
        mean_arr, m2_arr, n_welford = matrix.welford_state()
        matrix.finalize()
        variance = matrix.variance
        reference = cached_data[0][:min_size]
        total = min_size

    # Persist consensus artifacts.
    (artifact_dir / "consensus").mkdir(parents=True, exist_ok=True)
    variance_path = artifact_dir / "consensus" / "variance.npy"
    ref_path = artifact_dir / "consensus" / "reference.bin"
    np.save(variance_path, variance)
    ref_path.write_bytes(reference)
    _register_artifact(
        artifacts, artifact_dir,
        name="consensus_variance",
        relpath="consensus/variance.npy",
        media_type="application/octet-stream",
    )
    _register_artifact(
        artifacts, artifact_dir,
        name="consensus_reference",
        relpath="consensus/reference.bin",
        media_type="application/octet-stream",
    )
    # Persist Welford accumulators so brute-force can compute
    # neighborhood_variance and the refine workflow can fold more dumps.
    state_json_path = _persist_welford_state(
        artifact_dir, artifacts,
        mean_arr=mean_arr, m2_arr=m2_arr, total=total, n_welford=n_welford,
    )
    ctx.emit(
        "stage_end", stage="consensus", pct=1.0,
        msg=f"variance ready ({total} bytes)",
        extra={"total_bytes": total, "num_dumps": n},
    )
    return {
        "variance_path": str(variance_path),
        "reference_path": str(ref_path),
        "state_path": str(state_json_path),
        "total_bytes": int(total),
        "num_dumps": int(n),
    }


def _run_reduce(
    variance_path: Path,
    reference_path: Path,
    num_dumps: int,
    reduce_kwargs: Dict[str, Any],
    *,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
) -> Path:
    """Run search-reduce and persist the resulting candidates.json."""
    import numpy as np

    from memdiver.engine.candidate_pipeline import reduce_search_space

    variance = np.load(variance_path)
    reference = Path(reference_path).read_bytes()
    ctx.emit("stage_start", stage="search_reduce", pct=0.0,
             msg=f"total_bytes={len(reference)}")
    if ctx.is_cancelled():
        raise _CancelledByContext()
    reduction = reduce_search_space(
        variance, reference, num_dumps=num_dumps,
        progress_callback=_bridge(ctx, "search_reduce"),
        **reduce_kwargs,
    )
    (artifact_dir / "search_reduce").mkdir(parents=True, exist_ok=True)
    candidates_path = artifact_dir / "search_reduce" / "candidates.json"
    candidates_path.write_text(json.dumps(reduction.to_dict(), indent=2))
    _register_artifact(
        artifacts, artifact_dir,
        name="candidates",
        relpath="search_reduce/candidates.json",
        media_type="application/json",
    )
    ctx.emit(
        "stage_end", stage="search_reduce", pct=1.0,
        msg=f"{len(reduction.regions)} regions",
        extra={
            "num_regions": len(reduction.regions),
            "stages": reduction.stages.to_dict(),
            "fallback_entropy_only": reduction.fallback_entropy_only,
        },
    )
    return candidates_path


def _run_brute_force(
    candidates_path: Path,
    reference_path: Path,
    oracle_path: Path,
    bf_kwargs: Dict[str, Any],
    *,
    state_path: Optional[Path] = None,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
) -> Path:
    """Run the BYO oracle against surviving candidates and persist hits.json."""
    from memdiver.engine.brute_force import run_brute_force

    reference = Path(reference_path).read_bytes()
    ctx.emit("stage_start", stage="brute_force", pct=0.0,
             msg=f"oracle={oracle_path.name}")
    result = run_brute_force(
        candidates_path,
        reference,
        oracle_path,
        state_path=state_path,
        progress_callback=_bridge(ctx, "brute_force"),
        **bf_kwargs,
    )
    (artifact_dir / "brute_force").mkdir(parents=True, exist_ok=True)
    hits_path = artifact_dir / "brute_force" / "hits.json"
    hits_path.write_text(json.dumps(result.to_dict(), indent=2))
    _register_artifact(
        artifacts, artifact_dir,
        name="hits",
        relpath="brute_force/hits.json",
        media_type="application/json",
    )
    ctx.emit(
        "stage_end", stage="brute_force", pct=1.0,
        msg=f"{result.verified_count} hits / {result.total_candidates} candidates",
        extra={
            "verified_count": result.verified_count,
            "total_candidates": result.total_candidates,
            "hits": [h.to_dict() for h in result.hits],
        },
    )
    return hits_path


def _run_nsweep(
    sources: List,
    oracle_path: Path,
    nsweep_params: Dict[str, Any],
    *,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Run the N-sweep harness and persist report.{json,md,html}."""
    from memdiver.engine.nsweep import run_nsweep, write_nsweep_artifacts
    from memdiver.engine.oracle import load_oracle

    ctx.emit("stage_start", stage="nsweep", pct=0.0,
             msg=f"N values: {nsweep_params['n_values']}")
    oracle = load_oracle(oracle_path, config=nsweep_params.get("oracle_config", {}))
    result = run_nsweep(
        sources,
        n_values=nsweep_params["n_values"],
        reduce_kwargs=nsweep_params.get("reduce_kwargs", {}),
        oracle=oracle,
        key_sizes=nsweep_params.get("key_sizes", (32,)),
        stride=nsweep_params.get("stride", 8),
        exhaustive=nsweep_params.get("exhaustive", True),
        progress_callback=_bridge(ctx, "nsweep"),
    )
    out_dir = artifact_dir / "nsweep"
    paths = write_nsweep_artifacts(result, out_dir)
    for name, path in paths.items():
        _register_artifact(
            artifacts, artifact_dir,
            name=f"nsweep_{name}",
            relpath=f"nsweep/{Path(path).name}",
            media_type={"json": "application/json",
                        "html": "text/html",
                        "md": "text/markdown"}.get(name, "application/octet-stream"),
        )
    ctx.emit(
        "stage_end", stage="nsweep", pct=1.0,
        msg=result.headline(),
        extra={"first_hit_n": result.first_hit_n,
               "first_hit_offset": result.first_hit_offset,
               "total_dumps": result.total_dumps},
    )
    return result.to_dict()


def _run_emit_plugin(
    hits_path: Path,
    reference_path: Path,
    emit_params: Dict[str, Any],
    *,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
) -> Optional[Path]:
    """Emit a Vol3 plugin from the first hit, or return None if hits empty."""
    from memdiver.engine.vol3_emit import emit_plugin_for_hit

    payload = json.loads(Path(hits_path).read_text())
    hits = payload.get("hits", [])
    if not hits:
        ctx.emit(
            "stage_end", stage="emit_plugin", pct=1.0,
            msg="no hits to emit",
            extra={"skipped": True},
        )
        return None
    hit_index = int(emit_params.get("hit_index", 0))
    hit_index = max(0, min(hit_index, len(hits) - 1))
    name = emit_params.get("name", "memdiver_plugin")
    description = emit_params.get("description")

    ctx.emit("stage_start", stage="emit_plugin", pct=0.0,
             msg=f"plugin={name} hit_index={hit_index}")
    reference = Path(reference_path).read_bytes()
    output_dir = artifact_dir / "emit_plugin"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{name}.py"
    v_thresh = emit_params.get("variance_threshold")
    emit_plugin_for_hit(
        hits[hit_index], reference, name, output_path,
        description=description,
        min_static_ratio=float(emit_params.get("min_static_ratio", 0.3)),
        variance_threshold=float(v_thresh) if v_thresh is not None else None,
        progress_callback=_bridge(ctx, "emit_plugin"),
    )
    _register_artifact(
        artifacts, artifact_dir,
        name="vol3_plugin",
        relpath=f"emit_plugin/{output_path.name}",
        media_type="text/x-python",
    )
    from memdiver.engine.vol3_emit import extract_inferred_fields

    hit = hits[hit_index]
    thresh = float(v_thresh) if v_thresh is not None else None
    fields = extract_inferred_fields(hit, variance_threshold=thresh)
    fields_path = output_dir / f"{name}_fields.json"
    fields_path.write_text(json.dumps(fields, indent=2))
    _register_artifact(
        artifacts, artifact_dir,
        name="inferred_fields",
        relpath=f"emit_plugin/{name}_fields.json",
        media_type="application/json",
    )
    ctx.emit(
        "stage_end", stage="emit_plugin", pct=1.0,
        msg=f"wrote {output_path.name}",
        extra={
            "plugin_path": str(output_path),
            "fields": fields,
            "variance_threshold": thresh,
        },
    )
    return output_path


def run_auto_floor_stage(
    *,
    variance_path: str,
    reference_path: str,
    num_dumps: int,
    oracle_path: str,
    oracle_config: Optional[Dict[str, Any]] = None,
    reduce_kwargs: Optional[Dict[str, Any]] = None,
    key_sizes: Sequence[int] = (32,),
    stride: int = 8,
    coverage: Optional[float] = None,
    correspondence: Optional[float] = None,
    filter_recall: Optional[float] = None,
    min_coverage: float = 0.80,
    phi0_method: str = "pmin",
    p_min: float = 0.35,
    positive_control: Optional[bytes] = None,
    key_material: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[Callable] = None,
) -> "AutoFloorResult":
    """Ground-truth-free variance-floor selection for the pipeline / API.

    Mirrors the CLI ``_cmd_auto_floor`` assembly so the two transports
    cannot drift: it loads the persisted variance array (``.npy`` written
    by the consensus stage), reads the reference dump through a proper
    ``open_dump`` lifecycle (with optional ``key_material`` so an encrypted
    ``.msl`` reference can be decrypted, spec §10), loads the armed BYO
    oracle, then delegates the verdict to
    :func:`engine.auto_floor.run_auto_floor` — the single source of truth
    for the oracle-arbitrated sweep.

    ``reference_data`` is truncated to the variance length so the two arrays
    are index-aligned, exactly as the CLI does.
    """
    import numpy as np

    from memdiver.core.dump_source import open_dump
    from memdiver.engine.auto_floor import run_auto_floor
    from memdiver.engine.oracle import load_oracle

    variance = np.load(variance_path)
    with open_dump(Path(reference_path), **(key_material or {})) as source:
        reference_data = source.read_all()[: len(variance)]

    oracle = load_oracle(Path(oracle_path), config=oracle_config or {})

    extra: Dict[str, Any] = {}
    if progress_callback is not None:
        extra["progress_callback"] = progress_callback

    return run_auto_floor(
        variance,
        reference_data,
        int(num_dumps),
        oracle,
        reduce_kwargs=dict(reduce_kwargs or {}),
        key_sizes=tuple(key_sizes),
        stride=stride,
        coverage=coverage,
        correspondence=correspondence,
        filter_recall=filter_recall,
        min_coverage=min_coverage,
        positive_control=positive_control,
        phi0_method=phi0_method,
        p_min=p_min,
        **extra,
    )


# ---------------------------------------------------------------------------
# Stage abstraction + ordered registry.
#
# Historically :func:`run_pipeline` inlined a hardcoded 5-stage sequence.
# The abstraction below composes that same sequence from a module-level
# ordered registry so a new stage can be registered/inserted without editing
# ``run_pipeline``'s body. It is intentionally thin: each default stage is a
# wrapper delegating to the existing ``_build_consensus`` / ``_run_*``
# functions unchanged, so the default pipeline's ordering, optional gating,
# artifacts, emits and return value are byte-for-byte preserved.
#
# Pickle/spawn note: the registry is a module global rebuilt at import time in
# each worker (spawn re-imports the module). Neither ``Stage`` objects nor the
# wrapper functions are pickled — only ``run_pipeline`` and ``params``/``ctx``
# cross the process boundary — and every wrapper is a top-level function that
# captures no state, so the fragile spawn contract is upheld.
# ---------------------------------------------------------------------------


@dataclass
class PipelineState:
    """Mutable state threaded through the composed pipeline stages.

    Stages read the parsed request fields + upstream results and write their
    own outputs back onto the same instance. This replaces the ad-hoc local
    variables the inline sequence used (``consensus``/``candidates_path``/
    ``hits_path``) without changing what flows between stages.
    """

    ctx: Any
    artifact_dir: Path
    sources: List[Any]
    reduce_kwargs: Dict[str, Any]
    oracle_path: Path
    bf_kwargs: Dict[str, Any]
    nsweep_params: Optional[Dict[str, Any]]
    emit_params: Optional[Dict[str, Any]]
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    # Upstream results shared between stages.
    consensus: Optional[Dict[str, Any]] = None
    candidates_path: Optional[Path] = None
    hits_path: Optional[Path] = None


def _always_enabled(state: "PipelineState") -> bool:
    return True


def _nsweep_enabled(state: "PipelineState") -> bool:
    return state.nsweep_params is not None


def _emit_enabled(state: "PipelineState") -> bool:
    return state.emit_params is not None


@dataclass
class Stage:
    """A named, optionally-gated step in the pipeline.

    ``run(state)`` mutates ``state`` in place (writes artifacts/summary and any
    result other stages consume). ``enabled(state)`` decides whether the stage
    runs at all — this is where the historical optional gating for nsweep/emit
    lives. ``check_cancel_before`` mirrors the pre-refactor placement of the
    ``ctx.is_cancelled()`` guard (consensus checked cancellation only inside
    its fold loop; every later stage was guarded before it ran).
    """

    name: str
    run: Callable[["PipelineState"], None]
    enabled: Callable[["PipelineState"], bool] = _always_enabled
    check_cancel_before: bool = True


def _stage_consensus(state: "PipelineState") -> None:
    state.consensus = _build_consensus(
        state.sources,
        ctx=state.ctx,
        artifact_dir=state.artifact_dir,
        artifacts=state.artifacts,
    )
    state.summary["consensus"] = state.consensus


def _stage_reduce(state: "PipelineState") -> None:
    consensus = state.consensus
    state.candidates_path = _run_reduce(
        Path(consensus["variance_path"]),
        Path(consensus["reference_path"]),
        consensus["num_dumps"],
        state.reduce_kwargs,
        ctx=state.ctx,
        artifact_dir=state.artifact_dir,
        artifacts=state.artifacts,
    )
    state.summary["candidates_path"] = str(state.candidates_path)


def _stage_brute_force(state: "PipelineState") -> None:
    consensus = state.consensus
    state.hits_path = _run_brute_force(
        state.candidates_path,
        Path(consensus["reference_path"]),
        state.oracle_path,
        state.bf_kwargs,
        state_path=Path(consensus["state_path"]),
        ctx=state.ctx,
        artifact_dir=state.artifact_dir,
        artifacts=state.artifacts,
    )
    state.summary["hits_path"] = str(state.hits_path)


def _stage_nsweep(state: "PipelineState") -> None:
    state.summary["nsweep"] = _run_nsweep(
        state.sources,
        state.oracle_path,
        state.nsweep_params,
        ctx=state.ctx,
        artifact_dir=state.artifact_dir,
        artifacts=state.artifacts,
    )


def _stage_emit_plugin(state: "PipelineState") -> None:
    plugin_path = _run_emit_plugin(
        state.hits_path,
        Path(state.consensus["reference_path"]),
        state.emit_params,
        ctx=state.ctx,
        artifact_dir=state.artifact_dir,
        artifacts=state.artifacts,
    )
    state.summary["plugin_path"] = str(plugin_path) if plugin_path else None


def _default_stages() -> List[Stage]:
    """Build a fresh list of the default stages in canonical order."""
    return [
        Stage("consensus", _stage_consensus, check_cancel_before=False),
        Stage("search_reduce", _stage_reduce),
        Stage("brute_force", _stage_brute_force),
        Stage("nsweep", _stage_nsweep, enabled=_nsweep_enabled),
        Stage("emit_plugin", _stage_emit_plugin, enabled=_emit_enabled),
    ]


# Ordered registry the composed pipeline iterates over. Mutated by
# ``register_stage``; snapshotted by ``get_pipeline_stages``.
_STAGE_REGISTRY: List[Stage] = _default_stages()

#: Entry-point group under which out-of-tree packages advertise pipeline stages.
#: Each advertised entry point is a module (imported for its ``register_stage``
#: side effects) or a callable (invoked to self-register). See
#: ``docs/contributing/adding_pipeline_stage.md``.
STAGE_ENTRY_POINT_GROUP = "memdiver.pipeline_stages"

#: Guards one-time out-of-tree discovery so it runs at most once per process.
_ENTRY_POINTS_LOADED = False


def _load_entry_point_stages_once() -> None:
    """Load out-of-tree pipeline stages exactly once, after the defaults.

    Runs at module import so SPAWNED workers (which re-import this module under
    ``mp_context="spawn"``) also pick up out-of-tree stages — closing the known
    spawn-visibility gap where ``register_stage`` calls made only in the parent
    process never reached the workers. Additive, import-safe and
    failure-isolated: a silent no-op when nothing is installed, and a broken
    plugin can never abort import.
    """
    global _ENTRY_POINTS_LOADED  # noqa: PLW0603
    if _ENTRY_POINTS_LOADED:
        return
    _ENTRY_POINTS_LOADED = True
    try:
        from memdiver.core.plugin_discovery import load_entry_point_registrations
        load_entry_point_registrations(STAGE_ENTRY_POINT_GROUP)
    except Exception:  # noqa: BLE001 - discovery must never break module import
        logger.warning(
            "out-of-tree pipeline-stage discovery failed; using built-in "
            "stages only", exc_info=True,
        )


_load_entry_point_stages_once()


def get_pipeline_stages() -> List[Stage]:
    """Return a shallow copy of the registered stages in execution order."""
    return list(_STAGE_REGISTRY)


def register_stage(
    stage: Stage,
    *,
    index: Optional[int] = None,
    before: Optional[str] = None,
    after: Optional[str] = None,
) -> None:
    """Register ``stage`` into the ordered pipeline.

    Position may be given as an explicit ``index``, or relative to an existing
    stage's ``name`` via ``before`` / ``after``. With none supplied the stage
    is appended. At most one of ``index`` / ``before`` / ``after`` may be set.
    """
    supplied = [x for x in (index, before, after) if x is not None]
    if len(supplied) > 1:
        raise ValueError("register_stage: pass at most one of index/before/after")

    # Idempotent replace-by-name: a stage registered twice (double import,
    # plugin setup invoked twice, hot-reload) must NOT end up executing twice.
    # Drop any existing stage with the same name before (re)inserting. Mirrors
    # FormatRegistry.register()'s replace-by-name semantics.
    existing = [s for s in _STAGE_REGISTRY if s.name == stage.name]
    if existing:
        logger.debug("register_stage: replacing existing stage %r", stage.name)
        _STAGE_REGISTRY[:] = [s for s in _STAGE_REGISTRY if s.name != stage.name]

    if before is not None:
        pos = _index_of(before)
    elif after is not None:
        pos = _index_of(after) + 1
    elif index is not None:
        pos = index
    else:
        pos = len(_STAGE_REGISTRY)
    _STAGE_REGISTRY.insert(pos, stage)


def _index_of(name: str) -> int:
    for i, stage in enumerate(_STAGE_REGISTRY):
        if stage.name == name:
            return i
    raise KeyError(f"register_stage: no registered stage named {name!r}")


def _execute_stages(state: "PipelineState", stages: Sequence[Stage]) -> None:
    """Run ``stages`` in order against ``state``, preserving gating + cancel.

    A stage runs only when ``enabled(state)`` is truthy; a stage with
    ``check_cancel_before`` raises :class:`_CancelledByContext` if the context
    was cancelled before it starts. This reproduces the pre-refactor control
    flow exactly.
    """
    for stage in stages:
        if not stage.enabled(state):
            continue
        if stage.check_cancel_before and state.ctx.is_cancelled():
            raise _CancelledByContext()
        stage.run(state)


def run_pipeline(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Top-level worker entry point.

    ``params`` keys:

    * ``artifact_dir`` (str, required): per-task directory the
      TaskManager has already created for us.
    * ``source_paths`` (list[str], required): dump files to fold.
    * ``reduce_kwargs`` (dict): passed straight to
      :func:`engine.candidate_pipeline.reduce_search_space`.
    * ``oracle_path`` (str): absolute path to the armed oracle file.
    * ``brute_force`` (dict): ``key_sizes``, ``stride``, ``jobs``,
      ``exhaustive``, ``top_k``, ``oracle_config_path``.
    * ``nsweep`` (dict, optional): if present, runs the N-sweep harness
      with ``n_values``, ``reduce_kwargs``, ``key_sizes``, ``stride``,
      ``exhaustive``, ``oracle_config``.
    * ``emit`` (dict, optional): ``name``, ``description``, ``hit_index``,
      ``min_static_ratio``.

    Returns a dict with:

        {
          "artifacts": [<ArtifactSpec dicts>],
          "summary": { ... per-stage summary for the UI ... }
        }

    which the TaskManager reads in ``_on_success`` to publish the
    terminal ``done`` event and register artifacts onto the task record.
    """
    # The TaskManager mints a task_id inside submit() and cannot pass
    # the final artifact_dir back to the caller. The router therefore
    # passes ``task_root`` instead, and we derive the per-task dir
    # inside the worker from ``ctx.task_id``. Callers that already
    # know the absolute dir (tests) can still pass ``artifact_dir``.
    if "artifact_dir" in params:
        artifact_dir = Path(params["artifact_dir"]).expanduser()
    else:
        artifact_dir = Path(params["task_root"]).expanduser() / ctx.task_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    source_paths: List[str] = list(params["source_paths"])
    reduce_kwargs: Dict[str, Any] = dict(params.get("reduce_kwargs", {}))
    oracle_path = Path(params["oracle_path"]).expanduser()
    bf_kwargs: Dict[str, Any] = dict(params.get("brute_force", {}))
    # Sanitize brute_force kwargs — run_brute_force does not accept an
    # arbitrary progress_callback from params; the orchestrator supplies
    # the bridge itself.
    bf_kwargs.pop("progress_callback", None)
    bf_kwargs.pop("cancel_event", None)
    bf_kwargs.pop("state_path", None)
    nsweep_params = params.get("nsweep")
    emit_params = params.get("emit")

    sources = _load_sources(source_paths)
    state = PipelineState(
        ctx=ctx,
        artifact_dir=artifact_dir,
        sources=sources,
        reduce_kwargs=reduce_kwargs,
        oracle_path=oracle_path,
        bf_kwargs=bf_kwargs,
        nsweep_params=nsweep_params,
        emit_params=emit_params,
    )
    try:
        # Compose the registered stages (default order below) instead of an
        # inline sequence. Ordering, optional gating and per-stage cancel
        # guards are carried by the Stage objects / _execute_stages:
        #   consensus → search_reduce → brute_force
        #   → [nsweep if params.nsweep] → [emit_plugin if params.emit]
        _execute_stages(state, get_pipeline_stages())
    except _CancelledByContext:
        ctx.emit("error", error="cancelled")
        raise RuntimeError("pipeline cancelled")
    finally:
        _close_sources(sources)

    return {"artifacts": state.artifacts, "summary": state.summary}
