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
from typing import Any, Callable, Dict, List, Optional, Sequence

import numpy as np

from memdiver.core.service_errors import (
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.core.service_result import KeyStatus

from .key_material import key_material_kwargs

logger = logging.getLogger("memdiver.app.tools_pipeline")


def _ensure_dir(path: Path) -> Path:
    path = Path(path).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _raise_if_locked(source: Any) -> None:
    """Raise :class:`EncryptedDumpLockedError` for an encrypted-and-locked source.

    A locked source (``tag_status`` MISSING_KEY / CORRUPTED) reads back empty;
    without this guard the downstream empty/negative handling misattributes the
    lock as a genuine empty result. A decrypted source — including a genuinely
    empty one and any non-encrypted source — passes through untouched, so the
    existing empty-result error path is preserved.
    """
    key = KeyStatus.from_source(source)
    if not key.decrypted:
        raise EncryptedDumpLockedError(key.hint)


def _dump_json(payload: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def _read_reference_bytes(
    reference_path: str,
    key_material: Dict[str, Any],
    on_source: Optional[Callable[[Any], None]] = None,
) -> bytes:
    """Read a reference dump's bytes through the key-aware ``open_dump`` path.

    Unifies the CLI's key-aware read with the pipeline producers' historical
    ``Path(...).read_bytes()``: a plain artifact (``reference.bin`` / ``.npy``)
    opens as a :class:`RawDumpSource` whose ``read_all()`` equals the raw file
    bytes, so unkeyed callers are byte-identical to before; an encrypted
    ``.msl`` supplied with key material is decrypted through the same call, and
    the offsets stay in the space they were derived in (VAS for ``.msl``).

    ``on_source`` — when given — is invoked on the opened source before the
    read, letting a surface report AEAD/tag status (the CLI passes its
    ``_warn_tag_status``) without the producer importing any presentation code.
    """
    from memdiver.core.dump_source import open_dump

    with open_dump(Path(reference_path), **key_material) as source:
        source.open()
        if on_source is not None:
            on_source(source)
        return source.read_all()


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
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """Reduce consensus variance to a region list via the Phase 25 filter chain.

    Encrypted ``.msl`` references are decrypted when key material is supplied;
    a plain ``reference.bin`` opens raw (byte-identical to the previous
    ``read_bytes`` path).
    """
    from memdiver.engine import floor_policy
    from memdiver.engine.candidate_pipeline import reduce_search_space

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        variance = np.load(variance_path)
        reference = _read_reference_bytes(reference_path, km, on_source)
    except FileNotFoundError as exc:
        raise FileNotFoundServiceError(f"File not found: {exc.filename or exc}") from exc
    except (OSError, ValueError) as exc:
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc
    result = reduce_search_space(
        variance, reference, num_dumps=num_dumps,
        alignment=alignment, block_size=block_size,
        density_threshold=density_threshold,
        min_variance=min_variance,
        entropy_window=entropy_window,
        entropy_threshold=entropy_threshold,
        min_region=min_region,
    )
    # Advisory only: a data-driven floor to consider for min_variance
    # (0.0 = too few dumps / no crypto component; keep everything).
    recommended = floor_policy.recommended_floor(variance, num_dumps)
    out = _ensure_dir(Path(output_dir))
    candidates_path = out / "candidates.json"
    payload = result.to_dict()
    payload["recommended_floor"] = recommended
    _dump_json(payload, candidates_path)
    return {
        "candidates_path": str(candidates_path),
        "num_regions": len(result.regions),
        "stages": result.stages.to_dict(),
        "fallback_entropy_only": result.fallback_entropy_only,
        "recommended_floor": recommended,
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
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """Iterate surviving candidates through a BYO oracle and persist hits.json.

    Encrypted ``.msl`` references are decrypted when key material is supplied;
    a plain ``reference.bin`` opens raw (byte-identical to the previous
    ``read_bytes`` path).
    """
    from memdiver.engine.brute_force import run_brute_force

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        reference = _read_reference_bytes(reference_path, km, on_source)
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
        raise FileNotFoundServiceError(f"File not found: {exc.filename or exc}") from exc
    except (OSError, ValueError) as exc:
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc
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
    escalate: bool = False,
    escalate_oracle_budget: Optional[int] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """Run the N-scaling harness and emit report.{json,md,html}.

    Encrypted ``.msl`` inputs are decrypted when key material is supplied.
    When ``escalate`` is set and no checkpoint found a hit, a floor-free
    sweep at the terminal N runs and its verdict surfaces under
    ``escalation``.
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
            if on_source is not None:
                on_source(src)
            _raise_if_locked(src)
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
            escalate=escalate,
            escalate_oracle_budget=escalate_oracle_budget,
        )
    except FileNotFoundError as exc:
        raise FileNotFoundServiceError(f"File not found: {exc.filename or exc}") from exc
    except (OSError, ValueError) as exc:
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc
    finally:
        for src in sources:
            try:
                src.close()
            except Exception:  # pragma: no cover
                pass

    out = _ensure_dir(Path(output_dir))
    paths = write_nsweep_artifacts(result, out)
    payload = {
        "report_json": str(paths["json"]),
        "report_md": str(paths["md"]),
        "report_html": str(paths["html"]),
        "first_hit_n": result.first_hit_n,
        "first_hit_offset": result.first_hit_offset,
        "total_dumps": result.total_dumps,
        "headline": result.headline(),
    }
    if result.escalation is not None:
        payload["escalation"] = result.escalation
    return payload


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
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """Emit a Volatility 3 plugin from a hit's neighborhood variance.

    Encrypted ``.msl`` references are decrypted when key material is supplied;
    a plain ``reference.bin`` opens raw (byte-identical to the previous
    ``read_bytes`` path).
    """
    from memdiver.engine.vol3_emit import emit_plugin_from_hits_file

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        reference = _read_reference_bytes(reference_path, km, on_source)
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
        raise FileNotFoundServiceError(f"File not found: {exc.filename or exc}") from exc
    except (OSError, ValueError) as exc:
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc
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
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")
    if len(paths) < 2:
        raise CapabilityError(
            f"Need at least 2 dumps, got {len(paths)}",
            category=ErrorCategory.PRECONDITION,
        )

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        # The on_source hook runs per opened source before the vector is built,
        # so a locked (missing/wrong-key) dump surfaces as EncryptedDumpLockedError
        # instead of misattributing the resulting empty variance as
        # "empty or mismatched dumps" below.
        cm = build_consensus(
            paths, normalize=normalize, key_material=km, on_source=_raise_if_locked
        )
    except (OSError, ValueError) as exc:
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc

    if cm.size == 0:
        raise CapabilityError(
            "Consensus produced an empty variance vector "
            "(empty or mismatched dumps)",
            category=ErrorCategory.PRECONDITION,
        )

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
    on_source: Optional[Callable[[Any], None]] = None,
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
            if on_source is not None:
                on_source(source)
            _raise_if_locked(source)
            reference_data = source.read_all()[: len(variance)]
        oracle = load_oracle(
            Path(oracle_path),
            load_oracle_config(Path(oracle_config_path) if oracle_config_path else None),
        )
    except FileNotFoundError as exc:
        raise FileNotFoundServiceError(f"File not found: {exc.filename or exc}") from exc
    except (OSError, ValueError) as exc:
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc

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
    # AnalysisServiceError (raised by auto_export_pattern) is already a
    # CapabilityError subclass carrying its own accurate category/status
    # (e.g. DumpsNotFoundError -> NOT_FOUND/404, EmptyRegionError ->
    # INTERNAL/500) -- it is allowed to propagate unmodified so the MCP
    # funnel and any HTTP translator see the real category instead of a
    # blanket INVALID_INPUT.
    from memdiver.api.services.analysis_service import auto_export_pattern

    paths = [Path(p) for p in dump_paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")
    if len(paths) < 2:
        raise CapabilityError(
            f"Need at least 2 dumps, got {len(paths)}",
            category=ErrorCategory.PRECONDITION,
        )

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    result = auto_export_pattern(
        paths, fmt=fmt, name=name, align=align, context=context,
        min_static_ratio=min_static_ratio, key_material=km,
    )

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


# ----------------------------------------------------------------------
# verify-key  (decryption verification of a candidate key at an offset)
# ----------------------------------------------------------------------


def verify_key_result(
    *,
    dump_path: str,
    offset: int,
    length: int,
    ciphertext_hex: str,
    cipher: str = "AES-256-CBC",
    iv_hex: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """Verify a candidate key read at ``offset`` decrypts a known ciphertext.

    The single implementation behind the CLI ``verify`` command, the HTTP
    ``POST /api/analysis/verify-key`` route, and the MCP ``verify`` tool. The
    candidate is read through the DumpSource memory projection (VAS for
    ``.msl``), so a memory-relative offset is interpreted in the space it was
    derived in; encrypted containers are decrypted with ``key_material``.

    Raises :class:`CapabilityError` (or a subclass) for every hard error — a
    missing dump (NOT_FOUND), an unknown cipher / malformed hex / oversized
    range (INVALID_INPUT), or a locked encrypted dump — so each surface maps it
    to its own idiom. Returns a canonical dict each surface reshapes.
    """
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.verification import (
        VERIFICATION_IV,
        VERIFICATION_PLAINTEXT,
        VERIFIER_REGISTRY,
    )

    if not Path(dump_path).is_file():
        raise FileNotFoundServiceError(f"Dump not found: {dump_path}")
    if cipher not in VERIFIER_REGISTRY:
        raise CapabilityError(
            f"Unknown cipher: {cipher}. Available: {list(VERIFIER_REGISTRY)}",
            category=ErrorCategory.INVALID_INPUT,
        )
    verifier = VERIFIER_REGISTRY[cipher]

    km = dict(key_material or {})
    with open_dump(Path(dump_path), **km) as source:
        source.open()
        if on_source is not None:
            on_source(source)
        _raise_if_locked(source)
        candidate = source.read_range(offset, length)

    if len(candidate) < length:
        raise CapabilityError(
            "Offset+length exceeds dump size",
            category=ErrorCategory.INVALID_INPUT,
        )
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        iv = bytes.fromhex(iv_hex) if iv_hex else VERIFICATION_IV
    except ValueError as exc:
        raise CapabilityError(
            f"Invalid hex input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc

    verified = verifier.verify(candidate, ciphertext, iv, VERIFICATION_PLAINTEXT)
    return {
        "verified": verified,
        "offset": offset,
        "length": length,
        "cipher": cipher,
        "key_hex": candidate.hex() if verified else None,
    }


# ----------------------------------------------------------------------
# experiment  (spawn target -> dump N x -> consensus -> verify -> emit)
# ----------------------------------------------------------------------


def _emit(on_progress: Optional[Callable[..., None]], event: str, **fields: Any) -> None:
    """Forward one progress event to the surface's sink, if any.

    ``on_progress`` matches the ``ctx.emit(event, **fields)`` shape the task
    manager already uses, so the API adapter can pass ``ctx.emit`` verbatim; a
    ``None`` sink (the CLI/MCP) is a silent no-op.
    """
    if on_progress is not None:
        on_progress(event, **fields)


def _experiment_check_cancelled(
    is_cancelled: Optional[Callable[[], bool]],
    on_progress: Optional[Callable[..., None]],
) -> None:
    if is_cancelled is not None and is_cancelled():
        _emit(on_progress, "error", error="cancelled")
        raise CapabilityError(
            "experiment cancelled",
            category=ErrorCategory.PRECONDITION,
            code="cancelled",
        )


def _experiment_capture(
    orch: Any,
    target_path: Path,
    num_runs: int,
    output_dir: Path,
    on_progress: Optional[Callable[..., None]],
) -> Any:
    """Run the orchestrator, streaming a bracketing ``capture`` stage."""
    _emit(
        on_progress, "stage_start", stage="capture", pct=0.0,
        msg=f"capturing {num_runs} runs across {len(orch.available_tools)} tools",
    )
    exp = orch.run_experiment(target_path, num_runs, output_dir)
    dump_summary: Dict[str, int] = {}
    for tool_name, tool_dir in exp.tool_dirs.items():
        dumps = sorted(list(Path(tool_dir).glob("*/*.dump"))
                       + list(Path(tool_dir).glob("*/*.msl")))
        dump_summary[tool_name] = len(dumps)
        _emit(
            on_progress, "progress", stage="capture", pct=1.0,
            msg=f"{tool_name}: {len(dumps)} dumps",
            extra={"tool": tool_name, "dumps": len(dumps)},
        )
    _emit(
        on_progress, "stage_end", stage="capture", pct=1.0,
        msg=f"captured {sum(dump_summary.values())} dumps total",
        extra={"dumps_per_tool": dump_summary},
    )
    return exp


def _experiment_consensus_phase(
    tool_dirs: Dict[str, Any],
    key_material: Optional[Dict[str, Any]],
    on_source: Optional[Callable[[Any], None]],
    on_progress: Optional[Callable[..., None]],
) -> Dict[str, Dict[str, Any]]:
    """Fold each tool's dumps into a MEMORY-relative consensus vector.

    Uses :func:`engine.consensus_service.build_consensus` (the ``open_dump``
    projection) — NOT the raw-bytes ``ConsensusVector.build`` the API runner
    used to call — so downstream offsets stay in the projection space (A5).
    """
    from memdiver.engine.consensus_service import build_consensus

    tools = list(tool_dirs.items())
    _emit(on_progress, "stage_start", stage="consensus", pct=0.0,
          msg=f"folding consensus for {len(tools)} tools")
    per_tool: Dict[str, Dict[str, Any]] = {}
    for idx, (tool_name, tool_dir) in enumerate(tools):
        pct = (idx + 1) / max(len(tools), 1)
        dumps = sorted(list(Path(tool_dir).glob("*/*.dump"))
                       + list(Path(tool_dir).glob("*/*.msl")))
        if len(dumps) < 2:
            _emit(on_progress, "progress", stage="consensus", pct=pct,
                  msg=f"{tool_name}: not enough dumps ({len(dumps)}); skipping",
                  extra={"tool": tool_name, "skipped": True})
            continue
        cm = build_consensus(
            dumps, key_material=key_material or {}, on_source=on_source
        )
        aligned = cm.get_aligned_candidates()
        volatile = cm.get_volatile_regions()
        per_tool[tool_name] = {
            "consensus": cm, "dump_paths": dumps,
            "aligned": aligned, "volatile": volatile,
        }
        _emit(on_progress, "progress", stage="consensus", pct=pct,
              msg=f"{tool_name}: {len(aligned)} aligned, {len(volatile)} volatile regions",
              extra={"tool": tool_name, "aligned_regions": len(aligned),
                     "volatile_regions": len(volatile), "num_dumps": len(dumps)})
    _emit(on_progress, "stage_end", stage="consensus", pct=1.0,
          msg=f"consensus ready for {len(per_tool)} tools",
          extra={"tools": list(per_tool.keys())})
    return per_tool


def _experiment_scan_for_key(verify: Callable, aligned: Sequence[Any],
                             reference: bytes, ciphertext: bytes) -> bool:
    """Byte-by-byte AES-CBC scan of the aligned regions for a matching key."""
    from memdiver.engine.verification import (
        HAS_CRYPTO,
        VERIFICATION_IV,
        VERIFICATION_PLAINTEXT,
    )

    if not HAS_CRYPTO:
        return False
    for region in aligned:
        for off in range(region.start, region.end - 31):
            if verify(reference[off:off + 32], ciphertext,
                      VERIFICATION_IV, VERIFICATION_PLAINTEXT):
                return True
    return False


def _experiment_render_plugin(pattern: Any, export_format: str) -> Optional[str]:
    if export_format in ("volatility3", "vol3"):
        from memdiver.architect.volatility3_exporter import Volatility3Exporter
        from memdiver.architect.yara_exporter import YaraExporter
        return Volatility3Exporter.export(
            pattern, yara_rule=YaraExporter.export(pattern))
    if export_format == "yara":
        from memdiver.architect.yara_exporter import YaraExporter
        return YaraExporter.export(pattern)
    return None


def _experiment_emit_plugin(cm: Any, volatile: Sequence[Any], tool_name: str,
                            output_dir: Path, export_format: str) -> Optional[Path]:
    """Emit a plugin from the largest volatile region's MEMORY-relative slab.

    The static mask is derived from the consensus variance (a byte is static
    iff its variance is 0) rather than re-reading raw file bytes — the A5 fix
    the CLI already carried, now shared with the API runner.
    """
    if not volatile:
        return None
    from memdiver.architect.pattern_generator import PatternGenerator

    best = max(volatile, key=lambda r: r.end - r.start)
    ctx_pad = 32
    exp_offset = max(0, best.start - ctx_pad)
    exp_end = min(cm.size, best.end + ctx_pad)
    reference = cm.reference_bytes[exp_offset:exp_end]
    var_slice = cm.variance[exp_offset:exp_end]
    if isinstance(var_slice, np.ndarray):
        static_mask = (var_slice == 0.0).tolist()
    else:
        static_mask = [v == 0.0 for v in var_slice]
    if not reference:
        return None
    pattern = PatternGenerator.generate(
        reference, static_mask, f"{tool_name}_aes256_key")
    if not pattern:
        return None
    plugin_content = _experiment_render_plugin(pattern, export_format)
    if not plugin_content:
        return None
    plugins_dir = Path(output_dir) / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    ext = ".py" if export_format in ("volatility3", "vol3") else ".yar"
    plugin_path = plugins_dir / f"{tool_name}_aes256_key{ext}"
    plugin_path.write_text(plugin_content)
    return plugin_path


def _experiment_verify_phase(
    per_tool: Dict[str, Dict[str, Any]],
    metadata: Dict[str, Any],
    output_dir: Path,
    export_format: str,
    convergence: bool,
    max_fp: int,
    on_progress: Optional[Callable[..., None]],
) -> Dict[str, Dict[str, Any]]:
    """Run decryption verification + plugin emission per tool."""
    from memdiver.engine.verification import (
        AesCbcVerifier,
        VERIFICATION_IV,
        VERIFICATION_PLAINTEXT,
    )

    verifier = AesCbcVerifier()
    verify = verifier.verify
    tools = list(per_tool.items())
    _emit(on_progress, "stage_start", stage="verify", pct=0.0,
          msg=f"verifying {len(tools)} tools")
    first_key = bytes.fromhex(metadata["runs"][0]["key_hex"])
    ciphertext = verifier.create_ciphertext(
        first_key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)

    results: Dict[str, Dict[str, Any]] = {}
    for idx, (tool_name, info) in enumerate(tools):
        cm, dumps = info["consensus"], info["dump_paths"]
        aligned, volatile = info["aligned"], info["volatile"]
        dec_verified = _experiment_scan_for_key(
            verify, aligned, cm.reference_bytes, ciphertext)
        plugin_path = _experiment_emit_plugin(
            cm, volatile, tool_name, output_dir, export_format)
        tool_result: Dict[str, Any] = {
            "tool": tool_name,
            "format": "MSL (.msl)" if tool_name == "memslicer" else "Raw (.dump)",
            "num_dumps": len(dumps),
            "volatile_regions": len(volatile),
            "aligned_regions": len(aligned),
            "decryption_verified": dec_verified,
            "plugin_saved": str(plugin_path) if plugin_path else None,
        }
        if convergence:
            from memdiver.engine.convergence import run_convergence_sweep
            from memdiver.engine.serializer import serialize_convergence_result
            sweep = run_convergence_sweep(dumps, max_fp=max_fp)
            tool_result["convergence"] = serialize_convergence_result(sweep)
        results[tool_name] = tool_result
        _emit(on_progress, "progress", stage="verify",
              pct=(idx + 1) / max(len(tools), 1),
              msg=f"{tool_name}: decryption "
                  f"{'verified' if dec_verified else 'not verified'}",
              extra=tool_result)
    _emit(on_progress, "stage_end", stage="verify", pct=1.0,
          msg=f"verified {len(results)} tools",
          extra={"tool_results": results})
    return results


def experiment_result(
    *,
    target: str,
    output_dir: str,
    num_runs: int = 10,
    tools: Optional[Sequence[str]] = None,
    export_format: str = "volatility3",
    convergence: bool = False,
    max_fp: int = 0,
    key_material: Optional[Dict[str, Any]] = None,
    on_source: Optional[Callable[[Any], None]] = None,
    on_progress: Optional[Callable[..., None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Own the full experiment once: spawn -> dump N x per tool -> consensus ->
    decryption-verify -> emit plugin.

    The single implementation behind the CLI ``experiment`` command, the API
    experiment task runner, and the MCP ``experiment`` tool — replacing the two
    forked copies (the CLI's memory-relative analysis and the API runner's
    raw-bytes analysis). The MEMORY-relative consensus is used uniformly, so
    the API surface inherits the A5 offset fix.

    Progress streams through the optional ``on_progress(event, **fields)`` sink
    (the API passes ``ctx.emit``); ``is_cancelled`` is polled between stages.
    A missing/unusable backend raises ``CapabilityError`` with
    ``code="missing_backend"`` so a surface can degrade gracefully; a missing
    target raises ``FileNotFoundServiceError``.
    """
    try:
        from memdiver.core.dump_driver import DumpOrchestrator
    except ImportError as exc:  # pragma: no cover - environmental
        raise CapabilityError(
            f"experiment backend unavailable: {exc}. "
            "Install with `pip install memdiver[experiment]`.",
            category=ErrorCategory.UNSUPPORTED, code="missing_backend",
        ) from exc

    target_path = Path(target).expanduser()
    if not target_path.is_file():
        _emit(on_progress, "error", error=f"target not found: {target_path}")
        raise FileNotFoundServiceError(f"target not found: {target_path}")

    tools_list = list(tools) if tools else None
    try:
        orch = DumpOrchestrator(tools=tools_list)
    except Exception as exc:  # pragma: no cover - defensive
        raise CapabilityError(
            f"DumpOrchestrator unavailable: {exc}",
            category=ErrorCategory.PRECONDITION, code="missing_backend",
        ) from exc
    if not orch.available_tools:
        raise CapabilityError(
            "no dump tools available on this machine "
            "(install frida-tools / memslicer / lldb to enable capture).",
            category=ErrorCategory.PRECONDITION, code="missing_backend",
        )

    _experiment_check_cancelled(is_cancelled, on_progress)
    exp = _experiment_capture(
        orch, target_path, num_runs, Path(output_dir), on_progress)
    _experiment_check_cancelled(is_cancelled, on_progress)
    per_tool = _experiment_consensus_phase(
        exp.tool_dirs, key_material, on_source, on_progress)
    tool_results = _experiment_verify_phase(
        per_tool, exp.metadata, Path(output_dir),
        export_format, convergence, max_fp, on_progress)
    return {
        "tool_results": tool_results,
        "tools_used": list(per_tool.keys()),
        "target": str(target_path),
        "num_runs": num_runs,
    }
