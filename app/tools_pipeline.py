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
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

import numpy as np

from memdiver.core.service_errors import (
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.core.service_result import Diagnostic, KeyStatus, Severity

from ._progress import (
    _cancel_bridge,
    _emit,
    _experiment_check_cancelled,
    _progress_bridge,
    _raise_cancelled,
)
from .artifact_cache import cache_reference_bytes, mmapped_variance
from .key_material import has_key_material, key_material_kwargs

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
    from memdiver.app.composition import open_dump

    def _load() -> bytes:
        with open_dump(Path(reference_path), **key_material) as source:
            source.open()
            if on_source is not None:
                on_source(source)
            return source.read_all()

    # Cache only plaintext, non-observed reads. Key material carries secrets
    # (must never enter a shared cache); an ``on_source`` hook must observe a
    # real open on every call (a cache hit would skip it). Both bypass to a
    # direct load. With no active reference_cache_scope, cache_reference_bytes
    # is a no-op wrapper over _load, so the CLI/MCP path stays byte-identical.
    if on_source is not None or has_key_material(key_material):
        return _load()
    return cache_reference_bytes(reference_path, _load)


def _is_msl_source(source: Any) -> bool:
    """True for a native MSL source (mirrors ``pipeline_runner._is_msl``)."""
    return getattr(source, "format_name", "") == "msl"


def _select_hit(hits_path: Path, hit_index: int) -> Dict[str, Any]:
    """Load hits.json and pick one hit, reproducing the validation errors
    :func:`engine.vol3_emit.emit_plugin_from_hits_file` raises verbatim.

    Lets the ``emit_plugin`` producer forward a ``progress_callback`` to the
    :func:`emit_plugin_for_hit` leaf (which the file-level wrapper cannot) and
    reuse the selected hit for the inferred-fields artifact, without changing
    the errors an unkeyed caller sees for an empty / out-of-range hits file.
    """
    payload = json.loads(Path(hits_path).read_text())
    hits = payload.get("hits", [])
    if not hits:
        raise ValueError(f"{hits_path}: no hits to emit plugin from")
    if hit_index < 0 or hit_index >= len(hits):
        raise ValueError(
            f"{hits_path}: requested hit {hit_index} but only "
            f"{len(hits)} present"
        )
    return hits[hit_index]


# ----------------------------------------------------------------------
# search-reduce
# ----------------------------------------------------------------------

#: Default cap on the regions ``search_reduce`` returns INLINE. A pathological
#: reduction can produce tens of thousands of runs, and an MCP tool result is a
#: single JSON string an agent has to hold in its context — so the inline list
#: is bounded by default and the caller raises it deliberately. The persisted
#: ``candidates.json`` is never capped.
DEFAULT_MAX_RETURNED_REGIONS = 200


def _bounded_regions(
    regions: List[Dict[str, Any]], max_returned: int
) -> tuple[List[Dict[str, Any]], bool]:
    """Cap an ordered region list to the ``max_returned`` BEST-RANKED rows.

    Selection is by ``rank``, never by list position, so a cap applied to an
    offset-ordered list still keeps the top candidates instead of whatever
    happens to live at the lowest offsets. The rows that survive stay in the
    order they arrived in, so the caller's ``order`` still describes them.

    ``max_returned <= 0`` means uncapped.
    """
    if max_returned <= 0 or len(regions) <= max_returned:
        return list(regions), False
    return [r for r in regions if int(r.get("rank", 0)) <= max_returned], True


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
    max_region: int = 0,
    classes: Optional[Sequence[str]] = None,
    order: str = "offset",
    max_returned: int = DEFAULT_MAX_RETURNED_REGIONS,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    on_source: Optional[Callable[[Any], None]] = None,
    on_progress: Optional[Callable[..., None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Reduce consensus variance to a region list via the Phase 25 filter chain.

    Encrypted ``.msl`` references are decrypted when key material is supplied;
    a plain ``reference.bin`` opens raw (byte-identical to the previous
    ``read_bytes`` path).

    ``classes`` narrows the result to named ByteClass bands ("key_candidate",
    "pointer", "structural", "invariant") IN ADDITION to ``min_variance`` —
    note that the default 3000.0 floor already excludes everything below
    KEY_CANDIDATE, so an all-non-invariant query needs ``min_variance=0.0`` to
    mean what it says. ``max_region`` mirrors ``min_region``.

    ``order`` orders both the persisted ``candidates.json`` and the returned
    ``regions``: "offset" (the default, unchanged from before ranking existed)
    or "rank", best-scoring first. Every row carries ``rank``/``score``/
    ``score_components`` in either order.

    The regions come back INLINE in the returned dict, not only as a path: an
    MCP client has no way to read ``candidates_path`` back, so returning only
    the path made this whole stage unreachable over that surface. The inline
    list is capped at ``max_returned`` rows (0 = uncapped) — always the
    TOP-RANKED rows, presented in ``order``, never a blind head of the list, so
    a cap can't drop the best candidate. ``regions_truncated`` says whether a
    cap bit and ``num_regions`` always reports the true total, so a capped
    result never reads as "that is all there is". ``candidates_path`` still
    holds every region.

    ``on_progress`` / ``is_cancelled`` are the optional surface hooks (the web
    passes ``ctx.emit`` / ``ctx.is_cancelled``); when unset the stage-bracketing
    emits are silent no-ops and the leaf keeps its ``noop_progress`` default, so
    the CLI/MCP result is byte-identical to before. Progress mirrors the web's
    ``search_reduce`` stage (sub-stages ``variance``/``aligned``/``entropy``).
    """
    from memdiver.engine import floor_policy
    from memdiver.engine.candidate_pipeline import (
        reduce_search_space,
        resolve_byte_classes,
    )

    wanted_classes = resolve_byte_classes(classes) if classes else None

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with ExitStack() as _vstack:
        try:
            # enter_context runs np.load(mmap_mode="r"); its FileNotFound /
            # OSError / ValueError stay translated exactly as the old np.load.
            variance = _vstack.enter_context(mmapped_variance(variance_path))
            reference = _read_reference_bytes(reference_path, km, on_source)
        except FileNotFoundError as exc:
            raise FileNotFoundServiceError(f"File not found: {exc.filename or exc}") from exc
        except (OSError, ValueError) as exc:
            raise CapabilityError(
                f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
            ) from exc
        _emit(on_progress, "stage_start", stage="search_reduce", pct=0.0,
              msg=f"total_bytes={len(reference)}")
        _experiment_check_cancelled(is_cancelled, on_progress)
        reduce_extra: Dict[str, Any] = {}
        pcb = _progress_bridge(on_progress, "search_reduce")
        if pcb is not None:
            reduce_extra["progress_callback"] = pcb
        result = reduce_search_space(
            variance, reference, num_dumps=num_dumps,
            alignment=alignment, block_size=block_size,
            density_threshold=density_threshold,
            min_variance=min_variance,
            entropy_window=entropy_window,
            entropy_threshold=entropy_threshold,
            min_region=min_region,
            max_region=max_region,
            classes=wanted_classes,
            order=order,
            **reduce_extra,
        )
        # Advisory only: a data-driven floor to consider for min_variance
        # (0.0 = too few dumps / no crypto component; keep everything).
        # Computed inside the mmap block (it reads ``variance``).
        recommended = floor_policy.recommended_floor(variance, num_dumps)
    out = _ensure_dir(Path(output_dir))
    candidates_path = out / "candidates.json"
    payload = result.to_dict()
    payload["recommended_floor"] = recommended
    _dump_json(payload, candidates_path)
    _emit(on_progress, "stage_end", stage="search_reduce", pct=1.0,
          msg=f"{len(result.regions)} regions",
          extra={"num_regions": len(result.regions),
                 "stages": result.stages.to_dict(),
                 "fallback_entropy_only": result.fallback_entropy_only})
    inline, truncated = _bounded_regions(payload["regions"], max_returned)
    return {
        "candidates_path": str(candidates_path),
        "num_regions": len(result.regions),
        "stages": result.stages.to_dict(),
        "fallback_entropy_only": result.fallback_entropy_only,
        "recommended_floor": recommended,
        "regions": inline,
        "regions_returned": len(inline),
        "regions_truncated": truncated,
        "max_returned": int(max_returned),
        "order": order,
    }


# ----------------------------------------------------------------------
# exploratory candidates — N dumps in, ranked candidates out, no oracle
# ----------------------------------------------------------------------

#: Diagnostic codes :func:`analyze_candidates` can attach to a result. Stable
#: strings, because a surface (or a test) keys off them rather than off the
#: prose, which is free to improve.
CANDIDATES_EMPTY_CODE = "analysis.candidates.empty"
CANDIDATES_UNCLASSIFIED_CODE = "analysis.candidates.unclassified"
CANDIDATES_NOT_PERSISTED_CODE = "analysis.candidates.not_persisted"


def _dominant_byte_class(class_counts: Dict[str, int]) -> str:
    """Name the most volatile ByteClass a region actually contains.

    Mirrors ``ConsensusVector._region_label``: a region is named for the
    HIGHEST band present, never the most numerous one. Real key material is
    class-mixed — the measured 48-byte TLS 1.2 secret is 22 KEY_CANDIDATE + 18
    POINTER + 8 STRUCTURAL — so labelling by plurality would file it under
    ``pointer`` and hide it from every ``byte_class="key_candidate"`` query.

    Returns ``""`` for a region with no counts at all, which happens only in
    the entropy-only fallback where the pipeline declines to classify.
    """
    from memdiver.core.variance import ByteClass

    present = [c for c in ByteClass if class_counts.get(c.name.lower(), 0)]
    return present[-1].name.lower() if present else ""


def _candidate_db_row(region: Dict[str, Any]) -> Dict[str, Any]:
    """Render one ranked region as an ``add_candidate_regions_batch`` row.

    The score components are flattened out of the nested ``score_components``
    dict into the four columns the table names them by, so a reader can sort or
    filter on any one of them in SQL instead of re-parsing JSON.
    """
    components = region.get("score_components", {})
    return {
        "offset": region["offset"],
        "length": region["length"],
        "byte_class": _dominant_byte_class(region.get("class_counts", {})),
        "mean_variance": region.get("mean_variance", 0.0),
        "mean_entropy": region.get("mean_entropy", 0.0),
        "rank": region.get("rank", 0),
        "score": region.get("score", 0.0),
        "score_class_weight": components.get("byte_class", 0.0),
        "score_variance_component": components.get("variance", 0.0),
        "score_entropy_component": components.get("entropy", 0.0),
        "score_length_component": components.get("length", 0.0),
    }


def _empty_result_diagnostic(
    stages: Dict[str, int],
    class_counts: Dict[str, int],
    *,
    min_region: int,
    max_region: int,
) -> Diagnostic:
    """Say WHICH gate emptied the candidate list, reading the funnel top-down.

    An empty list is a legitimate answer — most byte positions in a process are
    invariant across a phase series — but "0 regions" on its own is
    indistinguishable from a broken filter chain, which is the failure mode
    that made the pre-A4 Consensus tab useless. Naming the first stage whose
    survivor count reached zero turns the empty result into an instruction.
    """
    total = stages.get("total_bytes", 0)
    invariant = class_counts.get("invariant", 0)
    if not total:
        reason = ("no bytes were compared — the dumps have no common range "
                  "under this alignment")
    elif not stages.get("variance"):
        reason = (
            f"every one of the {total:,} compared bytes was below the variance "
            f"floor ({invariant:,} of them classify INVARIANT), so nothing "
            f"reached the class gate"
        )
    elif not stages.get("byte_class"):
        reason = "no surviving byte fell in the requested variance classes"
    elif not stages.get("aligned"):
        reason = "the block-density gate rejected every surviving byte"
    elif not stages.get("high_entropy"):
        reason = "no surviving byte cleared the entropy threshold"
    else:
        bound = f" or longer than {max_region}" if max_region else ""
        reason = (
            f"{stages['high_entropy']:,} bytes survived every gate but formed "
            f"no run shorter than {min_region}{bound} bytes"
        )
    return Diagnostic(
        code=CANDIDATES_EMPTY_CODE,
        message=f"No candidate regions: {reason}.",
        severity=Severity.INFO,
        details={"stages": dict(stages), "class_counts": dict(class_counts)},
    )


def _persist_candidate_run(
    *,
    dump_paths: Sequence[str],
    project_id: str,
    alignment: Dict[str, Any],
    class_counts: Dict[str, int],
    regions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Best-effort: file one exploratory comparison into the project DB.

    Returns ``{"consensus_id", "candidates_persisted", "diagnostic"}`` with a
    ``None`` diagnostic when the run was stored. NEVER raises: this is a read
    path an analyst runs to look at a dump set, ``resolve_project_db()``
    returns ``None`` in perfectly valid environments (the DuckDB/Ibis stack is
    optional), and losing an already-computed answer to an unavailable cache
    would be the wrong trade. The same posture — and the same
    open/try/finally-close shape — as :func:`_persist_ground_truth_hits`.

    Regions the reduction left UNCLASSIFIED (the entropy-only fallback at
    N < 3, where ``class_counts`` is empty) are not written: ``byte_class`` is
    a required, validated column, and there is no honest value for a region the
    pipeline has already declined to classify. The caller reports the shortfall
    as its own diagnostic rather than filing a guess.
    """
    from memdiver.app.composition import resolve_project_db

    def _unavailable(reason: str, detail: str) -> Dict[str, Any]:
        return {
            "consensus_id": "",
            "candidates_persisted": 0,
            "diagnostic": Diagnostic(
                code=CANDIDATES_NOT_PERSISTED_CODE,
                message=(
                    f"Results were not saved to the project database: {detail} "
                    f"They are complete in this response."
                ),
                severity=Severity.INFO,
                details={"reason": reason},
            ),
        }

    db = resolve_project_db()
    if db is None:
        return _unavailable(
            "project_db_unavailable",
            "no project database is available (the DuckDB/Ibis extra is "
            "optional).",
        )
    try:
        consensus_id = db.add_consensus_run(
            project_id=project_id,
            dump_paths=list(dump_paths),
            alignment_method=alignment["method"],
            bytes_compared=alignment["bytes_compared"],
            bytes_discarded=alignment["bytes_discarded"],
            sizes_differed=alignment["sizes_differed"],
            alignment_warnings=alignment["warnings"],
            class_counts=class_counts,
        )
        if not consensus_id:
            return _unavailable(
                "project_db_unavailable",
                "the project database declined the write.",
            )
        rows = [_candidate_db_row(r) for r in regions if r.get("class_counts")]
        written = db.add_candidate_regions_batch(consensus_id, rows) if rows else 0
        return {
            "consensus_id": consensus_id,
            "candidates_persisted": written,
            "diagnostic": None,
        }
    except Exception as exc:  # noqa: BLE001 - persistence is advisory here
        logger.warning("candidate persistence failed", exc_info=True)
        return _unavailable("persistence_failed", f"{exc}.")
    finally:
        db.close()


def analyze_candidates(
    *,
    dump_paths: Sequence[str],
    classes: Optional[Sequence[str]] = None,
    min_variance: Optional[float] = None,
    min_region: int = 16,
    max_region: int = 0,
    alignment: int = 8,
    block_size: int = 32,
    density_threshold: float = 0.5,
    entropy_window: int = 32,
    entropy_threshold: float = 4.5,
    order: str = "offset",
    max_returned: int = DEFAULT_MAX_RETURNED_REGIONS,
    normalize: bool = False,
    project_id: str = "",
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """N dumps in, a ranked candidate list out — with no oracle and no pcap.

    THE EXPLORATORY PATH. Every other route to a candidate list either starts
    from a precomputed ``variance.npy`` (:func:`search_reduce`) or refuses to
    run without a way to confirm a hit (``POST /api/pipeline/run``, correctly:
    that flow exists to drive a brute force). An analyst holding N dumps of one
    process who does not know whether there is a key, let alone where, could
    not reach a candidate list at all. This producer is that one call:
    consensus → class / length / entropy / density filters → ranked regions,
    returned INLINE.

    It deliberately takes no oracle and no capture. Nothing here confirms a
    candidate; the ranking says which regions are worth looking at first, and
    ``verify_key_result`` / :func:`brute_force` remain the ways to prove one.

    ``classes`` names ByteClass bands ("invariant", "structural", "pointer",
    "key_candidate"). Prefer ALL THREE non-invariant bands: real key material
    is class-MIXED (measured on a real OpenSSL run, a 48-byte TLS 1.2 master
    secret is 22 KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL), so a
    KEY_CANDIDATE-only query returns fragments from INSIDE the key instead of
    the key. ``min_variance`` is left to resolve against ``classes``
    (:func:`~memdiver.engine.candidate_pipeline.reduce_search_space` — ``None``
    means the historical 3000.0 floor only when no class is named, 0.0 when one
    is), so a class query is never silently re-narrowed by the float floor it
    just widened. Pass a float to override.

    An EMPTY result is not an error. Most byte positions in a process are
    invariant across a phase series, and "0 regions" alone reads exactly like a
    broken filter chain, so an empty list always comes back with a
    ``diagnostics`` entry naming the gate that emptied it.

    Encrypted ``.msl`` inputs are decrypted when key material is supplied —
    either as ``key_file`` / ``passphrase`` / ``kem_key_file`` (the CLI / MCP
    idiom, read from disk here) or as a pre-decoded ``key_material`` dict of
    ``open_dump`` kwargs (the web idiom, already decoded at the HTTP boundary).
    A dump that is encrypted and LOCKED raises rather than reading back as
    zeros, which would otherwise land as "every byte is invariant".

    Persistence is BEST-EFFORT. The comparison and its ranked candidates are
    written to the project DuckDB when one is available, and ``consensus_id``
    identifies the stored run; re-running the same dump set under the same
    alignment CORRECTS that row rather than duplicating it. When no database is
    available the analysis is unaffected and a diagnostic says so — this is a
    read path, not a sweep.

    Returns the regions plus the class histogram, the alignment provenance
    (``alignment``: which of module_offset / virtual_address / file_offset ran,
    what it discarded, and any warning that makes the result questionable), the
    RESOLVED ``thresholds``, the reduction funnel (``stages``), and
    ``warnings`` / ``diagnostics``. ``regions`` is capped at ``max_returned``
    best-ranked rows (0 = uncapped) exactly as :func:`search_reduce` caps its
    own; ``num_regions`` is always the true total.
    """
    from memdiver.engine.candidate_pipeline import (
        ORDERS,
        reduce_search_space,
        resolve_byte_classes,
    )
    from memdiver.engine.consensus_service import build_consensus

    paths = [Path(p).expanduser() for p in dump_paths]
    if len(paths) < 2:
        # PRECONDITION, not INVALID_INPUT, to match the three sibling producers
        # that make the identical check (`consensus`, and the two n-sweep
        # entry points). Both map to HTTP 400 and CLI exit 2, so nothing
        # observable turns on it -- but two spellings of one rule is how a
        # caller learns to catch the wrong category.
        raise CapabilityError(
            f"Need at least 2 dumps to compare, got {len(paths)}",
            category=ErrorCategory.PRECONDITION,
        )
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")
    if order not in ORDERS:
        raise CapabilityError(
            f"order={order!r} is not one of {ORDERS}",
            category=ErrorCategory.INVALID_INPUT,
        )
    try:
        wanted_classes = resolve_byte_classes(classes) if classes else None
    except ValueError as exc:
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc

    def _observe(source: Any) -> None:
        # A locked encrypted dump reads back empty, which would land here as
        # "every byte is invariant" — the single most misleading empty result
        # this producer can return. Surface the lock instead, then let the
        # caller's own hook (the CLI's AEAD line) run.
        _raise_if_locked(source)
        if on_source is not None:
            on_source(source)

    km = _resolve_key_material(key_material, key_file, passphrase, kem_key_file)
    try:
        cm = build_consensus(
            [str(p) for p in paths], normalize=normalize,
            key_material=km, on_source=_observe,
        )
    except (OSError, ValueError) as exc:
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc

    try:
        result = reduce_search_space(
            cm.variance, cm.reference_bytes, num_dumps=cm.num_dumps,
            alignment=alignment, block_size=block_size,
            density_threshold=density_threshold,
            min_variance=min_variance,
            classes=wanted_classes,
            entropy_window=entropy_window,
            entropy_threshold=entropy_threshold,
            min_region=min_region,
            max_region=max_region,
            order=order,
        )
    except ValueError as exc:
        # An unsatisfiable filter combination (the clearest being an
        # entropy_threshold above log2(entropy_window), which no window can
        # ever reach) is a caller-correctable argument, not a server fault —
        # without this it would leave the web surface as an HTTP 500.
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc

    payload = result.to_dict()
    all_regions: List[Dict[str, Any]] = payload["regions"]
    class_counts = cm.classification_counts()
    alignment_report = cm.alignment_report.to_dict()
    stages = result.stages.to_dict()

    diagnostics: List[Diagnostic] = []
    if not all_regions:
        diagnostics.append(_empty_result_diagnostic(
            stages, class_counts, min_region=min_region, max_region=max_region))
    unclassified = sum(1 for r in all_regions if not r.get("class_counts"))
    if unclassified:
        diagnostics.append(Diagnostic(
            code=CANDIDATES_UNCLASSIFIED_CODE,
            message=(
                f"{unclassified} of {len(all_regions)} regions carry no byte "
                f"classes: at N={cm.num_dumps} the cross-dump variance is not "
                f"trustworthy, so the reduction fell back to entropy only and "
                f"declined to classify. They are ranked and returned, but not "
                f"saved, and no class filter can match them. Compare more "
                f"dumps to classify them."
            ),
            severity=Severity.WARNING,
            details={"unclassified_regions": unclassified,
                     "num_dumps": cm.num_dumps},
        ))

    stored = _persist_candidate_run(
        dump_paths=[str(p) for p in paths],
        project_id=project_id,
        alignment=alignment_report,
        class_counts=class_counts,
        regions=all_regions,
    )
    if stored["diagnostic"] is not None:
        diagnostics.append(stored["diagnostic"])

    inline, truncated = _bounded_regions(all_regions, max_returned)
    return {
        "num_dumps": cm.num_dumps,
        "size": cm.size,
        "class_counts": class_counts,
        "alignment": alignment_report,
        "thresholds": payload["thresholds"],
        "stages": stages,
        "fallback_entropy_only": result.fallback_entropy_only,
        "num_regions": len(all_regions),
        "regions": inline,
        "regions_returned": len(inline),
        "regions_truncated": truncated,
        "max_returned": int(max_returned),
        "order": order,
        "consensus_id": stored["consensus_id"],
        "persisted": bool(stored["consensus_id"]),
        "candidates_persisted": stored["candidates_persisted"],
        # The alignment provenance an analyst must see before trusting the
        # numbers, hoisted so a surface renders its banner without reaching
        # into ``alignment``. Empty on an equal-sized phase series — it fires
        # exactly when the result is questionable.
        "warnings": list(alignment_report["warnings"]),
        "diagnostics": [d.to_dict() for d in diagnostics],
    }


# ----------------------------------------------------------------------
# brute-force
# ----------------------------------------------------------------------


def _validate_pcap_caps(
    pcap_max_records: Optional[int], pcap_max_challenges: Optional[int]
) -> None:
    """Reject a pcap parse cap below 1, on every surface.

    Validated at this shared layer so all four surfaces agree with the web
    router's ``ge=1``. Without it the CLI, MCP and library paths accepted 0 and
    negatives, and the consequence was a SILENT FALSE NEGATIVE: a cap of 0
    yields zero decryption challenges, so a genuine key reports "0 confirmed" --
    indistinguishable from the key not being in the dump. A negative cap was
    worse: it reached ``challenges[:-1]`` (dropping a challenge) and surfaced a
    negative ``records_returned`` in the JSON the web UI and any corpus
    aggregate consume. ``None`` means "leave the default alone" and is allowed.

    Shared by :func:`brute_force` (which runs the oracle) and
    :func:`inspect_pcap` (which reports the caps in force), so the arm step can
    never accept a cap the run itself would reject.
    """
    for name, value in (
        ("pcap_max_records", pcap_max_records),
        ("pcap_max_challenges", pcap_max_challenges),
    ):
        if value is not None and int(value) < 1:
            raise CapabilityError(
                f"{name} must be >= 1 (got {value}); omit it to keep "
                f"the default. A cap below 1 verifies nothing, so a real key "
                f"would be reported as unconfirmed.",
                category=ErrorCategory.INVALID_INPUT,
            )


def _corpus_axes_kwargs(dump_path: str) -> Dict[str, Any]:
    """Resolve the corpus axes the analysed dump is an instance of.

    Returns exactly the axis keywords :func:`_persist_ground_truth_hits`
    accepts, so a caller that has a dump path can stamp a whole ledger batch
    with one ``**`` splat and no axis name is ever spelled twice.

    :func:`core.corpus_axes.axes_from_dump_path` returns ``None`` — never
    raises — for any path outside the corpus layout (an ad-hoc dump the operator
    pointed at, a reference slab that is not inside a run directory). That is
    not an error: the row is still written, with the dump path recorded and
    every other axis left at the ledger's own default.

    ``canonical_phase`` is deliberately reported as ``""``. A canonical phase is
    positional across a run's SIBLING dumps (see
    :class:`core.corpus_axes.CorpusAxes`), so it cannot be derived from one path
    at all; inventing one here would make the ledger's identity key mutate as
    soon as an unrelated sibling dump appeared in the same run.
    """
    from memdiver.core.corpus_axes import axes_from_dump_path

    axes = axes_from_dump_path(dump_path)
    if axes is None:
        return {"dump_path": str(dump_path)}
    return {
        "library": axes.library,
        "protocol_version": axes.protocol_version,
        "library_version": axes.library_version,
        "scenario": axes.scenario,
        "run_number": axes.run_number,
        "phase": axes.phase,
        "canonical_phase": "",
        "dump_path": str(axes.dump_path or dump_path),
    }


def _persist_ground_truth_hits(
    hits: list,
    *,
    confirmed_by: str,
    project_name: str,
    library: str = "",
    protocol_version: str = "",
    library_version: str = "unknown",
    scenario: str = "",
    run_number: int = 0,
    phase: str = "",
    canonical_phase: str = "",
    dump_id: str = "",
    dump_path: str = "",
) -> Optional[str]:
    """Best-effort: file confirmed brute-force hits into the ground-truth ledger.

    Bridges the oracle path (confirmed hits, no DB handle) into ProjectDB via the
    composition root. Returns the run_id, or ``None`` when the DB is unavailable
    or persistence fails — it never raises, since the brute-force result is
    already computed and written.

    The corpus axes say what the analysed dump is an instance of; without them
    every ledger row lands with empty ``library`` / ``protocol_version`` /
    ``scenario`` / ``run_number`` / ``phase`` / ``dump_path`` columns and the
    proof ledger cannot be sliced by anything. Build them with
    :func:`_corpus_axes_kwargs`; each keeps a default so a caller with no dump
    path still writes a usable row.
    """
    from memdiver.app.composition import resolve_project_db

    db = resolve_project_db()
    if db is None:
        return None
    try:
        return db.record_ground_truth_run(
            hits,
            confirmed_by=confirmed_by,
            project_name=project_name,
            library=library,
            # ``ground_truth.version`` IS the protocol version; the DB keeps the
            # historical column/parameter name, this layer uses the axis name.
            version=protocol_version,
            library_version=library_version,
            scenario=scenario,
            run_number=run_number,
            phase=phase,
            canonical_phase=canonical_phase,
            dump_id=dump_id,
            dump_path=dump_path,
        ) or None
    except Exception:
        logger.warning("ground-truth persistence failed", exc_info=True)
        return None
    finally:
        db.close()


PARTIAL_COVERAGE_CODE = "brute_force.partial_coverage"


def _window_label(key_sizes: Sequence[int]) -> str:
    """Human phrase for the window widths a run tested ("32-byte", "32/48-byte")."""
    sizes = sorted({int(k) for k in key_sizes})
    if not sizes:
        return "candidate"
    return "/".join(str(k) for k in sizes) + "-byte"


def _smaller_stride_hint(stride: int) -> str:
    """Suggest only strides strictly SMALLER than the current one.

    The remedy for partial coverage is a finer grid, so a hardcoded example is
    wrong as soon as the user picked an unusual stride: at ``stride=3``,
    "try --stride 4" is coarser, not finer. Offer the halved stride (when that
    is still above 1) and always 1, which is full coverage by definition.
    """
    halved = stride // 2
    if halved > 1:
        return f"--stride {halved} or 1"
    return "--stride 1"


def _partial_coverage_diagnostic(
    *,
    candidates_tested: int,
    candidates_possible: int,
    stride: int,
    coverage_fraction: float,
    key_sizes: Sequence[int],
) -> Diagnostic:
    """Explain a zero-hit run that only examined part of the candidate space.

    A stride-``s`` grid tests only offsets that are multiples of ``s``, so a
    secret that is not ``s``-aligned is never handed to the oracle at all. That
    run still ends "succeeded" with zero hits, which is indistinguishable from
    "the key is not in this dump" unless we say so — this diagnostic is that
    difference.
    """
    return Diagnostic(
        code=PARTIAL_COVERAGE_CODE,
        message=(
            f"No candidate was confirmed. The search tested "
            f"{candidates_tested:,} of {candidates_possible:,} possible "
            f"{_window_label(key_sizes)} windows ({coverage_fraction * 100:.1f}%): "
            f"stride={stride} only tests offsets that are multiples of {stride}, "
            f"so a secret that is not {stride}-aligned cannot be found at this "
            f"setting. Re-run with a smaller stride (e.g. "
            f"{_smaller_stride_hint(stride)}) to widen coverage."
        ),
        severity=Severity.WARNING,
        details={
            "candidates_tested": int(candidates_tested),
            "candidates_possible": int(candidates_possible),
            "stride": int(stride),
            "coverage_fraction": float(coverage_fraction),
            "key_sizes": [int(k) for k in key_sizes],
        },
    )


def brute_force(
    *,
    candidates_path: str,
    reference_path: str,
    output_dir: str,
    oracle_path: Optional[str] = None,
    oracle_config_path: Optional[str] = None,
    pcap_path: Optional[str] = None,
    tls_client_random: Optional[str] = None,
    pcap_max_records: Optional[int] = None,
    pcap_max_challenges: Optional[int] = None,
    persist_ground_truth: bool = False,
    key_sizes: Sequence[int] = (32,),
    stride: int = 1,
    jobs: int = 0,
    exhaustive: bool = True,
    state_path: Optional[str] = None,
    top_k: int = 10,
    variance_threshold: Optional[float] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    on_source: Optional[Callable[[Any], None]] = None,
    on_progress: Optional[Callable[..., None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Iterate surviving candidates through an oracle and persist hits.json.

    Two oracle sources are supported, mutually exclusive:
      * ``oracle_path`` — a user-supplied BYO decryption oracle script (sandboxed).
        Hits it confirms are labelled ``confirmed_by="oracle"``.
      * ``pcap_path`` — a pcap/pcapng of the same TLS session; MemDiver's
        first-party pcap oracle proves a recovered key decrypts the real captured
        records (TLS 1.3, TLS 1.2 GCM, and older CBC suites). ``tls_client_random``
        (hex) optionally restricts matching to one session. Requires the ``pcap``
        extra. Hits it confirms are labelled ``confirmed_by="pcap"``.

    ``pcap_max_records`` / ``pcap_max_challenges`` size the pcap oracle's work:
    the first caps how many encrypted application-data records each direction of
    a session contributes, the second caps the total challenges the oracle keeps.
    Both are silent truncations of verification coverage, so both are explicit
    knobs rather than buried defaults; ``None`` (the default) leaves today's
    behaviour exactly as it was — 16 records per direction, no challenge cap.
    Passing the same two caps to ``inspect_pcap`` reports them back plus the
    ``records_truncated`` / ``challenges_truncated`` flags for that capture, so
    the truncation a cap will cause is visible before the sweep runs.

    ``persist_ground_truth`` (opt-in, default off) records the confirmed hits in
    the project database's ``ground_truth`` ledger (labelled ``"pcap"`` or
    ``"oracle"``) — the trusted denominator for later corpus/precision stats. It
    no-ops gracefully when the DuckDB backend is unavailable. Each row is
    stamped with the corpus axes resolved from ``reference_path`` (library,
    protocol version, library version, scenario, run number, raw phase, dump
    path), so the ledger can be sliced by axis; a dump outside the corpus layout
    records its path and leaves the rest at the ledger's defaults.

    Encrypted ``.msl`` references are decrypted when key material is supplied;
    a plain ``reference.bin`` opens raw. ``on_progress`` / ``is_cancelled`` are
    optional surface hooks; unset they are no-ops.
    """
    from memdiver.engine.brute_force import run_brute_force
    from memdiver.engine.progress import Cancelled
    from memdiver.engine.resources.tls_pcap import PcapParseError
    from memdiver.engine.vol3_emit import resolve_variance_threshold

    if bool(oracle_path) == bool(pcap_path):
        raise CapabilityError(
            "Provide exactly one of oracle_path or pcap_path",
            category=ErrorCategory.INVALID_INPUT,
        )

    bf_oracle_kwargs: Dict[str, Any] = {}
    if pcap_path:
        from memdiver.engine.resources.builtin_oracle import BUILTIN_ORACLE_PATH
        resolved_oracle_path = BUILTIN_ORACLE_PATH
        oracle_label = Path(pcap_path).name
        pcap_config: Dict[str, Any] = {"resource_type": "tls-pcap", "pcap": pcap_path}
        if tls_client_random:
            pcap_config["client_random"] = tls_client_random
        # Only forward a cap the caller actually asked for: an absent key leaves
        # the resource/oracle defaults untouched (see builtin_oracle's config).
        _validate_pcap_caps(pcap_max_records, pcap_max_challenges)
        if pcap_max_records is not None:
            pcap_config["max_records_per_direction"] = int(pcap_max_records)
        if pcap_max_challenges is not None:
            pcap_config["max_challenges"] = int(pcap_max_challenges)
        bf_oracle_kwargs["oracle_config"] = pcap_config
        bf_oracle_kwargs["oracle_trusted"] = True
    else:
        resolved_oracle_path = oracle_path
        oracle_label = Path(oracle_path).name
        bf_oracle_kwargs["oracle_config_path"] = (
            Path(oracle_config_path) if oracle_config_path else None
        )

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        reference = _read_reference_bytes(reference_path, km, on_source)
        _emit(on_progress, "stage_start", stage="brute_force", pct=0.0,
              msg=f"oracle={oracle_label}")
        _experiment_check_cancelled(is_cancelled, on_progress)
        bf_extra: Dict[str, Any] = {}
        pcb = _progress_bridge(on_progress, "brute_force")
        if pcb is not None:
            bf_extra["progress_callback"] = pcb
        # Cancellation has to reach INSIDE the sweep. The check above fires only
        # once, before any candidate is tested; at the stride-1 default the grid
        # holds ~700k windows, so without this the brute-force stage ignores a
        # cancel for the entire run and ``check_cancel`` in the engine hot-loop
        # is dead code on the web and MCP surfaces.
        cev = _cancel_bridge(is_cancelled)
        if cev is not None:
            bf_extra["cancel_event"] = cev
        result = run_brute_force(
            Path(candidates_path),
            reference,
            Path(resolved_oracle_path),
            key_sizes=tuple(key_sizes),
            stride=stride,
            jobs=jobs,
            exhaustive=exhaustive,
            state_path=Path(state_path) if state_path else None,
            top_k=top_k,
            **bf_oracle_kwargs,
            **bf_extra,
        )
    except Cancelled:
        # The sweep observed the cancel token mid-grid. Re-express it as the app
        # layer's canonical cancel signal so it is indistinguishable from one
        # caught at a stage boundary — this must NOT fall through to the
        # INVALID_INPUT funnel below and be reported to the user as a bad input.
        _raise_cancelled(on_progress)
        raise  # pragma: no cover - _raise_cancelled always raises
    except FileNotFoundError as exc:
        raise FileNotFoundServiceError(f"File not found: {exc.filename or exc}") from exc
    except (OSError, ValueError, PcapParseError) as exc:
        # PcapParseError (a bare ``Exception`` subclass) can surface eagerly from
        # a pcap oracle's ``ResourceOracle.__init__`` — e.g. a ``tls_client_random``
        # that matches no captured session — so it must be funnelled too.
        raise CapabilityError(
            f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc
    out = _ensure_dir(Path(output_dir))
    hits_path = out / "hits.json"
    result_dict = result.to_dict()
    # Every hit that reaches here was confirmed by *something*: ``run_brute_force``
    # only records a candidate once the oracle returned truthy for it (both the
    # serial and the parallel path append on ``ok``), so a hit can never be an
    # unconfirmed candidate. A pcap hit is a proven decryption of real captured
    # traffic; a BYO-oracle hit is the user's own oracle vouching for it. Stamp
    # both with their provenance — the single ``hit_source`` below is also what
    # the ground-truth ledger records, so the two labels cannot drift.
    hit_source = "pcap" if pcap_path else "oracle"
    for hit in result_dict.get("hits", []):
        hit["verified"] = True
        hit["confirmed_by"] = hit_source
    _dump_json(result_dict, hits_path)
    # Opt-in: file the oracle-confirmed hits into the ground-truth ledger. This
    # is the bridge from the oracle path (which owns confirmed hits but no DB
    # handle) into ProjectDB; it no-ops when DuckDB is absent and never fails the
    # brute-force run (hits.json is already written).
    ground_truth_run_id: Optional[str] = None
    if persist_ground_truth and result_dict.get("hits"):
        ground_truth_run_id = _persist_ground_truth_hits(
            result_dict["hits"],
            confirmed_by=hit_source,
            project_name=Path(reference_path).stem or "oracle-run",
            # ``reference_path`` IS the dump this sweep searched (the CLI spells
            # it ``--dump``), so it is the authoritative axis source; a path
            # outside the corpus layout degrades to defaults, never an error.
            **_corpus_axes_kwargs(reference_path),
        )
    # Resolve the static/dynamic variance cutoff to a concrete value (never
    # ``None``) so the web reducer can seed its convergence preview from the
    # exact threshold the emit stage will use instead of hardcoding the default.
    resolved_vt = resolve_variance_threshold(variance_threshold)
    # Coverage rides EVERY run, hit or miss: a forensics reader needs to know how
    # much of the candidate space was never examined before reading "1 hit" as
    # "exactly one key present". Only the WARNING is conditional on zero hits.
    coverage = {
        "candidates_tested": result.candidates_tested,
        "candidates_possible": result.candidates_possible,
        "stride": result.stride,
        "coverage_fraction": result.coverage_fraction,
    }
    warnings: List[Dict[str, Any]] = []
    if result.verified_count == 0 and result.coverage_fraction < 1.0:
        warnings.append(
            _partial_coverage_diagnostic(
                candidates_tested=result.candidates_tested,
                candidates_possible=result.candidates_possible,
                stride=result.stride,
                coverage_fraction=result.coverage_fraction,
                key_sizes=key_sizes,
            ).to_dict()
        )
    _emit(on_progress, "stage_end", stage="brute_force", pct=1.0,
          msg=f"{result.verified_count} hits / {result.total_candidates} candidates",
          extra={"verified_count": result.verified_count,
                 "total_candidates": result.total_candidates,
                 "variance_threshold": resolved_vt,
                 "hits": result_dict.get("hits", []),
                 **coverage,
                 "warnings": warnings})
    return {
        "hits_path": str(hits_path),
        "verified_count": result.verified_count,
        "total_candidates": result.total_candidates,
        "exit_code": result.exit_code,
        "hits": result_dict.get("hits", []),
        "ground_truth_run_id": ground_truth_run_id,
        **coverage,
        "warnings": warnings,
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
    stride: int = 1,
    exhaustive: bool = True,
    oracle_config_path: Optional[str] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    escalate: bool = False,
    escalate_oracle_budget: Optional[int] = None,
    on_source: Optional[Callable[[Any], None]] = None,
    on_progress: Optional[Callable[..., None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Run the N-scaling harness and emit report.{json,md,html}.

    Encrypted ``.msl`` inputs are decrypted when key material is supplied.
    When ``escalate`` is set and no checkpoint found a hit, a floor-free
    sweep at the terminal N runs and its verdict surfaces under
    ``escalation``.

    ``on_progress`` / ``is_cancelled`` are optional surface hooks; unset they
    are no-ops (byte-identical CLI/MCP behaviour). Progress mirrors the web's
    ``nsweep`` stage.
    """
    from memdiver.app.reports import write_nsweep_artifacts
    from memdiver.app.composition import open_dump
    from memdiver.engine.nsweep import run_nsweep
    from memdiver.engine.oracle import load_oracle, load_oracle_config
    from memdiver.presentation.reports import nsweep_headline

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
        _emit(on_progress, "stage_start", stage="nsweep", pct=0.0,
              msg=f"N values: {n_values}")
        _experiment_check_cancelled(is_cancelled, on_progress)
        ns_extra: Dict[str, Any] = {}
        pcb = _progress_bridge(on_progress, "nsweep")
        if pcb is not None:
            ns_extra["progress_callback"] = pcb
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
            **ns_extra,
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
    headline = nsweep_headline(result)
    paths = write_nsweep_artifacts(result, out, headline=headline)
    _emit(on_progress, "stage_end", stage="nsweep", pct=1.0,
          msg=headline,
          extra={"first_hit_n": result.first_hit_n,
                 "first_hit_offset": result.first_hit_offset,
                 "total_dumps": result.total_dumps})
    payload = {
        "report_json": str(paths["json"]),
        "report_md": str(paths["md"]),
        "report_html": str(paths["html"]),
        "first_hit_n": result.first_hit_n,
        "first_hit_offset": result.first_hit_offset,
        "total_dumps": result.total_dumps,
        "headline": headline,
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
    min_static_ratio: float = 0.3,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    on_source: Optional[Callable[[Any], None]] = None,
    write_fields: bool = False,
    on_progress: Optional[Callable[..., None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Emit a Volatility 3 plugin from a hit's neighborhood variance.

    Encrypted ``.msl`` references are decrypted when key material is supplied;
    a plain ``reference.bin`` opens raw (byte-identical to the previous
    ``read_bytes`` path).

    ``on_progress`` / ``is_cancelled`` are optional surface hooks; unset they
    are no-ops (byte-identical CLI/MCP behaviour). Progress mirrors the web's
    ``emit_plugin`` stage. ``min_static_ratio`` (default 0.3, matching
    :func:`engine.vol3_emit.emit_plugin_for_hit`) is forwarded to the leaf in the
    hooked/``write_fields`` path so the web ``EmitParams.min_static_ratio``
    reaches the generator unchanged. Opt-in ``write_fields`` reproduces the web's
    ``inferred_fields`` artifact: it writes ``<name>_fields.json`` next to the
    plugin (via :func:`engine.vol3_emit.extract_inferred_fields`) and adds the
    ``fields`` list to the return dict and the ``stage_end`` extra — so a later
    web route through this producer keeps the artifact and the ``extra.fields``
    the frontend reads. The generated plugin file is byte-identical whether or
    not the hooks/``write_fields`` are active.
    """
    from memdiver.engine.vol3_emit import (
        emit_plugin_for_hit,
        emit_plugin_from_hits_file,
        extract_inferred_fields,
    )

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    pcb = _progress_bridge(on_progress, "emit_plugin")
    fields: Optional[List[dict]] = None
    try:
        reference = _read_reference_bytes(reference_path, km, on_source)
        out = _ensure_dir(Path(output_dir))
        output_path = out / f"{name}.py"
        _emit(on_progress, "stage_start", stage="emit_plugin", pct=0.0,
              msg=f"plugin={name} hit_index={hit_index}")
        _experiment_check_cancelled(is_cancelled, on_progress)
        if pcb is not None or write_fields:
            # Select the hit ourselves so we can forward the progress_callback
            # to the leaf (the file-level wrapper does not accept one) and reuse
            # the hit for the inferred-fields artifact. The generated plugin is
            # identical to emit_plugin_from_hits_file, which just selects the
            # same hit and delegates to emit_plugin_for_hit.
            hit = _select_hit(Path(hits_path), hit_index)
            emit_extra: Dict[str, Any] = {}
            if pcb is not None:
                emit_extra["progress_callback"] = pcb
            emit_plugin_for_hit(
                hit, reference, name, output_path,
                description=description,
                variance_threshold=variance_threshold,
                min_static_ratio=min_static_ratio,
                **emit_extra,
            )
            if write_fields:
                fields = extract_inferred_fields(
                    hit, variance_threshold=variance_threshold)
                fields_path = out / f"{name}_fields.json"
                fields_path.write_text(json.dumps(fields, indent=2))
        else:
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
    result: Dict[str, Any] = {
        "plugin_path": str(output_path),
        "size": output_path.stat().st_size,
        "name": name,
    }
    if write_fields:
        result["fields_path"] = str(out / f"{name}_fields.json")
        result["fields"] = fields
    _emit(on_progress, "stage_end", stage="emit_plugin", pct=1.0,
          msg=f"wrote {output_path.name}",
          extra={"plugin_path": str(output_path), "fields": fields,
                 "variance_threshold": variance_threshold})
    return result


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
    persist_welford: bool = False,
    on_progress: Optional[Callable[..., None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
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

    Opt-in ``persist_welford`` switches to the web runner's *incremental*
    estimator (:func:`app.pipeline.pipeline_runner._build_consensus`): it folds each
    source one at a time (raw via :class:`ConsensusVector` Welford, native
    ``.msl`` via :class:`MslIncrementalBuilder`), emits a per-fold ``progress``
    event, and additionally persists ``mean.npy`` / ``m2.npy`` / ``state.json``
    (``{size, num_dumps, mean_path, m2_path}``) — the accumulator state
    ``/refine``, ``/neighborhood`` and brute-force ``state_path`` read. The
    default (batch) path is unchanged, so existing CLI/MCP callers are
    byte-identical. ``on_progress`` / ``is_cancelled`` are the surface hooks
    (no-ops when unset).
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
    _emit(on_progress, "stage_start", stage="consensus", pct=0.0,
          msg=f"folding {len(paths)} dumps")
    _experiment_check_cancelled(is_cancelled, on_progress)
    if persist_welford:
        return _consensus_incremental(
            paths, Path(output_dir), km, normalize, on_progress, is_cancelled)
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
    _emit(on_progress, "stage_end", stage="consensus", pct=1.0,
          msg=f"variance ready ({cm.size} bytes)",
          extra={"total_bytes": cm.size, "num_dumps": cm.num_dumps})
    return meta


def _consensus_incremental(
    paths: List[Path],
    output_dir: Path,
    key_material: Dict[str, Any],
    normalize: bool,
    on_progress: Optional[Callable[..., None]],
    is_cancelled: Optional[Callable[[], bool]],
) -> Dict[str, Any]:
    """Incremental fold that mirrors ``pipeline_runner._build_consensus``.

    NOTE: this deliberately duplicates the web runner's fold + Welford-persist
    logic (a clean move of ``_build_consensus`` / ``_persist_welford_state``
    into this module would require editing ``engine/pipeline_runner.py``, which
    is out of scope for this step). The two must stay in lock-step: the raw
    branch is validated against a direct :class:`WelfordVariance` computation in
    the tests, guaranteeing byte-identical ``mean.npy`` / ``m2.npy`` /
    ``state.json``; the ``.msl`` branch uses the identical
    :class:`MslIncrementalBuilder` calls the web runner makes.
    """
    from memdiver.app.composition import open_dump
    from memdiver.engine.consensus import ConsensusVector
    from memdiver.engine.consensus_msl import MslIncrementalBuilder

    n = len(paths)
    sources: List[Any] = []
    try:
        for p in paths:
            src = open_dump(p, **key_material)
            src.open()
            sources.append(src)
            # Surface a locked encrypted source instead of folding empty pages.
            _raise_if_locked(src)

        if all(_is_msl_source(s) for s in sources):
            builder = MslIncrementalBuilder.from_sources(sources)
            for i in range(n):
                _experiment_check_cancelled(is_cancelled, on_progress)
                builder.fold_next(i)
                _emit(on_progress, "progress", stage="consensus",
                      pct=(i + 1) / n, msg=f"folded {i + 1}/{n}",
                      extra={"dumps_folded": i + 1, "total_dumps": n})
            variance = builder.get_live_variance()
            reference = builder.get_reference()
            total = builder.total_bytes
            mean_arr, m2_arr, n_welford = builder.welford_state()
        else:
            # Stream the fold: hand each source to add_source one at a time so
            # only ONE dump is resident at a time (peak ~O(dump size)) instead
            # of materializing all N up front (~O(N * dump size), which OOM'd on
            # large multi-dump runs). add_source reads each dump internally,
            # trims to min_size, folds it, and caches reference_bytes on the
            # first — matching the incremental MSL and n-sweep paths.
            min_size = min(s.size for s in sources)
            matrix = ConsensusVector()
            matrix.build_incremental(min_size)
            for i, s in enumerate(sources):
                _experiment_check_cancelled(is_cancelled, on_progress)
                matrix.add_source(s)
                _emit(on_progress, "progress", stage="consensus",
                      pct=(i + 1) / n, msg=f"folded {i + 1}/{n}",
                      extra={"dumps_folded": i + 1, "total_dumps": n})
            # Extract Welford state BEFORE finalize() destroys it.
            mean_arr, m2_arr, n_welford = matrix.welford_state()
            matrix.finalize()
            variance = matrix.variance
            reference = matrix.reference_bytes
            total = min_size
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

    out = _ensure_dir(output_dir)
    variance_path = out / "variance.npy"
    np.save(variance_path, variance)
    reference_path = out / "reference.bin"
    reference_path.write_bytes(reference)
    mean_path = out / "mean.npy"
    m2_path = out / "m2.npy"
    np.save(mean_path, mean_arr)
    np.save(m2_path, m2_arr)
    state_path = out / "state.json"
    state_path.write_text(json.dumps({
        "size": int(total),
        "num_dumps": int(n_welford),
        "mean_path": str(mean_path),
        "m2_path": str(m2_path),
    }, indent=2))

    _emit(on_progress, "stage_end", stage="consensus", pct=1.0,
          msg=f"variance ready ({total} bytes)",
          extra={"total_bytes": int(total), "num_dumps": n})
    return {
        "num_dumps": int(n_welford),
        "size": int(total),
        "total_bytes": int(total),
        "variance_path": str(variance_path),
        "reference_path": str(reference_path),
        "state_path": str(state_path),
        "mean_path": str(mean_path),
        "m2_path": str(m2_path),
        "normalize": normalize,
    }


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
    stride: int = 1,
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
    on_progress: Optional[Callable[..., None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Automated oracle-arbitrated variance-floor selection → single verdict.

    Mirrors ``cli._cmd_auto_floor`` but takes paths/params: a ``variance.npy``
    (as produced by ``consensus``), a reference dump/bytes file (opened via
    ``open_dump``, truncated to the variance length), a BYO oracle, and
    ``num_dumps``. Writes ``verdict.json`` + ``report.md`` into ``output_dir``
    and returns the verdict dict.

    Encrypted ``.msl`` references are decrypted when key material is supplied.

    ``on_progress`` / ``is_cancelled`` are optional surface hooks; unset they
    are no-ops (byte-identical CLI/MCP behaviour). Progress mirrors the web's
    ``escalate`` stage (the pipeline's floor-free fall-through).
    """
    from memdiver.app.reports import write_auto_floor_artifacts
    from memdiver.app.composition import open_dump
    from memdiver.engine.auto_floor import hit_tier, run_auto_floor
    from memdiver.engine.oracle import load_oracle, load_oracle_config

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with ExitStack() as _vstack:
        try:
            # enter_context runs np.load(mmap_mode="r"); its FileNotFound /
            # OSError / ValueError stay translated exactly as the old np.load.
            variance = _vstack.enter_context(mmapped_variance(variance_path))
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
        _emit(on_progress, "stage_start", stage="escalate", pct=0.0,
              msg="floor-free descending-variance sweep (brute-force found no hit)")
        _experiment_check_cancelled(is_cancelled, on_progress)
        af_extra: Dict[str, Any] = {}
        pcb = _progress_bridge(on_progress, "escalate")
        if pcb is not None:
            af_extra["progress_callback"] = pcb
        # Kept inside the mmap block: run_auto_floor reads ``variance`` (it
        # asarray(float64)-copies it up front, so no view escapes).
        result = run_auto_floor(
            variance, reference_data, num_dumps, oracle,
            reduce_kwargs=dict(reduce_kwargs or {}), key_sizes=tuple(key_sizes),
            stride=stride, coverage=coverage, correspondence=correspondence,
            filter_recall=filter_recall, min_coverage=min_coverage,
            positive_control=positive_control, phi0_method=phi0_method,
            p_min=p_min, self_test_trials=self_test_trials,
            oracle_budget=oracle_budget, alignment_quality=alignment_quality,
            min_alignment=min_alignment, managed_region=managed_region,
            **af_extra,
        )
    out = _ensure_dir(Path(output_dir))
    paths = write_auto_floor_artifacts(result, out)
    verdict = result.to_dict()
    # ``hit_tier`` is additive: it lets a caller reconstruct the canonical
    # ``escalation_verdict`` envelope ({**to_dict, "hit_tier"}) without holding
    # the ``AutoFloorResult`` — the web pipeline's escalate stage relies on this.
    verdict["hit_tier"] = hit_tier(result)
    verdict["artifacts"] = {k: str(v) for k, v in paths.items()}
    _emit(on_progress, "stage_end", stage="escalate", pct=1.0,
          msg=f"{result.verdict} tier={hit_tier(result)}",
          extra={"verdict": result.verdict, "hit_tier": hit_tier(result),
                 "phi_star": result.phi_star, "phi0": result.phi0})
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
    key_material: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Auto-detect a volatile region across N dumps and export a pattern.

    Thin wrapper over :func:`memdiver.app.export_service.auto_export_pattern`,
    covering ``yara`` / ``json`` / ``volatility3`` formats — the same
    pipeline the CLI ``export --auto`` and the HTTP ``/auto-export`` route
    use. When ``output_dir`` is given the rendered pattern is written to a
    file there; the content is always returned inline too.

    Encrypted ``.msl`` inputs are decrypted when key material is supplied —
    either as ``key_file`` / ``passphrase`` / ``kem_key_file`` (the MCP idiom,
    read from disk here) or as a pre-decoded ``key_material`` dict of
    ``open_dump`` kwargs (the web / CLI idiom, already decoded by that surface).
    """
    # AnalysisServiceError (raised by auto_export_pattern) is already a
    # CapabilityError subclass carrying its own accurate category/status
    # (e.g. DumpsNotFoundError -> NOT_FOUND/404, EmptyRegionError ->
    # INTERNAL/500) -- it is allowed to propagate unmodified so the MCP
    # funnel and any HTTP translator see the real category instead of a
    # blanket INVALID_INPUT.
    from memdiver.app.export_service import auto_export_pattern

    paths = [Path(p) for p in dump_paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")
    if len(paths) < 2:
        raise CapabilityError(
            f"Need at least 2 dumps, got {len(paths)}",
            category=ErrorCategory.PRECONDITION,
        )

    km = _resolve_key_material(key_material, key_file, passphrase, kem_key_file)
    result = auto_export_pattern(
        paths, fmt=fmt, name=name, align=align, context=context,
        min_static_ratio=min_static_ratio, key_material=km,
    )
    return _export_payload(result, name=name, output_dir=output_dir)


def manual_export_pattern(
    *,
    dump_paths: List[str],
    offset: int,
    length: int,
    output_dir: Optional[str] = None,
    fmt: str = "volatility3",
    name: str = "memdiver_pattern",
    min_static_ratio: float = 0.3,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Export a pattern from a user-specified ``offset`` + ``length``.

    The manual counterpart to :func:`export_pattern`: the caller already knows
    where the key lives and supplies the region explicitly. Thin wrapper over
    :func:`memdiver.app.export_service.manual_export_pattern`; the region is read
    through each dump's memory projection so ``.msl`` offsets are memory-relative
    and encrypted containers decrypt with the supplied key material. Mirrors
    :func:`export_pattern`'s payload shape and CapabilityError contract.

    Encrypted ``.msl`` inputs are decrypted when key material is supplied —
    either as file params (the MCP idiom) or as a pre-decoded ``key_material``
    dict of ``open_dump`` kwargs (the CLI idiom).
    """
    # AnalysisServiceError (raised by the compute) is already a CapabilityError
    # subclass with its own accurate category/status; it is allowed to
    # propagate unmodified for the same reasons documented on export_pattern.
    from memdiver.app.export_service import (
        manual_export_pattern as _manual_export,
    )

    paths = [Path(p) for p in dump_paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")
    if len(paths) < 2:
        raise CapabilityError(
            f"Need at least 2 dumps, got {len(paths)}",
            category=ErrorCategory.PRECONDITION,
        )

    km = _resolve_key_material(key_material, key_file, passphrase, kem_key_file)
    result = _manual_export(
        paths, offset=offset, length=length, fmt=fmt, name=name,
        min_static_ratio=min_static_ratio, key_material=km,
    )
    return _export_payload(result, name=name, output_dir=output_dir)


def _resolve_key_material(
    key_material: Optional[Dict[str, Any]],
    key_file: Optional[str],
    passphrase: Optional[str],
    kem_key_file: Optional[str],
) -> Dict[str, Any]:
    """Return ``open_dump`` key kwargs from either idiom.

    A pre-decoded ``key_material`` dict (web / CLI, already read + decoded by
    that surface) is used as-is; otherwise the file-path params (MCP) are read
    from disk via :func:`key_material_kwargs`.
    """
    if key_material is not None:
        return key_material
    return key_material_kwargs(key_file, passphrase, kem_key_file)


def _export_payload(
    result: Dict[str, Any], *, name: str, output_dir: Optional[str],
) -> Dict[str, Any]:
    """Shape an export-compute result into the producer's return payload.

    Shared by the auto (:func:`export_pattern`) and manual
    (:func:`manual_export_pattern`) producers so their observable output — the
    inline ``content`` plus the optional written ``pattern_path`` — cannot
    drift. The full ``pattern`` dict is carried through so the web
    ``/auto-export`` response body stays identical to the pre-relocation shape.
    """
    payload: Dict[str, Any] = {
        "format": result["format"],
        "content": result["content"],
        "pattern": result["pattern"],
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
    nonce_hex: Optional[str] = None,
    aad_hex: Optional[str] = None,
    tag_hex: Optional[str] = None,
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
    from memdiver.app.composition import open_dump
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
    # A negative offset would make read_range slice from the tail; a
    # non-positive length can never satisfy the len(candidate) < length check
    # meaningfully. Reject both up front (the over-run case is caught below).
    if offset < 0 or length <= 0:
        raise CapabilityError(
            "offset must be non-negative and length positive",
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
        nonce = bytes.fromhex(nonce_hex) if nonce_hex else None
        aad = bytes.fromhex(aad_hex) if aad_hex else None
        tag = bytes.fromhex(tag_hex) if tag_hex else None
    except ValueError as exc:
        raise CapabilityError(
            f"Invalid hex input: {exc}", category=ErrorCategory.INVALID_INPUT
        ) from exc

    # AEAD ciphers (GCM, ChaCha20-Poly1305) authenticate against a real record
    # whose plaintext is unknown, so the expected plaintext is dropped; the CBC
    # path keeps the fixed known-plaintext. AEAD-ness is a fact of the resolved
    # verifier, not of which optional args the caller happened to pass.
    is_aead = getattr(verifier, "is_aead", False)
    expected_plaintext = None if is_aead else VERIFICATION_PLAINTEXT
    verified = verifier.verify(
        candidate, ciphertext, iv, expected_plaintext, nonce=nonce, aad=aad, tag=tag
    )
    return {
        "verified": verified,
        "offset": offset,
        "length": length,
        "cipher": cipher,
        "key_hex": candidate.hex() if verified else None,
    }


# ----------------------------------------------------------------------
# export-keylog  (Wireshark-loadable NSS key log from recovered secrets)
# ----------------------------------------------------------------------


def keylog_result(
    *,
    secrets: List[dict],
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Emit a Wireshark-loadable NSS key log from recovered TLS secrets.

    The mission's headline export artifact: renders each recovered secret as one
    ``<LABEL> <client_random_hex> <secret_hex>`` line — the exact
    ``SSLKEYLOGFILE`` format ``tshark -o tls.keylog_file=...`` / Wireshark loads
    to decrypt a capture. The single implementation behind the CLI
    ``export-keylog`` command, the HTTP ``POST /api/analysis/export-keylog``
    route, and the MCP ``export_keylog`` tool, so the artifact cannot fork.

    Each item in ``secrets`` is a plain (JSON-friendly) dict with keys
    ``secret_type`` (str), ``client_random`` (hex str) and ``secret`` (hex str);
    each is converted to a :class:`~memdiver.core.models.CryptoSecret`
    (``identifier`` = the client_random bytes, ``secret_value`` = the secret
    bytes). When ``output_path`` is given the key log is also written there.

    Returns ``{"keylog": <str>, "count": <int lines>, "output_path": <str|None>}``.

    Raises :class:`CapabilityError` (INVALID_INPUT) for a missing required key, a
    non-canonical ``secret_type`` label, or a malformed hex value, mirroring
    :func:`verify_key_result`'s hex handling.

    A ``secret_type`` that is not a canonical NSS key-log label (the aggregate of
    every protocol's labels in the registry — TLS 1.2 ``CLIENT_RANDOM``, the TLS
    1.3 traffic/handshake/exporter labels, plus any non-TLS descriptors) is
    rejected up front: an unknown label silently yields a key log Wireshark
    cannot load, so it is caught here rather than shipped as a broken artifact.
    """
    from memdiver.core.keylog import ALL_SECRET_TYPES, format_keylog_lines
    from memdiver.core.models import CryptoSecret

    crypto_secrets: List[CryptoSecret] = []
    for i, item in enumerate(secrets):
        try:
            secret_type = item["secret_type"]
            client_random = item["client_random"]
            secret = item["secret"]
        except (KeyError, TypeError) as exc:
            raise CapabilityError(
                f"secrets[{i}] missing required key {exc}; each item needs "
                "'secret_type', 'client_random', 'secret'",
                category=ErrorCategory.INVALID_INPUT,
            ) from exc
        if secret_type not in ALL_SECRET_TYPES:
            raise CapabilityError(
                f"secrets[{i}] has non-canonical secret_type {secret_type!r}; "
                f"expected one of {sorted(ALL_SECRET_TYPES)}",
                category=ErrorCategory.INVALID_INPUT,
            )
        try:
            crypto_secrets.append(CryptoSecret(
                secret_type=secret_type,
                identifier=bytes.fromhex(client_random),
                secret_value=bytes.fromhex(secret),
            ))
        except (ValueError, TypeError) as exc:
            raise CapabilityError(
                f"secrets[{i}] has malformed hex: {exc}",
                category=ErrorCategory.INVALID_INPUT,
            ) from exc

    keylog = format_keylog_lines(crypto_secrets)
    if output_path is not None:
        Path(output_path).write_text(keylog)
    return {
        "keylog": keylog,
        "count": keylog.count("\n"),
        "output_path": output_path,
    }


# ----------------------------------------------------------------------
# inspect-pcap  (arm/validate a capture: summarise the TLS sessions it holds)
# ----------------------------------------------------------------------


def inspect_pcap(
    *,
    pcap_path: str,
    pcap_max_records: Optional[int] = None,
    pcap_max_challenges: Optional[int] = None,
) -> Dict[str, Any]:
    """Summarise the TLS sessions a capture contains, without decrypting.

    The "arm/validate" step of the pcap verification flow: before a recovered
    key is proven against a capture (see :func:`brute_force`'s ``pcap_path``
    oracle), this producer parses the capture's handshakes and reports the
    per-session facts the oracle keys off — client/server random, the
    negotiated cipher suite + version, and how many encrypted application-data
    records each direction carries. It reads only already-parsed state; it
    derives no keys and decrypts nothing.

    The single implementation behind the HTTP ``POST /api/pcaps/validate``
    route, the MCP ``inspect_pcap`` tool, and the CLI ``inspect-pcap`` command,
    so the summary cannot fork across surfaces.

    Raises :class:`CapabilityError` (UNSUPPORTED) when ``dpkt`` (a base
    dependency) is not installed, and (INVALID_INPUT) only when the capture
    itself is unreadable (truncated/corrupt/not a capture at all). A *parseable*
    capture with no TLS sessions is not an error: it returns ``session_count: 0``
    with an empty ``sessions`` list. Returns
    ``{"pcap_path": str, "session_count": int, "sessions": [...]}`` where each
    session is one :meth:`TlsPcapResource.describe_sessions` dict.

    ``pcap_max_records`` / ``pcap_max_challenges`` are the same two caps
    :func:`brute_force` applies to the oracle, and they are accepted here for
    one reason: the caps this producer *reports* must be the caps a run will
    actually use. Without them the arm step could only ever echo the resource
    DEFAULTS, so an operator capping a run read back "uncapped" and had no way
    to see the truncation coming. ``None`` (the default) leaves the resource
    default untouched; a value below 1 is rejected exactly as
    :func:`brute_force` rejects it, so the arm step cannot bless a cap the run
    would refuse.

    Alongside those it reports what the parse *dropped*, so a capture is never
    silently understated (the numbers a corpus sweep aggregates depend on it):

    * ``skipped_sessions`` — one dict per session the parser could not use, each
      with a machine-readable ``reason``, the ``flow`` it appeared on, and any
      reason-specific context (e.g. the out-of-table ``cipher_suite``). The
      reachable reasons are ``"no_client_hello"``, ``"no_server_hello"``,
      ``"unsupported_cipher_suite"``, ``"no_change_cipher_spec"`` (the session
      parsed but none of its application data is coverable) and
      ``"client_random_mismatch"`` (only when a resource is pinned to one
      session, which this producer never does). ``"no_cipher_suite"`` and
      ``"short_random"`` exist in the resource as defensive guards on malformed
      ServerHello shapes the bundled dpkt cannot produce — it raises first — so
      they are unreachable here and must not be advertised as expected output.
    * ``flow_count`` — directional TCP flows the capture yielded, so "1 session
      out of 40 flows" is distinguishable from "1 session out of 2".
    * ``caps`` — the parse caps in force:
      ``{"max_records_per_direction": int, "max_challenges": int | None}``.
    * ``records_truncated`` — True when a record was not covered, i.e. some
      session's ``records_returned`` is below its ``app_records_seen`` (both
      additive keys on each session dict).
    * ``challenges_available`` / ``challenges_returned`` /
      ``challenges_truncated`` — the capture-level challenge stream the oracle
      will see. ``max_challenges`` truncates that flat stream ACROSS sessions,
      so it is reported per capture (and mirrored per session by
      ``describe_capture``); ``challenges_returned < challenges_available`` is
      the signal that some verification work is being discarded.

    These keys are purely additive; every key this producer returned before is
    unchanged, including a zero-session capture's ``session_count: 0``.
    """
    from memdiver.engine.resources.tls_pcap import (
        _PCAP_MISSING,
        HAS_PCAP,
        PcapParseError,
        TlsPcapResource,
    )

    if not HAS_PCAP:
        raise CapabilityError(
            f"pcap parsing needs dpkt. {_PCAP_MISSING}",
            category=ErrorCategory.UNSUPPORTED,
        )

    # ``TlsPcapResource.describe_sessions`` funnels every capture-read failure —
    # including dpkt's own ``dpkt.dpkt.NeedData`` on a truncated capture — through
    # ``_read_flows`` into ``PcapParseError`` (see ``tls_pcap._read_flows``), so no
    # bare dpkt error can reach here; map the funnelled errors to INVALID_INPUT.
    _validate_pcap_caps(pcap_max_records, pcap_max_challenges)
    # Only forward a cap the caller actually asked for, so an absent argument
    # leaves the resource default in place instead of re-stating it here.
    resource_caps: Dict[str, Any] = {}
    if pcap_max_records is not None:
        resource_caps["max_records_per_direction"] = int(pcap_max_records)
    if pcap_max_challenges is not None:
        resource_caps["max_challenges"] = int(pcap_max_challenges)

    try:
        capture = TlsPcapResource(pcap_path, **resource_caps).describe_capture()
    except (PcapParseError, OSError, ValueError) as exc:
        raise CapabilityError(
            f"could not parse capture {pcap_path!r}: {exc}",
            category=ErrorCategory.INVALID_INPUT,
        ) from exc

    sessions = capture["sessions"]
    return {
        "pcap_path": pcap_path,
        "session_count": len(sessions),
        "sessions": sessions,
        "skipped_sessions": capture["skipped"],
        "flow_count": capture["flow_count"],
        "caps": capture["caps"],
        "records_truncated": capture["records_truncated"],
        "challenges_available": capture["challenges_available"],
        "challenges_returned": capture["challenges_returned"],
        "challenges_truncated": capture["challenges_truncated"],
    }


# _emit/_progress_bridge/_experiment_check_cancelled MOVED to memdiver.app._progress (P3.1)
# experiment orchestration MOVED to memdiver.app.experiment_orchestration (P3.1)
