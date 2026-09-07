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
import time
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)

import numpy as np

from memdiver.core.service_errors import (
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.core.service_result import Diagnostic, KeyStatus, Severity
from memdiver.engine.brute_force import DEFAULT_NEIGHBORHOOD_PAD
# Two DEFAULT VALUES, imported (never re-literalled) exactly as
# DEFAULT_NEIGHBORHOOD_PAD above is: they are keyword defaults in this module's
# signatures, so they must resolve at import time. The key-location COMPUTE is
# still imported function-locally inside the producers, so ``app`` does not pull
# ``engine.key_location`` at module scope.
from memdiver.engine.key_location import (
    DEFAULT_KEY_CONTEXT,
    DEFAULT_MAX_KEY_OFFSETS,
)

from .composition import raise_if_locked

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


#: The one locked-container guard, promoted to :func:`app.composition.raise_if_locked`
#: (this module, ``app.export_service`` and ``api.routers.architect`` each used
#: to hold their own copy). Kept under the historical private name so every
#: in-module caller — and the tests that reference it — keep working, while the
#: single implementation now lives beside the openers it guards.
_raise_if_locked = raise_if_locked


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

#: Diagnostic codes :func:`locate_key` can attach. Same rationale as the
#: ``CANDIDATES_*`` block above: a surface (or a test) keys off the CODE, never
#: off the prose, which is free to improve.
LOCATE_KEY_NOT_SEARCHED_CODE = "analysis.locate_key.not_searched"
LOCATE_KEY_ABSENT_CODE = "analysis.locate_key.absent"
LOCATE_KEY_PARTIAL_CODE = "analysis.locate_key.partial"
LOCATE_KEY_OFFSET_DRIFT_CODE = "analysis.locate_key.offset_drift"
LOCATE_KEY_MULTI_HIT_CODE = "analysis.locate_key.multiple_occurrences"
LOCATE_KEY_TRUNCATED_CODE = "analysis.locate_key.offsets_truncated"

#: Diagnostic codes :func:`export_key_pattern` can attach. These are QUALITY
#: judgements on the emitted rule, not errors: every one of them still returns a
#: pattern, because a weak signature the analyst can see is worth more than a
#: refusal they cannot inspect.
KEY_PATTERN_STATIC_KEY_CODE = "export.key_pattern.key_fully_static"
KEY_PATTERN_DEGENERATE_ANCHORS_CODE = "export.key_pattern.degenerate_anchors"
KEY_PATTERN_SUBSET_CODE = "export.key_pattern.mask_subset"
KEY_PATTERN_NO_ANCHORS_CODE = "export.key_pattern.no_static_anchors"

#: ``degenerate_anchors`` thresholds. Four distinct byte values is the point
#: below which a "static anchor" is a run of padding; 1.0 bit/byte is what a
#: fair coin over two values carries, and anything below it cannot distinguish
#: this region from any other stretch of the same filler. Both are measured
#: against the real corpus: the key at offset 370,672 has 1 distinct anchor byte
#: and 0.0 bits at the default 64-byte context, and reaches 1.26 bits only at
#: context=256.
KEY_PATTERN_MIN_ANCHOR_BYTES = 4
KEY_PATTERN_MIN_ANCHOR_BITS = 1.0


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


#: The verification resource every pcap run uses unless told otherwise -- the
#: first-party TLS-over-TCP one. Named here, once, because it is now the default
#: of four things that must agree: :func:`_pcap_oracle_config`,
#: :func:`brute_force`, :func:`n_sweep`, and the MCP/CLI spellings of the last
#: two. (``builtin_oracle.build_resource`` keeps its own identical default for
#: the config-file path, which never passes through a producer.)
DEFAULT_RESOURCE_TYPE = "tls-pcap"


def _pcap_oracle_config(
    pcap_path: str,
    tls_client_random: Optional[str],
    pcap_max_records: Optional[int],
    pcap_max_challenges: Optional[int],
    resource_type: str = DEFAULT_RESOURCE_TYPE,
) -> Dict[str, Any]:
    """Assemble the pcap oracle's resource spec.

    Shared by :func:`brute_force` and :func:`n_sweep` so both reach the pcap
    oracle through ONE spelling of the spec. A sweep that verified under a
    different config than the brute force would report a different confirmed
    set for the same key, and the divergence would look like a key that only
    sometimes survives -- exactly the false signal this harness exists to rule
    out.

    ``resource_type`` names the registered verification resource
    (``engine.resources.builtin_oracle.RESOURCE_FACTORIES``). It defaults to the
    first-party ``"tls-pcap"``, so behaviour is unchanged, but it is an explicit
    parameter rather than a literal buried in this body: the resource registry
    is now extensible out-of-tree (the ``memdiver.oracles`` entry-point group),
    and a hardcoded type would make every such resource unreachable from here.
    Trust is NOT inherited from this argument -- see
    :func:`_pcap_oracle_trusted`.

    Only a cap the caller actually asked for is forwarded: an absent key leaves
    the resource/oracle defaults untouched (see builtin_oracle's config).
    :func:`_validate_pcap_caps` runs here so every caller of the pcap oracle
    rejects a sub-1 cap identically.
    """
    config: Dict[str, Any] = {"resource_type": resource_type, "pcap": pcap_path}
    if tls_client_random:
        config["client_random"] = tls_client_random
    _validate_pcap_caps(pcap_max_records, pcap_max_challenges)
    if pcap_max_records is not None:
        config["max_records_per_direction"] = int(pcap_max_records)
    if pcap_max_challenges is not None:
        config["max_challenges"] = int(pcap_max_challenges)
    return config


def _validate_resource_type(resource_type: str) -> None:
    """Refuse an unregistered ``resource_type`` before any oracle is loaded.

    Reachable only because C4a promoted ``resource_type`` to a real
    :func:`brute_force` / :func:`n_sweep` parameter (and a ``--resource-type``
    CLI flag), which also made a typo reachable. Left unchecked, an unknown name
    reaches ``build_resource``'s ``ValueError`` inside the oracle LOADER, where
    it is re-wrapped as ``OracleLoadError`` -- a bare ``RuntimeError`` no
    surface funnels -- and the user gets a traceback instead of the list of
    names they could have typed. That is precisely the failure mode C4a exists
    to remove, so it is caught here, fail-fast, with the registry in the
    message.

    NOT folded into :func:`_pcap_oracle_config`: that builder is also the
    documented way to construct a spec for a type that is deliberately absent
    (the provenance tests do exactly that), and a builder that refused unknown
    names could no longer express "what if this were installed". Two call sites
    share this one function for the same reason they share
    :func:`_pcap_oracle_trusted`.
    """
    from memdiver.engine.resources.builtin_oracle import (
        is_registered_resource_type,
        registered_resource_types,
    )

    if not is_registered_resource_type(resource_type):
        raise CapabilityError(
            f"unknown resource_type {resource_type!r}; registered: "
            f"{list(registered_resource_types())}. Out-of-tree resources are "
            f"registered by installing a package that advertises the "
            f"'memdiver.oracles' entry-point group; "
            f"inspect_pcap(detect_protocols=True) reports which resource_type "
            f"a given capture needs.",
            category=ErrorCategory.INVALID_INPUT,
        )


def _pcap_oracle_trusted(config: Dict[str, Any]) -> bool:
    """Whether *config*'s resource may skip the untrusted-code load sandbox.

    THE one place the trusted-load decision is made for the builtin resource
    oracle, shared by :func:`brute_force` (``oracle_trusted=``) and
    :func:`n_sweep` (``load_oracle(sandbox=)``) so the two surfaces cannot
    disagree about whether the same spec is trusted.

    The exemption exists for our own in-tree factories, whose input is a pcap --
    data, not executable -- and whose parse of a large capture would be
    misread as a hang under the sandbox's tight caps. It is granted per
    RESOURCE TYPE and not per config, because ``resource_type`` may now name an
    out-of-tree factory from the ``memdiver.oracles`` entry-point group. Passing
    the exemption on to one of those would make merely installing a package an
    arbitrary-code-execution path: the plugin's import and ``build_oracle``
    would run unsandboxed in this process and in every brute-force worker.
    """
    from memdiver.engine.resources.builtin_oracle import is_first_party_resource_type

    return is_first_party_resource_type(str(config.get("resource_type", "")))


def _pcap_protocol_refusal(
    pcap_path: str, resource_type: str, exc: Exception
) -> CapabilityError:
    """Turn a pcap-oracle parse failure into an error that says what IS there.

    The oracle's own message is honest but one-sided: ``no complete TLS
    handshake found in 'capture.pcap'`` describes what was LOOKED FOR. A user
    who captured QUIC, or captured the wrong interface, reads it as "MemDiver
    is broken" because it never mentions the two QUIC associations sitting in
    the file. So the message is kept verbatim (it is the precise diagnosis
    whenever the capture really is TLS) and the detector's answer is appended to
    it.

    THE refusal rule -- ask, never guess:

    * **Several decryptable protocols** -> ``PRECONDITION``, listing them and
      demanding an explicit ``resource_type``. Picking one would verify against
      a different protocol's records than the caller meant and report a real key
      as unconfirmed, which looks exactly like a key that is not there. Mirrors
      :func:`_select_pcap_field_session`'s multi-session refusal, for the same
      reason and in the same shape.
    * **Exactly one, and it is not the type we were told to use** ->
      ``PRECONDITION`` naming it, because the fix is a single argument away and
      the caller cannot be expected to know the registry.
    * **Otherwise** (nothing registered can decrypt what is there, or the one
      thing that can is already what we tried) -> ``INVALID_INPUT``, the
      category this path has always used, carrying the original message plus the
      inventory and the registered types.

    Shared by :func:`brute_force` and :func:`n_sweep` so the two cannot describe
    the same capture differently. Detection never raises (see
    :func:`~memdiver.engine.resources.protocol_detect.detect_protocols`), so
    this helper cannot fail on top of the failure it is explaining.
    """
    from memdiver.engine.resources.builtin_oracle import registered_resource_types
    from memdiver.engine.resources.protocol_detect import detect_protocols

    candidates = detect_protocols(pcap_path)
    decryptable = tuple(c for c in candidates if c.decryptable)
    registered = list(registered_resource_types())

    if len(decryptable) > 1:
        return CapabilityError(
            f"capture {pcap_path!r} carries {len(decryptable)} protocols this "
            f"build can decrypt; name one with "
            f"resource_type ({[c.resource_type for c in decryptable]}). There "
            f"is no default on purpose: verifying a key against the wrong "
            f"protocol's records reports a real key as unconfirmed. Found: "
            f"{'; '.join(c.describe() for c in decryptable)}.",
            category=ErrorCategory.PRECONDITION,
        )
    if len(decryptable) == 1 and decryptable[0].resource_type != resource_type:
        only = decryptable[0]
        return CapabilityError(
            f"capture {pcap_path!r} holds no {resource_type!r} session, but it "
            f"does hold {only.protocol} ({only.detail}); re-run with "
            f"resource_type={only.resource_type!r}. Original parse error: {exc}",
            category=ErrorCategory.PRECONDITION,
        )
    inventory = (
        "; ".join(c.describe() for c in candidates)
        if candidates
        else "no protocol MemDiver can name (an unreadable capture, or one with "
        "no IP traffic)"
    )
    return CapabilityError(
        f"Invalid input: {exc}. Detected in {pcap_path!r}: {inventory}. "
        f"Registered resource types: {registered}.",
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


def _validate_neighborhood_pad(neighborhood_pad: int) -> int:
    """Reject a negative per-side neighborhood pad through the standard funnel.

    Zero is legal (it means "attach only the hit itself"); a negative pad would
    silently invert the slice bounds and emit a nonsense window.
    """
    pad = int(neighborhood_pad)
    if pad < 0:
        raise CapabilityError(
            f"neighborhood_pad must be >= 0, got {pad}",
            category=ErrorCategory.INVALID_INPUT,
        )
    return pad


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
    resource_type: str = DEFAULT_RESOURCE_TYPE,
    persist_ground_truth: bool = False,
    key_sizes: Sequence[int] = (32,),
    stride: int = 1,
    jobs: int = 0,
    exhaustive: bool = True,
    state_path: Optional[str] = None,
    top_k: int = 10,
    neighborhood_pad: int = DEFAULT_NEIGHBORHOOD_PAD,
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

    ``resource_type`` names the registered verification resource the capture is
    read through (``engine.resources.builtin_oracle.RESOURCE_FACTORIES``). It
    defaults to the first-party ``"tls-pcap"``, so behaviour is unchanged, and it
    is a real parameter rather than a literal for one reason: when a capture
    turns out to hold more than one protocol this build can decrypt, the refusal
    DEMANDS an explicit ``resource_type`` (see
    :func:`_pcap_protocol_refusal`) — and an error that demands what the caller
    has no way to supply is not an error, it is a dead end. Trust is NOT
    inherited from it: an out-of-tree type keeps the load sandbox (see
    :func:`_pcap_oracle_trusted`).

    ``persist_ground_truth`` (opt-in, default off) records the confirmed hits in
    the project database's ``ground_truth`` ledger (labelled ``"pcap"`` or
    ``"oracle"``) — the trusted denominator for later corpus/precision stats. It
    no-ops gracefully when the DuckDB backend is unavailable. Each row is
    stamped with the corpus axes resolved from ``reference_path`` (library,
    protocol version, library version, scenario, run number, raw phase, dump
    path), so the ledger can be sliced by axis; a dump outside the corpus layout
    records its path and leaves the rest at the ledger's defaults.

    ``neighborhood_pad`` (default 64 bytes per side) sets how much context is
    sliced around each hit from the ``state_path`` Welford state. It flows
    straight into the emitted vol3 plugin / YARA rule, so the default is pinned;
    widen it only when the emitted signature is deliberately being regenerated.

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
    neighborhood_pad = _validate_neighborhood_pad(neighborhood_pad)

    bf_oracle_kwargs: Dict[str, Any] = {}
    if pcap_path:
        from memdiver.engine.resources.builtin_oracle import BUILTIN_ORACLE_PATH
        resolved_oracle_path = BUILTIN_ORACLE_PATH
        oracle_label = Path(pcap_path).name
        _validate_resource_type(resource_type)
        pcap_config = _pcap_oracle_config(
            pcap_path, tls_client_random, pcap_max_records, pcap_max_challenges,
            resource_type,
        )
        bf_oracle_kwargs["oracle_config"] = pcap_config
        # Not an unconditional True: the sandbox exemption belongs to
        # first-party resource types only (see :func:`_pcap_oracle_trusted`).
        bf_oracle_kwargs["oracle_trusted"] = _pcap_oracle_trusted(pcap_config)
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
            neighborhood_pad=neighborhood_pad,
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
    except PcapParseError as exc:
        # PcapParseError (a bare ``Exception`` subclass) can surface eagerly from
        # a pcap oracle's ``ResourceOracle.__init__`` — e.g. a ``tls_client_random``
        # that matches no captured session, or a capture holding no TLS handshake
        # at all. Caught ahead of the generic funnel below so the refusal can say
        # what the capture DOES hold instead of only what was looked for; the
        # oracle's own message is carried through verbatim.
        if not pcap_path:  # pragma: no cover - only a BYO oracle raising ours
            raise CapabilityError(
                f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
            ) from exc
        raise _pcap_protocol_refusal(str(pcap_path), resource_type, exc) from exc
    except (OSError, ValueError) as exc:
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
    output_dir: str,
    n_values: List[int],
    oracle_path: Optional[str] = None,
    pcap_path: Optional[str] = None,
    tls_client_random: Optional[str] = None,
    pcap_max_records: Optional[int] = None,
    pcap_max_challenges: Optional[int] = None,
    resource_type: str = DEFAULT_RESOURCE_TYPE,
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

    The same two mutually-exclusive oracle sources :func:`brute_force` accepts:
      * ``oracle_path`` — a user-supplied BYO decryption oracle script
        (sandboxed), optionally configured by ``oracle_config_path``.
      * ``pcap_path`` — a pcap/pcapng of the same TLS session, verified through
        MemDiver's first-party pcap oracle. ``tls_client_random`` (hex)
        optionally restricts matching to one session, and ``pcap_max_records`` /
        ``pcap_max_challenges`` size the oracle's work exactly as they do for
        ``brute_force``. Requires the ``pcap`` extra.

    The sweep re-runs whichever oracle it was given at every N, so a pcap run
    answers the same question a BYO-oracle run does — at what N does the key
    first survive the consensus filter — without needing an oracle FILE.

    ``resource_type`` names the registered verification resource, exactly as it
    does for :func:`brute_force` (default ``"tls-pcap"``, trust never inherited)
    — the two share ONE config builder, so a sweep and a brute force cannot read
    the same capture through different resources.

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
    from memdiver.engine.resources.tls_pcap import PcapParseError
    from memdiver.presentation.reports import nsweep_headline

    if bool(oracle_path) == bool(pcap_path):
        raise CapabilityError(
            "Provide exactly one of oracle_path or pcap_path",
            category=ErrorCategory.INVALID_INPUT,
        )
    # Built (and both the caps and the resource type validated) BEFORE any dump
    # is opened, so bad input fails fast instead of after an expensive fold.
    if pcap_path:
        _validate_resource_type(resource_type)
    pcap_config = (
        _pcap_oracle_config(
            pcap_path, tls_client_random, pcap_max_records, pcap_max_challenges,
            resource_type,
        )
        if pcap_path
        else None
    )

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
        if pcap_config is not None:
            from memdiver.engine.resources.builtin_oracle import BUILTIN_ORACLE_PATH

            # Same trusted-load contract ``run_brute_force`` applies to the
            # builtin oracle: for a FIRST-PARTY resource type it is our own
            # module and the pcap it reads is data, not executable, so the
            # untrusted-code load sandbox is skipped. Sandboxing it would also
            # misclassify a slow parse of a large capture as a hang. An
            # out-of-tree resource type keeps the sandbox -- one predicate,
            # shared with ``brute_force`` (see :func:`_pcap_oracle_trusted`).
            oracle = load_oracle(Path(BUILTIN_ORACLE_PATH), config=pcap_config,
                                 sandbox=not _pcap_oracle_trusted(pcap_config))
        else:
            config = load_oracle_config(
                Path(oracle_config_path) if oracle_config_path else None
            )
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
    except PcapParseError as exc:
        # PcapParseError (a bare ``Exception`` subclass) surfaces eagerly from the
        # pcap oracle's ``ResourceOracle.__init__`` — e.g. a ``tls_client_random``
        # matching no captured session, or a capture holding no TLS handshake at
        # all. Routed through the SAME refusal ``brute_force`` uses, so a sweep
        # and a brute force describe the same capture identically instead of one
        # naming the QUIC in it and the other not.
        if not pcap_path:  # pragma: no cover - only a BYO oracle raising ours
            raise CapabilityError(
                f"Invalid input: {exc}", category=ErrorCategory.INVALID_INPUT
            ) from exc
        raise _pcap_protocol_refusal(str(pcap_path), resource_type, exc) from exc
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
    neighborhood_pad: int = DEFAULT_NEIGHBORHOOD_PAD,
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

    ``neighborhood_pad`` (default 64 bytes per side) sets the context width
    attached to a recovered hit — the same knob ``brute_force`` exposes, and the
    same pinned default, because it reaches every emitted artifact.

    ``on_progress`` / ``is_cancelled`` are optional surface hooks; unset they
    are no-ops (byte-identical CLI/MCP behaviour). Progress mirrors the web's
    ``escalate`` stage (the pipeline's floor-free fall-through).
    """
    from memdiver.app.reports import write_auto_floor_artifacts
    from memdiver.app.composition import open_dump
    from memdiver.engine.auto_floor import hit_tier, run_auto_floor
    from memdiver.engine.oracle import load_oracle, load_oracle_config

    neighborhood_pad = _validate_neighborhood_pad(neighborhood_pad)
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
            neighborhood_pad=neighborhood_pad,
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
# locate-key  (where ONE known secret sits across N dumps)  +  the
# key-anchored pattern export built on top of it
# ----------------------------------------------------------------------
#
# Neither producer returns a ``ServiceResult``. That envelope belongs to the
# ``tools_inspect`` / ``tools_xref`` families, whose payloads must carry a
# per-dump key/decrypt StatusBlock; these two are pipeline producers like every
# other function in this module and return a bare dict with a ``diagnostics``
# list. Hard errors are RAISED as ``CapabilityError`` — never returned as
# ``{"error": ...}``, which ``tests/test_architecture_invariants.py`` enforces
# with a zero-tolerance ratchet.


class _KeyNeedle(NamedTuple):
    """The resolved secret plus the provenance of HOW it was supplied.

    ``input_form`` travels all the way into the payload on purpose: three input
    forms that agree on the bytes still differ in what the caller knew, and an
    analyst reading a result months later needs to see whether the 48 bytes came
    from a key log (labelled, with a client random) or from a bare hex paste.
    """

    needle: bytes
    secret_type: str
    client_random: str
    input_form: str


#: The three accepted spellings of "here is the secret", in the order the
#: error message lists them.
KEY_INPUT_FORMS = ("key_hex", "keylog_line", "secret")

#: :func:`locate_key`'s forms: the three above plus C2's SYMBOLIC one, which
#: names a handshake field in a capture instead of pasting its bytes.
#:
#: A separate tuple rather than four entries in ``KEY_INPUT_FORMS`` because
#: :func:`export_key_pattern` shares the resolver but NOT this form: a signature
#: anchored on a public handshake field is not a key pattern (the field is on the
#: wire, so wildcarding it proves nothing), and its "supply exactly ONE of ..."
#: message must therefore keep naming three forms rather than advertising a
#: fourth it would refuse.
LOCATE_KEY_INPUT_FORMS = KEY_INPUT_FORMS + ("pcap_field",)


def _resolve_key_needle(
    key_hex: str,
    keylog_line: str,
    secret: Optional[Dict[str, str]],
    pcap_field: Optional[Dict[str, str]] = None,
    *,
    accepted_forms: Sequence[str] = KEY_INPUT_FORMS,
) -> _KeyNeedle:
    """Resolve EXACTLY ONE of the accepted input forms into needle bytes.

    Shared by :func:`locate_key` and :func:`export_key_pattern` so the two
    cannot disagree about what a given input means.

    There is deliberately NO precedence and NO autodetection. A caller that
    sends ``key_hex`` together with a ``keylog_line`` naming DIFFERENT bytes has
    a bug, and silently answering about one of them produces a confident,
    fully-populated per-dump census of the wrong secret — the single most
    expensive wrong answer this capability can give. Refusing costs one round
    trip. The precedent is :func:`brute_force`'s ``--oracle`` / ``--pcap``
    mutual exclusion, made for the same reason.

    ``accepted_forms`` is which spellings THIS caller takes — the three-form
    :data:`KEY_INPUT_FORMS` by default, :data:`LOCATE_KEY_INPUT_FORMS` from
    :func:`locate_key`. It is a parameter rather than a global so the error
    message can only ever name forms the call would actually honour.

    Raises:
        CapabilityError: INVALID_INPUT when zero or more than one accepted form
            is supplied (the message names what WAS supplied), when a form this
            caller does not accept is supplied, for malformed hex, for a key-log
            line that does not parse, for an unresolvable ``pcap_field``, and for
            an empty secret.
    """
    present = {
        "key_hex": bool(key_hex and key_hex.strip()),
        "keylog_line": bool(keylog_line and keylog_line.strip()),
        "secret": secret is not None,
        "pcap_field": pcap_field is not None,
    }
    # A form this caller does not accept is refused BY NAME rather than
    # dropped. Silently ignoring a ``pcap_field`` passed to
    # ``export_key_pattern`` would answer about whichever OTHER form came with
    # it — the same confident-wrong-secret failure the exactly-one rule exists
    # to prevent, just arrived at from the other side.
    unaccepted = [name for name, given in present.items()
                  if given and name not in accepted_forms]
    if unaccepted:
        raise CapabilityError(
            f"Input form(s) {unaccepted} are not accepted here; this call takes "
            f"exactly ONE of {list(accepted_forms)}.",
            category=ErrorCategory.INVALID_INPUT,
        )
    supplied = [name for name in accepted_forms if present[name]]
    if len(supplied) != 1:
        raise CapabilityError(
            f"Supply exactly ONE of {list(accepted_forms)}; got "
            f"{supplied or 'none'}. There is no precedence between them on "
            f"purpose: two forms naming different bytes would otherwise yield a "
            f"confident per-dump answer about the wrong secret.",
            category=ErrorCategory.INVALID_INPUT,
        )
    form = supplied[0]

    if form == "key_hex":
        needle = _needle_from_key_hex(key_hex)
        secret_type, client_random = "", ""
    elif form == "keylog_line":
        crypto_secret = _secret_from_keylog_line(keylog_line)
        needle = bytes(crypto_secret.secret_value)
        secret_type = str(crypto_secret.secret_type)
        client_random = bytes(crypto_secret.identifier).hex()
    elif form == "pcap_field":
        needle, secret_type, client_random = _needle_from_pcap_field(pcap_field or {})
    else:
        crypto_secret = _crypto_secret_from_dict(secret)
        needle = bytes(crypto_secret.secret_value)
        secret_type = str(crypto_secret.secret_type)
        client_random = bytes(crypto_secret.identifier).hex()

    if not needle:
        # Mirrors ``search_bytes_result``'s "Empty byte pattern": an empty
        # needle would come back "searched, present=False" for every dump — a
        # green-looking absent verdict for a secret nobody searched for.
        # ``locate_key_across_dumps`` refuses it too (as a ValueError, i.e. a
        # writer bug); this is the user-facing spelling, raised first.
        raise CapabilityError(
            "Empty secret; nothing to locate",
            category=ErrorCategory.INVALID_INPUT,
        )
    return _KeyNeedle(
        needle=needle,
        secret_type=secret_type,
        client_random=client_random,
        input_form=form,
    )


def _needle_from_key_hex(key_hex: str) -> bytes:
    """Normalise a pasted hex key into bytes.

    The normalisation is copied VERBATIM from
    ``app.tools_inspect.search_bytes_result`` (strip, drop a leading ``0x``,
    join on any whitespace) so a hex string that works in the byte-search box
    works here — an analyst pastes the same ``aa bb cc`` from the same hex
    viewer into both.
    """
    cleaned = key_hex.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = "".join(cleaned.split())
    if not cleaned:
        raise CapabilityError(
            "Empty hex key", category=ErrorCategory.INVALID_INPUT)
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise CapabilityError(
            f"Invalid hex key: {key_hex!r}",
            category=ErrorCategory.INVALID_INPUT,
        ) from exc


def _secret_from_keylog_line(keylog_line: str) -> Any:
    """Parse ONE NSS key-log line, saying WHY it failed when it does.

    ``core.keylog.parse_keylog_line`` returns ``None`` for three distinct
    mistakes and the fix differs for each: a wrong field count means the paste
    lost a column, an unknown label means the wrong protocol was picked, and bad
    hex means a truncated copy. One "could not parse that line" message would
    send the analyst hunting through all three.
    ``core.keylog.is_well_formed_keylog_line`` is what splits them apart.
    """
    from memdiver.core.keylog import (
        ALL_SECRET_TYPES,
        is_well_formed_keylog_line,
        parse_keylog_line,
    )

    line = keylog_line.strip()
    parsed = parse_keylog_line(line)
    if parsed is not None:
        return parsed

    fields = line.split()
    if len(fields) != 3:
        raise CapabilityError(
            f"keylog_line has {len(fields)} whitespace-separated field(s), "
            f"expected 3: '<LABEL> <client_random_hex> <secret_hex>'",
            category=ErrorCategory.INVALID_INPUT,
        )
    if fields[0] not in ALL_SECRET_TYPES:
        raise CapabilityError(
            f"keylog_line has non-canonical label {fields[0]!r}; expected one "
            f"of {sorted(ALL_SECRET_TYPES)}",
            category=ErrorCategory.INVALID_INPUT,
        )
    if not is_well_formed_keylog_line(line):
        raise CapabilityError(
            f"keylog_line has malformed hex in the client_random or secret "
            f"field: {line!r}",
            category=ErrorCategory.INVALID_INPUT,
        )
    # Unreachable: both the parser and the well-formedness probe consult
    # ``keylog._get_all_secret_types()``, so a well-formed line with a canonical
    # label and valid hex always parses. Kept as INTERNAL rather than silently
    # re-raising INVALID_INPUT, because reaching it means the two diverged.
    raise CapabilityError(
        f"keylog_line is well-formed but did not parse: {line!r}",
        category=ErrorCategory.INTERNAL,
    )


#: The keys a ``pcap_field`` mapping may carry. ``client_random`` is the only
#: optional one: it selects ONE session out of a capture that holds several.
PCAP_FIELD_KEYS = ("pcap_path", "field_id", "client_random")


def _needle_from_pcap_field(
    pcap_field: Mapping[str, str],
    *,
    pcap_max_records: Optional[int] = None,
    pcap_max_challenges: Optional[int] = None,
) -> Tuple[bytes, str, str]:
    """Resolve ``{pcap_path, field_id, client_random?}`` into needle bytes.

    C2's SYMBOLIC input form: instead of pasting 64 hex characters, the caller
    says *"use this capture's ``client_random``"* (or its ``sni``, or its
    ``certificate.0``) and the bytes are read off the wire. That matters for two
    reasons. It removes the transcription step — the single most common way a
    hunt ends in a confident, fully-populated census of the wrong bytes — and it
    makes the request REPRODUCIBLE: ``field_id="client_random"`` re-resolves
    against a re-captured session, whereas a pasted hex string is frozen to one
    handshake.

    The field catalogue comes from :func:`inspect_pcap` with
    ``include_fields=True`` — not from ``TlsPcapResource`` directly — so the
    dpkt guard, the cap validation and the unreadable-capture funnel are the
    ones a caller already gets from the arm step, spelled once.

    Returns ``(needle, field_id, client_random)``. The ``field_id`` rides home in
    the payload's ``secret_type`` slot and the resolved session's
    ``client_random`` in its own, which keeps :func:`_locate_key_payload`'s shape
    frozen while still recording WHICH field of WHICH session produced the bytes
    (``input_form == "pcap_field"`` is what tells a reader to read
    ``secret_type`` as a field id rather than an NSS secret label).

    ``pcap_max_records`` / ``pcap_max_challenges`` are forwarded to that arm
    step so the caps the caller asked for are the caps the needle was read
    under; both default to ``None`` (the resource defaults), which is what
    :func:`locate_key` passes.

    Raises:
        CapabilityError: INVALID_INPUT for an unknown key, a missing
            ``pcap_path`` / ``field_id``, a capture with no parsed session, a
            ``client_random`` no session carries, an unknown ``field_id``, and a
            field whose ``searchable`` is False. PRECONDITION when the capture
            holds several sessions and no ``client_random`` picks one — the one
            case where guessing would silently answer about another handshake.
    """
    unknown = [key for key in pcap_field if key not in PCAP_FIELD_KEYS]
    if unknown:
        raise CapabilityError(
            f"pcap_field has unknown key(s) {sorted(unknown)}; expected "
            f"{list(PCAP_FIELD_KEYS)} (client_random optional)",
            category=ErrorCategory.INVALID_INPUT,
        )
    pcap_path = str(pcap_field.get("pcap_path") or "").strip()
    field_id = str(pcap_field.get("field_id") or "").strip()
    missing = [name for name, value in
               (("pcap_path", pcap_path), ("field_id", field_id)) if not value]
    if missing:
        raise CapabilityError(
            f"pcap_field is missing required key(s) {missing}; it takes "
            f"{{'pcap_path': ..., 'field_id': ..., 'client_random': <optional>}}",
            category=ErrorCategory.INVALID_INPUT,
        )
    # ``include_fields=True`` is the only extra work this asks for; every other
    # part of the arm step (caps, dpkt probe, error funnel) is unchanged. The
    # two caps default to ``None`` -- i.e. every existing caller reaches exactly
    # the call it always made -- and are forwarded for one reason:
    # :func:`locate_field_across_pairs` accepts them, and a cap it honoured for
    # the search but dropped for the needle extraction would silently answer
    # about a different parse of the capture than the one it reported.
    inspected = inspect_pcap(
        pcap_path=pcap_path,
        pcap_max_records=pcap_max_records,
        pcap_max_challenges=pcap_max_challenges,
        include_fields=True,
    )
    session = _select_pcap_field_session(
        inspected["sessions"], str(pcap_field.get("client_random") or "").strip()
    )
    field = _select_pcap_field(session.get("fields") or [], field_id)
    if not field["searchable"]:
        # Function-local so this ``app`` module still pulls no ``engine`` at
        # import time (the repo-wide idiom); the floor is quoted rather than
        # restated so the message cannot drift from the rule that set the flag.
        from memdiver.engine.resources.protocol_fields import MIN_SEARCHABLE_LEN

        raise CapabilityError(
            f"pcap_field {field_id!r} is not searchable (type "
            f"{field['type']}, length {field['length']}). A needle must be a "
            f"literal run of at least {MIN_SEARCHABLE_LEN} bytes: shorter runs "
            f"and wire-encoding artifacts (uint / uint[]) match everywhere, so "
            f"a hit on one carries no information. Searchable in this session: "
            f"{_searchable_field_ids(session)}.",
            category=ErrorCategory.INVALID_INPUT,
        )
    return bytes.fromhex(field["value_hex"]), field_id, session["client_random"]


def _select_pcap_field_session(
    sessions: Sequence[Dict[str, Any]], client_random: str,
) -> Dict[str, Any]:
    """Pick the ONE session a ``pcap_field`` request refers to.

    Pure over ``inspect_pcap``'s session dicts so the selection rule is testable
    without a capture. The rule, in order:

    * an explicit ``client_random`` selects that session (hex, case-insensitive,
      a leading ``0x`` tolerated exactly as :func:`_needle_from_key_hex` does);
    * with no selector, a single-session capture — the overwhelmingly common
      case — selects itself;
    * with no selector and several sessions, REFUSE. Defaulting to the first
      would answer about a different handshake than the one the caller meant,
      and the answer would look completely healthy.
    """
    if not sessions:
        raise CapabilityError(
            "capture holds no parsed TLS session, so it has no fields to name",
            category=ErrorCategory.INVALID_INPUT,
        )
    wanted = client_random.strip().lower()
    if wanted.startswith("0x"):
        wanted = wanted[2:]
    if wanted:
        for session in sessions:
            if str(session["client_random"]).lower() == wanted:
                return session
        raise CapabilityError(
            f"no session in this capture has client_random {client_random!r}; "
            f"it holds {[s['client_random'] for s in sessions]}",
            category=ErrorCategory.INVALID_INPUT,
        )
    if len(sessions) == 1:
        return sessions[0]
    raise CapabilityError(
        f"capture holds {len(sessions)} sessions; name one with "
        f"pcap_field['client_random'] "
        f"({[s['client_random'] for s in sessions]}). There is no default on "
        f"purpose: the wrong session's field is a valid-looking needle from "
        f"another handshake.",
        category=ErrorCategory.PRECONDITION,
    )


def _select_pcap_field(
    fields: Sequence[Dict[str, Any]], field_id: str,
) -> Dict[str, Any]:
    """Look one ``field_id`` up in a session's field list.

    Id-keyed, which is why C1 prefixes extension ids ``client_ext.``/
    ``server_ext.``: extension 0x000b appears in BOTH hellos of a real
    handshake, so a bare ``ext.0x000b`` would resolve to whichever came last.
    The not-found message lists the SEARCHABLE ids rather than all of them,
    because those are the only ones this form can go on to use.
    """
    for field in fields:
        if field["field_id"] == field_id:
            return field
    available = sorted(f["field_id"] for f in fields if f["searchable"])
    raise CapabilityError(
        f"unknown pcap field_id {field_id!r}; searchable ids in this session: "
        f"{available}",
        category=ErrorCategory.INVALID_INPUT,
    )


def _searchable_field_ids(session: Mapping[str, Any]) -> List[str]:
    """The field ids of one session that a dump search can usefully take."""
    return sorted(
        field["field_id"]
        for field in (session.get("fields") or [])
        if field["searchable"]
    )


def _locate_key_diagnostics(
    result: Any, *, max_offsets: int,
) -> List[Diagnostic]:
    """The honest qualifications on one key-location verdict.

    Every one of these is a QUALIFICATION, never an error: the result is already
    computed and the caller is entitled to it. What they encode is the gap
    between "found" / "absent" and what the numbers actually support.
    """
    diagnostics: List[Diagnostic] = []

    unsearched = [d for d in result.dumps if not d.searched]
    if unsearched:
        # Fires EVEN when the verdict is ``found``. A found verdict needs only
        # one dump, but every count beside it (``dumps_absent``, the survival
        # ratio a caller computes from it) is over a SHORT denominator, and the
        # unsearched rows are exactly the ones that might also hold the key.
        diagnostics.append(Diagnostic(
            code=LOCATE_KEY_NOT_SEARCHED_CODE,
            message=(
                f"{len(unsearched)} of {result.dumps_total} dumps were never "
                f"searched ("
                + "; ".join(
                    f"{d.name}: {d.status}" + (f" — {d.detail}" if d.detail else "")
                    for d in unsearched[:5])
                + f"). Their presence is UNKNOWN, not absent, so every count "
                f"here is over {result.dumps_searched} dumps, not "
                f"{result.dumps_total}."
            ),
            severity=Severity.WARNING,
            details={
                "dumps_not_searched": len(unsearched),
                "dumps_total": result.dumps_total,
                "dumps_searched": result.dumps_searched,
                "statuses": {d.dump_path: d.status for d in unsearched},
            },
        ))

    if result.verdict == "absent":
        diagnostics.append(Diagnostic(
            code=LOCATE_KEY_ABSENT_CODE,
            message=(
                f"The secret occurs in none of the {result.dumps_searched} "
                f"dumps that were actually searched. This is a measured "
                f"absence over a known denominator, not a failure to look."
            ),
            severity=Severity.INFO,
            details={"dumps_searched": result.dumps_searched},
        ))

    if result.verdict == "found" and not result.unanimous:
        # THE ordinary case on real memory, not an edge case: on the reference
        # 8-dump OpenSSL TLS 1.2 run the master secret survives in 2 of the 8
        # phases and is wiped in the other 6.
        diagnostics.append(Diagnostic(
            code=LOCATE_KEY_PARTIAL_CODE,
            message=(
                f"Present in {result.dumps_present} of "
                f"{result.dumps_searched} searched dumps ("
                + ", ".join(d.name for d in result.present[:8])
                + f"), and provably absent from {result.dumps_absent}. Partial "
                f"survival is the normal shape of a real key across a process "
                f"lifecycle — the absent dumps are evidence, not a shortfall."
            ),
            severity=Severity.INFO,
            details={
                "dumps_present": result.dumps_present,
                "dumps_absent": result.dumps_absent,
                "present_dumps": [d.dump_path for d in result.present],
                "absent_dumps": [d.dump_path for d in result.absent],
            },
        ))

    if result.dumps_present > 1 and not result.offsets_agree:
        diagnostics.append(Diagnostic(
            code=LOCATE_KEY_OFFSET_DRIFT_CODE,
            message=(
                f"The secret sits at DIFFERENT offsets across the "
                f"{result.dumps_present} dumps that hold it "
                f"({sorted(set(result.anchor_offsets.values()))}). No single "
                f"offset generalises, so an offset-based rule derived from one "
                f"of them will not locate it in the others."
            ),
            severity=Severity.INFO,
            details={"anchor_offsets": dict(result.anchor_offsets)},
        ))

    multi = [d for d in result.present if d.hit_count > 1]
    if multi:
        diagnostics.append(Diagnostic(
            code=LOCATE_KEY_MULTI_HIT_CODE,
            message=(
                f"{len(multi)} dump(s) contain the secret more than once ("
                + ", ".join(f"{d.name}: {d.hit_count}" for d in multi[:8])
                + "). These are REAL copies, not a search artefact: a TLS "
                "library keeps the same secret in its key-schedule and its "
                "record-layer structs (see engine/truth_labels.py), so the "
                "extra occurrences are additional places to look, not noise."
            ),
            severity=Severity.INFO,
            details={d.dump_path: d.hit_count for d in multi},
        ))

    truncated = [d for d in result.dumps if d.offsets_truncated]
    if truncated:
        diagnostics.append(Diagnostic(
            code=LOCATE_KEY_TRUNCATED_CODE,
            message=(
                f"{len(truncated)} dump(s) returned only the first "
                f"{max_offsets} offsets (max_offsets={max_offsets}); "
                f"``hit_count`` is still the TRUE total, so the verdict and "
                f"every count are unaffected. Raise max_offsets to see them "
                f"all."
            ),
            severity=Severity.INFO,
            details={
                "max_offsets": int(max_offsets),
                "hit_counts": {d.dump_path: d.hit_count for d in truncated},
            },
        ))
    return diagnostics


def _locate_key_payload(
    result: Any,
    *,
    needle: bytes,
    secret_type: str,
    client_random: str,
    input_form: str,
    view: Optional[str],
    max_offsets: int,
) -> Dict[str, Any]:
    """Shape a :class:`KeyLocationResult` into the wire payload.

    Shared so :func:`export_key_pattern` can nest the IDENTICAL block under
    ``location`` — one shape for "where is this key", whether it was asked
    directly or as the first half of an export.

    The needle bytes are deliberately NOT echoed. The caller already holds them
    (they supplied them), and this payload is what gets pasted into tickets,
    agent transcripts and CI logs. ``needle_sha256`` correlates two results
    without disclosing anything, and ``client_random`` is public handshake
    material that identifies the session.
    """
    return {
        "verdict": result.verdict,
        "input_form": input_form,
        "secret_type": secret_type,
        "client_random": client_random,
        "needle_length": len(needle),
        "needle_sha256": result.needle_sha256,
        "view": view,
        "dumps_total": result.dumps_total,
        "dumps_searched": result.dumps_searched,
        "dumps_present": result.dumps_present,
        "dumps_absent": result.dumps_absent,
        "dumps_unreadable": result.dumps_unreadable,
        "dumps_too_small": result.dumps_too_small,
        "unanimous": result.unanimous,
        "first_offset": result.first_offset,
        "offsets_agree": result.offsets_agree,
        "common_offset": result.common_offset,
        "dumps": [d.to_dict() for d in result.dumps],
        "elapsed_s": result.elapsed_s,
        "diagnostics": [
            d.to_dict()
            for d in _locate_key_diagnostics(result, max_offsets=max_offsets)
        ],
    }


def locate_key(
    *,
    dump_paths: Sequence[str],
    key_hex: str = "",
    keylog_line: str = "",
    secret: Optional[Dict[str, str]] = None,
    pcap_field: Optional[Dict[str, str]] = None,
    view: Optional[str] = None,
    max_offsets: int = DEFAULT_MAX_KEY_OFFSETS,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """Locate ONE known secret across N dumps, with an honest three-valued census.

    The single implementation behind the CLI ``locate-key`` command, the HTTP
    ``POST /api/analysis/locate-key`` route, the MCP ``locate_key`` tool and
    ``memdiver.services.locate_key``. The caller already HOLDS the secret — from
    a key log, a confirmed brute-force hit, or a paste into the key-log composer
    — and wants to know which dumps still contain it and where.

    Supply the secret in exactly ONE of four forms:

    * ``key_hex`` — bare hex bytes (``"aa bb cc"`` and ``"0xaabbcc"`` both work).
    * ``keylog_line`` — one NSS key-log row, ``"<LABEL> <client_random> <secret>"``.
      This form additionally reports ``secret_type`` and ``client_random``.
    * ``secret`` — a ``{secret_type, client_random, secret}`` dict, validated by
      the same helper ``export_keylog`` uses.
    * ``pcap_field`` — the SYMBOLIC form (C2):
      ``{"pcap_path": ..., "field_id": ..., "client_random": <optional>}``. The
      needle is read off the wire instead of pasted: ``field_id="client_random"``
      means *"whatever this capture's ClientHello.random actually is"*. Browse
      the available ids with ``inspect_pcap(include_fields=True)``. Only
      ``searchable`` fields are accepted — a 2-byte extension payload occurs
      everywhere in any real dump, so offering it as a needle could only produce
      a guaranteed false-positive sweep. ``secret_type`` carries the resolved
      ``field_id`` and ``client_random`` the session it came from; the
      ``input_form: "pcap_field"`` in the payload is what says to read the first
      as a field id rather than an NSS label.

    Zero or two-or-more forms is INVALID_INPUT, with no precedence between them
    — see :func:`_resolve_key_needle` for why silence would be worse.

    ONE dump is enough, unlike every sibling producer in this module. The
    >= 2 rule elsewhere exists because a cross-dump *comparison* of one dump is
    meaningless; "is this secret in this dump, and where" is a complete question
    about a single dump and the answer is the whole point of the capability.

    Nothing is PERSISTED and there is no ``project_id``. The only table this
    would fit is ``ground_truth``, and that table holds ORACLE-CONFIRMED hits: a
    key-log-derived location is corroborating evidence, not a confirmation, and
    filing it there would launder one into the other for every later query that
    trusts the ledger.

    Returns:
        A bare dict (not a ``ServiceResult``) carrying the verdict, the six
        per-status counts, the per-dump rows in the SUPPLIED order, and
        ``diagnostics``. Read ``verdict`` before any count: ``"not_searched"``
        claims NOTHING and must never be rendered as an absence.

    Raises:
        CapabilityError: PRECONDITION for an empty ``dump_paths``, INVALID_INPUT
            for the input-form and secret-parsing errors above.
        FileNotFoundServiceError: when any supplied dump does not exist.
        EncryptedDumpLockedError: for a locked encrypted container — every
            answer in the set would otherwise be a confident absence over bytes
            nobody decrypted.
    """
    # Function-local so the ``app`` layer does not pull ``engine`` at module
    # import time (the repo-wide idiom; see ``analyze_candidates``).
    from memdiver.engine.key_location import locate_key_across_dumps

    resolved = _resolve_key_needle(
        key_hex, keylog_line, secret, pcap_field,
        accepted_forms=LOCATE_KEY_INPUT_FORMS,
    )

    paths = [Path(p).expanduser() for p in dump_paths]
    if not paths:
        raise CapabilityError(
            "Need at least 1 dump to search, got 0",
            category=ErrorCategory.PRECONDITION,
        )
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")

    def _observe(source: Any) -> None:
        # A locked encrypted dump reads back EMPTY, which this producer would
        # otherwise report as a confident absence in every locked dump — the
        # single most misleading result it can return. Surface the lock, then
        # let the caller's own hook (the CLI's AEAD line) run.
        _raise_if_locked(source)
        if on_source is not None:
            on_source(source)

    km = _resolve_key_material(key_material, key_file, passphrase, kem_key_file)
    result = locate_key_across_dumps(
        [str(p) for p in paths],
        resolved.needle,
        view=view,
        key_material=km,
        max_offsets=max_offsets,
        on_source=_observe,
    )
    return _locate_key_payload(
        result,
        needle=resolved.needle,
        secret_type=resolved.secret_type,
        client_random=resolved.client_random,
        input_form=resolved.input_form,
        view=view,
        max_offsets=max_offsets,
    )


#: The keys ONE explicit ``pairs`` entry may carry. ``client_random`` is the
#: only optional one and does exactly the job it does in ``pcap_field``: it
#: picks one session out of a capture that holds several.
PCAP_PAIR_KEYS = ("dump_path", "pcap_path", "client_random")

#: How a pair's capture was arrived at. ``"unpaired"`` is a VALUE here, not an
#: absence: a dump whose capture could not be found is a row, because dropping
#: it would shrink the denominator every ratio in the result is computed over.
PAIRING_EXPLICIT = "explicit"
PAIRING_DISCOVERED = "discovered"
PAIRING_UNPAIRED = "unpaired"
PAIRINGS = (PAIRING_EXPLICIT, PAIRING_DISCOVERED, PAIRING_UNPAIRED)

#: What HAPPENED to a pair, three-valued for the same reason
#: :attr:`engine.key_location.DumpKeyLocation.status` is:
#:
#: * ``"searched"`` — a needle was resolved and the dump was read. ``location``
#:   is non-NULL and carries the honest per-dump verdict.
#: * ``"unpaired"`` — no capture belongs to this dump, so there was no needle to
#:   search for. ``location`` is NULL.
#: * ``"field_unresolved"`` — a capture was found but it does not yield the
#:   requested field (no session, no such id, or the id is not searchable).
#:   ``location`` is NULL.
#:
#: The last two are the whole point of the type. A pair that was never searched
#: rendered as a zero-hit row is an absence claim over bytes nobody read.
PAIR_SEARCHED = "searched"
PAIR_UNPAIRED = "unpaired"
PAIR_FIELD_UNRESOLVED = "field_unresolved"
PAIR_STATUSES = (PAIR_SEARCHED, PAIR_UNPAIRED, PAIR_FIELD_UNRESOLVED)

#: The field every real pairing hunt starts from: the ClientHello random is 32
#: bytes, unique per handshake, and present in every TLS version, which makes it
#: the one field that is both a usable needle and guaranteed to exist.
DEFAULT_PAIR_FIELD_ID = "client_random"

LOCATE_PAIRS_UNPAIRED_CODE = "analysis.locate_field_pairs.unpaired"
LOCATE_PAIRS_FIELD_UNRESOLVED_CODE = "analysis.locate_field_pairs.field_unresolved"
LOCATE_PAIRS_NOT_SEARCHED_CODE = "analysis.locate_field_pairs.not_searched"
LOCATE_PAIRS_ABSENT_CODE = "analysis.locate_field_pairs.absent"
LOCATE_PAIRS_PARTIAL_CODE = "analysis.locate_field_pairs.partial"
LOCATE_PAIRS_OFFSET_DRIFT_CODE = "analysis.locate_field_pairs.offset_drift"
LOCATE_PAIRS_SHARED_CAPTURE_CODE = "analysis.locate_field_pairs.shared_capture"


class _PcapPair(NamedTuple):
    """One ``(dump, capture)`` pairing, however it was arrived at.

    The single internal shape both input forms normalise into, so the search
    loop below cannot behave differently for an explicit pair than for a
    discovered one. ``pcap_path`` is ``""`` exactly when ``pairing`` is
    ``"unpaired"``.
    """

    dump_path: str
    pcap_path: str
    client_random: str
    pairing: str
    capture_status: str


def _normalise_explicit_pairs(
    pairs: Sequence[Mapping[str, str]],
) -> List[_PcapPair]:
    """Validate the explicit ``pairs`` form into :class:`_PcapPair` records.

    Every entry is checked BEFORE anything is read, so a typo in pair 9 is
    reported instead of arriving after eight dumps have been swept. An unknown
    key is refused by name rather than ignored, mirroring
    :func:`_needle_from_pcap_field`'s guard over :data:`PCAP_FIELD_KEYS`: a
    misspelt ``pcap`` silently dropped would leave the pair looking unpaired,
    which reads as a finding about the corpus rather than a mistake in the
    request.

    ``capture_status`` is ``"supplied"`` on this path — the caller asserted the
    pairing, so there is no probe whose three-state verdict could be reported.
    """
    normalised: List[_PcapPair] = []
    for index, entry in enumerate(pairs):
        if not isinstance(entry, Mapping):
            raise CapabilityError(
                f"pairs[{index}] is {type(entry).__name__}, expected a mapping "
                f"{{'dump_path': ..., 'pcap_path': ...}}",
                category=ErrorCategory.INVALID_INPUT,
            )
        unknown = [key for key in entry if key not in PCAP_PAIR_KEYS]
        if unknown:
            raise CapabilityError(
                f"pairs[{index}] has unknown key(s) {sorted(unknown)}; expected "
                f"{list(PCAP_PAIR_KEYS)} (client_random optional)",
                category=ErrorCategory.INVALID_INPUT,
            )
        dump_path = str(entry.get("dump_path") or "").strip()
        pcap_path = str(entry.get("pcap_path") or "").strip()
        missing = [name for name, value in
                   (("dump_path", dump_path), ("pcap_path", pcap_path))
                   if not value]
        if missing:
            raise CapabilityError(
                f"pairs[{index}] is missing required key(s) {missing}; each "
                f"pair takes {{'dump_path': ..., 'pcap_path': ..., "
                f"'client_random': <optional>}}",
                category=ErrorCategory.INVALID_INPUT,
            )
        normalised.append(_PcapPair(
            dump_path=dump_path,
            pcap_path=pcap_path,
            client_random=str(entry.get("client_random") or "").strip(),
            pairing=PAIRING_EXPLICIT,
            capture_status="supplied",
        ))
    return normalised


def _discover_pcap_pairs(dump_paths: Sequence[str]) -> List[_PcapPair]:
    """Let each dump find its OWN capture, via the run-discovery walker.

    The pairing this producer exists for: N dumps go in, and each comes back
    matched to the capture of the run it belongs to — not to one capture chosen
    for all of them. The probe is
    :meth:`core.discovery.RunDiscovery.find_capture_for`, i.e. the SAME
    ``_find_capture`` the dataset scanner uses, so a dump and its run can never
    disagree about which capture is theirs.

    A dump with no capture becomes a ``"unpaired"`` record rather than being
    dropped. ``capture_status`` carries the walker's own three-state verdict, so
    ``"absent"`` (there is no capture here) stays distinguishable from
    ``"unreadable"`` (there is one and we could not use it) — a zero-byte
    ``traffic.pcap`` is a corpus defect, not a corpus fact.
    """
    # Function-local, matching every other engine/core import in this module.
    from memdiver.core.discovery import RunDiscovery

    pairs: List[_PcapPair] = []
    for dump_path in dump_paths:
        capture, status = RunDiscovery.find_capture_for(dump_path)
        if capture is None or status != "present":
            pairs.append(_PcapPair(
                dump_path=dump_path,
                pcap_path="" if capture is None else str(capture),
                client_random="",
                pairing=PAIRING_UNPAIRED,
                capture_status=status,
            ))
            continue
        pairs.append(_PcapPair(
            dump_path=dump_path,
            pcap_path=str(capture),
            client_random="",
            pairing=PAIRING_DISCOVERED,
            capture_status=status,
        ))
    return pairs


def _resolve_pair_inputs(
    pairs: Optional[Sequence[Mapping[str, str]]],
    dump_paths: Optional[Sequence[str]],
) -> Tuple[List[_PcapPair], str]:
    """Take EXACTLY ONE of the two input forms and normalise it.

    The same discipline — and for the same reason — as
    :func:`_resolve_key_needle`'s exactly-one-of guard. There is deliberately no
    precedence: a caller sending ``pairs`` together with ``dump_paths`` believes
    something specific about which capture each dump will be matched against,
    and honouring one of them silently would produce a fully-populated,
    confident census against the wrong captures. Refusing costs one round trip.

    Returns ``(pairs, mode)`` where mode is ``"explicit"`` or ``"discovery"``.
    """
    supplied = [name for name, value in
                (("pairs", pairs), ("dump_paths", dump_paths))
                if value is not None]
    if len(supplied) != 1:
        raise CapabilityError(
            f"Supply exactly ONE of ['pairs', 'dump_paths']; got "
            f"{supplied or 'none'}. 'pairs' names the capture for each dump "
            f"explicitly; 'dump_paths' lets each dump discover its own run's "
            f"capture. There is no precedence between them on purpose: the two "
            f"forms disagreeing about a pairing would yield a confident census "
            f"read from the wrong capture.",
            category=ErrorCategory.INVALID_INPUT,
        )
    if pairs is not None:
        if not pairs:
            raise CapabilityError(
                "Need at least 1 (dump, pcap) pair to search, got 0",
                category=ErrorCategory.PRECONDITION,
            )
        return _normalise_explicit_pairs(pairs), "explicit"
    resolved = list(dump_paths or [])
    if not resolved:
        raise CapabilityError(
            "Need at least 1 dump to search, got 0",
            category=ErrorCategory.PRECONDITION,
        )
    return _discover_pcap_pairs(resolved), "discovery"


def _pair_row(
    pair: _PcapPair,
    *,
    field_id: str,
    status: str,
    needle_hex: str = "",
    detail: str = "",
    location: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble ONE pair row, with the status/location biconditional enforced.

    ``location`` is non-NULL if and ONLY IF ``status == "searched"``. That is the
    same invariant :meth:`engine.key_location.DumpKeyLocation.__post_init__`
    enforces over ``status`` / ``present``, lifted one level up: a ``location``
    on an unsearched pair is a census over bytes nobody read, and a NULL one on
    a searched pair is a row that contributes to neither a presence nor an
    absence in the consumer that renders it.

    Unlike :func:`_locate_key_payload`, this DOES echo ``needle_hex``. The
    contrast is deliberate and is the same distinction ``export_key_pattern``
    draws when it refuses the ``pcap_field`` form: a handshake field is public
    wire material, so disclosing it in a ticket or an agent transcript leaks
    nothing, and it is the one value that makes the row reproducible — without
    it a reader cannot tell whether two pairs searched for the same bytes.
    ``""`` means no needle was resolved, never "the empty needle".
    """
    if status not in PAIR_STATUSES:
        raise ValueError(
            "unknown pair status " + repr(status) + "; expected one of "
            + ", ".join(repr(s) for s in PAIR_STATUSES))
    if (status == PAIR_SEARCHED) != (location is not None):
        raise ValueError(
            "pair status " + repr(status) + " contradicts location "
            + ("present" if location is not None else "NULL") + " for "
            + repr(pair.dump_path))
    return {
        "dump_path": pair.dump_path,
        "dump_name": Path(pair.dump_path).name,
        "pcap_path": pair.pcap_path,
        "pairing": pair.pairing,
        "capture_status": pair.capture_status,
        "field_id": field_id,
        "needle_hex": needle_hex,
        "status": status,
        "detail": detail,
        "location": location,
    }


def _locate_field_pairs_diagnostics(
    rows: Sequence[Dict[str, Any]],
    *,
    verdict: str,
    field_id: str,
    pairs_present: int,
    pairs_absent: int,
    captures: Sequence[str],
    first_offsets: Sequence[int],
) -> List[Diagnostic]:
    """The honest qualifications on one paired-field search.

    Every one is a QUALIFICATION, not an error, exactly as in
    :func:`_locate_key_diagnostics`: the census is already computed and the
    caller is entitled to it. What these encode is the gap between the verdict
    and what the pairing actually supports.
    """
    diagnostics: List[Diagnostic] = []
    total = len(rows)

    unpaired = [r for r in rows if r["status"] == PAIR_UNPAIRED]
    if unpaired:
        diagnostics.append(Diagnostic(
            code=LOCATE_PAIRS_UNPAIRED_CODE,
            message=(
                f"{len(unpaired)} of {total} dump(s) have no capture to take a "
                f"needle from ("
                + "; ".join(
                    f"{r['dump_name']}: {r['capture_status']}"
                    for r in unpaired[:5])
                + f"). They were never searched, so their content is UNKNOWN "
                f"for {field_id!r} — not absent."
            ),
            severity=Severity.WARNING,
            details={
                "pairs_unpaired": len(unpaired),
                "pairs_total": total,
                "capture_statuses": {
                    r["dump_path"]: r["capture_status"] for r in unpaired
                },
            },
        ))

    unresolved = [r for r in rows if r["status"] == PAIR_FIELD_UNRESOLVED]
    if unresolved:
        diagnostics.append(Diagnostic(
            code=LOCATE_PAIRS_FIELD_UNRESOLVED_CODE,
            message=(
                f"{len(unresolved)} of {total} pair(s) have a capture that "
                f"yields no usable {field_id!r} ("
                + "; ".join(
                    f"{r['dump_name']}: {r['detail']}" for r in unresolved[:3])
                + "). Their needle_hex is empty and no search was run, so these "
                "are not absences."
            ),
            severity=Severity.WARNING,
            details={
                "pairs_field_unresolved": len(unresolved),
                "pairs_total": total,
                "details": {r["dump_path"]: r["detail"] for r in unresolved},
            },
        ))

    if verdict == "not_searched":
        diagnostics.append(Diagnostic(
            code=LOCATE_PAIRS_NOT_SEARCHED_CODE,
            message=(
                f"NOTHING was searched: none of the {total} pair(s) produced "
                f"both a needle and a readable dump. This result claims no "
                f"presence and no absence — fix the pairing before reading it "
                f"as a finding."
            ),
            severity=Severity.WARNING,
            details={"pairs_total": total},
        ))
    elif verdict == "absent":
        diagnostics.append(Diagnostic(
            code=LOCATE_PAIRS_ABSENT_CODE,
            message=(
                f"Each searched dump was read for the {field_id!r} of ITS OWN "
                f"capture, and none of the {pairs_absent} contains it. That is "
                f"a measured absence over a known denominator, not a failure "
                f"to look."
            ),
            severity=Severity.INFO,
            details={"pairs_absent": pairs_absent},
        ))
    elif pairs_absent:
        diagnostics.append(Diagnostic(
            code=LOCATE_PAIRS_PARTIAL_CODE,
            message=(
                f"{field_id!r} survives in {pairs_present} of the "
                f"{pairs_present + pairs_absent} searched dump(s) and is "
                f"provably absent from {pairs_absent}. Partial survival is the "
                f"normal shape of a real value across a process lifecycle — "
                f"the absent dumps are evidence, not a shortfall."
            ),
            severity=Severity.INFO,
            details={
                "pairs_present": pairs_present,
                "pairs_absent": pairs_absent,
                "present_dumps": [
                    r["dump_path"] for r in rows
                    if r["location"] and r["location"]["verdict"] == "found"
                ],
            },
        ))

    distinct_captures = sorted({c for c in captures if c})
    if len(distinct_captures) == 1 and total > 1:
        diagnostics.append(Diagnostic(
            code=LOCATE_PAIRS_SHARED_CAPTURE_CODE,
            message=(
                f"All {total} pair(s) resolved to the SAME capture "
                f"({Path(distinct_captures[0]).name}), so this is one session's "
                f"{field_id!r} traced across N dumps — not N independently "
                f"paired sessions. The per-dump verdicts are still per-dump; "
                f"only the needle is shared."
            ),
            severity=Severity.INFO,
            details={"capture": distinct_captures[0], "pairs_total": total},
        ))

    if len(set(first_offsets)) > 1:
        diagnostics.append(Diagnostic(
            code=LOCATE_PAIRS_OFFSET_DRIFT_CODE,
            message=(
                f"The field sits at DIFFERENT offsets across the "
                f"{len(first_offsets)} dump(s) that hold it "
                f"({sorted(set(first_offsets))}). No single offset "
                f"generalises, so an offset-based rule derived from one of "
                f"them will not locate it in the others."
            ),
            severity=Severity.INFO,
            details={
                "first_offsets": {
                    r["dump_path"]: r["location"]["first_offset"]
                    for r in rows
                    if r["location"] and r["location"]["first_offset"] is not None
                },
            },
        ))
    return diagnostics


def locate_field_across_pairs(
    *,
    pairs: Optional[Sequence[Dict[str, str]]] = None,
    dump_paths: Optional[Sequence[str]] = None,
    field_id: str = DEFAULT_PAIR_FIELD_ID,
    view: Optional[str] = None,
    max_offsets: int = DEFAULT_MAX_KEY_OFFSETS,
    pcap_max_records: Optional[int] = None,
    pcap_max_challenges: Optional[int] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """Search N dumps for a handshake field, each dump taking it from ITS OWN capture.

    The single implementation behind the CLI ``locate-field-pairs`` command, the
    HTTP ``POST /api/pcaps/locate-field`` route, the MCP
    ``locate_field_across_pairs`` tool and
    ``memdiver.services.locate_field_across_pairs``.

    :func:`locate_key` already searches N dumps — for ONE needle. That is the
    right question when a single session is under investigation and the wrong
    one for a corpus: 40 runs of the same client each negotiated their own
    handshake, so "is *this* client random in these 400 dumps" answers about 39
    runs it was never in. This producer asks the question that scales instead:
    *for each dump, is the ``field_id`` of the capture that belongs to that dump
    present in it, and where?* The needle varies per pair; the verdict is over
    the pairs.

    Supply the pairing in exactly ONE of two forms:

    * ``pairs`` — explicit: ``[{"dump_path": ..., "pcap_path": ...,
      "client_random": <optional>}, ...]``. The caller asserts each pairing, and
      ``client_random`` picks a session when a capture holds several.
    * ``dump_paths`` — discovery: each dump finds the capture of the run it
      lives in, via :meth:`core.discovery.RunDiscovery.find_capture_for` (the
      same ``_find_capture`` probe the dataset scanner uses:
      ``meta.capture``, then ``run_data/traffic.pcap*``, then a capture sitting
      beside the dumps).

    Both forms is INVALID_INPUT with no precedence — see
    :func:`_resolve_pair_inputs`.

    NO KEY LOG IS READ. That is the point of the capability, and it is what
    separates it from ``app.pipeline.corpus_pcap_runner.prove_run`` (which stays
    keylog-driven): the needle comes off the wire, so the search works on a
    corpus that ships captures but no ground truth. Only ``searchable`` fields
    are accepted, and that gate is C2's — a short field or a wire-encoding
    artifact matches everywhere, so a hit on one carries no information.

    Nothing is PERSISTED, for the same reason :func:`locate_key` persists
    nothing: the only table this would fit holds ORACLE-CONFIRMED hits, and a
    handshake field found in memory is a location, not a confirmation.

    Returns:
        A bare dict carrying ``verdict``, ``counts``, one row per pair in the
        SUPPLIED (or discovered) order, and ``diagnostics``. Read ``verdict``
        before any count: ``"not_searched"`` claims NOTHING.

        Each row carries ``pairing`` (``"explicit"`` / ``"discovered"`` /
        ``"unpaired"``), ``capture_status``, the resolved ``needle_hex``, a
        three-valued ``status`` (see :data:`PAIR_STATUSES`) and — only when that
        status is ``"searched"`` — a ``location`` block in exactly
        :func:`locate_key`'s shape, over that one dump.

    Raises:
        CapabilityError: INVALID_INPUT for zero or both input forms and for a
            malformed ``pairs`` entry; PRECONDITION for an empty sequence.
        FileNotFoundServiceError: when any supplied dump — or any explicitly
            paired capture — does not exist. Checked up front, so a typo is
            reported before N dumps are swept.
        EncryptedDumpLockedError: for a locked encrypted container; every
            answer in the set would otherwise be a confident absence over bytes
            nobody decrypted.
    """
    # Function-local so the ``app`` layer does not pull ``engine`` at module
    # import time (the repo-wide idiom; see ``locate_key``). ELAPSED_PRECISION
    # is imported rather than re-literalled so this producer's ``elapsed_s``
    # rounds exactly as every per-pair ``location.elapsed_s`` inside it does.
    from memdiver.engine.key_location import (
        ELAPSED_PRECISION,
        locate_key_across_dumps,
    )

    _validate_pcap_caps(pcap_max_records, pcap_max_challenges)
    resolved_field_id = field_id.strip()
    if not resolved_field_id:
        raise CapabilityError(
            "Empty field_id; name the handshake field to search for (browse "
            "them with inspect_pcap(include_fields=True))",
            category=ErrorCategory.INVALID_INPUT,
        )
    pair_records, mode = _resolve_pair_inputs(pairs, dump_paths)

    # Existence up front, over BOTH sides of every pair, so a mistyped path is
    # a NOT_FOUND rather than eight sweeps followed by one. Same posture as
    # ``locate_key``; a discovered capture is skipped here because the walker
    # already classified it (an "unreadable" one becomes an unpaired row).
    missing = [p.dump_path for p in pair_records
               if not Path(p.dump_path).expanduser().exists()]
    missing += [p.pcap_path for p in pair_records
                if p.pairing == PAIRING_EXPLICIT
                and not Path(p.pcap_path).expanduser().exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")

    def _observe(source: Any) -> None:
        # A locked encrypted dump reads back EMPTY, which would otherwise be
        # reported as a confident absence in every locked dump.
        _raise_if_locked(source)
        if on_source is not None:
            on_source(source)

    km = _resolve_key_material(key_material, key_file, passphrase, kem_key_file)
    started = time.perf_counter()
    rows: List[Dict[str, Any]] = []
    # Memoised per CALL, not globally: N dumps of one run share one capture, and
    # ``inspect_pcap(include_fields=True)`` re-reads the file every time, so
    # without this a 10-dump run parses the same 6 KB capture ten times. The key
    # includes the session selector because two pairs may legitimately name
    # different sessions of the SAME capture.
    needles: Dict[Tuple[str, str], Any] = {}

    for pair in pair_records:
        if pair.pairing == PAIRING_UNPAIRED:
            rows.append(_pair_row(
                pair, field_id=resolved_field_id, status=PAIR_UNPAIRED,
                detail=(
                    f"no capture for this dump's run "
                    f"(capture_status={pair.capture_status})"),
            ))
            continue

        cache_key = (str(Path(pair.pcap_path).expanduser()), pair.client_random)
        if cache_key not in needles:
            request = {"pcap_path": pair.pcap_path, "field_id": resolved_field_id}
            if pair.client_random:
                request["client_random"] = pair.client_random
            try:
                needles[cache_key] = _needle_from_pcap_field(
                    request,
                    pcap_max_records=pcap_max_records,
                    pcap_max_challenges=pcap_max_challenges,
                )
            except CapabilityError as exc:
                # CAUGHT, not propagated. One capture that lacks the field is a
                # fact about that pair; raising would discard the census for
                # every other pair in the set, which is the same
                # all-or-nothing failure the three-valued row model exists to
                # avoid. The resolver's own message is carried through verbatim
                # so the remedy (a different field_id, a client_random
                # selector) reads identically to ``locate_key``'s.
                needles[cache_key] = exc
        cached = needles[cache_key]
        if isinstance(cached, CapabilityError):
            rows.append(_pair_row(
                pair, field_id=resolved_field_id,
                status=PAIR_FIELD_UNRESOLVED, detail=str(cached),
            ))
            continue

        needle, resolved_id, session_random = cached
        result = locate_key_across_dumps(
            [pair.dump_path],
            needle,
            view=view,
            key_material=km,
            max_offsets=max_offsets,
            on_source=_observe,
        )
        rows.append(_pair_row(
            pair, field_id=resolved_field_id, status=PAIR_SEARCHED,
            needle_hex=needle.hex(),
            location=_locate_key_payload(
                result,
                needle=needle,
                # ``secret_type`` carries the resolved field id and
                # ``input_form`` says to read it as one — the same convention
                # ``locate_key``'s pcap_field form uses, so a reader parses one
                # ``location`` block, not two.
                secret_type=resolved_id,
                client_random=session_random,
                input_form="pcap_field",
                view=view,
                max_offsets=max_offsets,
            ),
        ))

    searched = [r for r in rows if r["status"] == PAIR_SEARCHED]
    present = [r for r in searched if r["location"]["verdict"] == "found"]
    absent = [r for r in searched if r["location"]["verdict"] == "absent"]
    dumps_searched = sum(r["location"]["dumps_searched"] for r in searched)
    # Verdict, in the SAME three-valued vocabulary
    # ``engine.key_location.KEY_LOCATION_VERDICTS`` uses, so a consumer that
    # already renders a ``locate_key`` verdict renders this one unchanged.
    # ``dumps_searched`` and not ``len(searched)`` gates the absence: a pair can
    # hold a needle and still read nothing (an unreadable or too-small dump).
    if present:
        verdict = "found"
    elif dumps_searched:
        verdict = "absent"
    else:
        verdict = "not_searched"

    first_offsets = [r["location"]["first_offset"] for r in present
                     if r["location"]["first_offset"] is not None]
    return {
        "verdict": verdict,
        "mode": mode,
        "field_id": resolved_field_id,
        "view": view,
        "caps": {
            "pcap_max_records": pcap_max_records,
            "pcap_max_challenges": pcap_max_challenges,
        },
        "counts": {
            "pairs_total": len(rows),
            "pairs_searched": len(searched),
            "pairs_unpaired": sum(
                1 for r in rows if r["status"] == PAIR_UNPAIRED),
            "pairs_field_unresolved": sum(
                1 for r in rows if r["status"] == PAIR_FIELD_UNRESOLVED),
            "pairs_present": len(present),
            "pairs_absent": len(absent),
            "dumps_searched": dumps_searched,
            "dumps_unreadable": sum(
                r["location"]["dumps_unreadable"] for r in searched),
            "dumps_too_small": sum(
                r["location"]["dumps_too_small"] for r in searched),
            # The two facts that say whether this was a real PAIRING or one
            # needle wearing N hats: how many distinct captures were consulted,
            # and how many distinct needles they yielded.
            "captures_distinct": len({r["pcap_path"] for r in rows
                                      if r["pcap_path"]}),
            "needles_distinct": len({r["needle_hex"] for r in rows
                                     if r["needle_hex"]}),
        },
        # Only meaningful across pairs that FOUND the field; ``None`` /``False``
        # when fewer than two did, exactly as ``KeyLocationResult`` treats them.
        "offsets_agree": len(set(first_offsets)) <= 1,
        "common_offset": (
            first_offsets[0] if len(set(first_offsets)) == 1 else None),
        "pairs": rows,
        "elapsed_s": round(time.perf_counter() - started, ELAPSED_PRECISION),
        "diagnostics": [
            d.to_dict() for d in _locate_field_pairs_diagnostics(
                rows,
                verdict=verdict,
                field_id=resolved_field_id,
                pairs_present=len(present),
                pairs_absent=len(absent),
                captures=[r["pcap_path"] for r in rows],
                first_offsets=first_offsets,
            )
        ],
    }


def _key_pattern_anchors(result: Any) -> Dict[str, int]:
    """Pick ONE occurrence per present dump — the one nearest the modal offset.

    A dump may hold several real copies of the secret (key schedule + record
    layer). The window comparison is positional, so the N windows must be
    anchored on CORRESPONDING copies; anchoring dump A on its key-schedule copy
    and dump B on its record-layer copy compares two unrelated structures and
    reports their surroundings as volatile.

    The modal offset is the offset the most dumps agree on (ties broken toward
    the lower offset, so the choice is deterministic), and each dump then
    contributes its own occurrence CLOSEST to it (ties again toward the lower).
    Where every dump has exactly one hit — the real-corpus case — this reduces
    to "first hit", identically to ``KeyLocationResult.anchor_offsets``.
    """
    frequency: Counter = Counter()
    for row in result.present:
        frequency.update(row.offsets)
    modal = min(frequency, key=lambda o: (-frequency[o], o))
    return {
        row.dump_path: min(row.offsets, key=lambda o: (abs(o - modal), o))
        for row in result.present
    }


def export_key_pattern(
    *,
    dump_paths: Sequence[str],
    key_hex: str = "",
    keylog_line: str = "",
    secret: Optional[Dict[str, str]] = None,
    context: int = DEFAULT_KEY_CONTEXT,
    fmt: str = "volatility3",
    name: str = "memdiver_key_pattern",
    min_static_ratio: float = 0.3,
    view: Optional[str] = None,
    output_dir: Optional[str] = None,
    include_window_hex: bool = False,
    max_offsets: int = DEFAULT_MAX_KEY_OFFSETS,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """Export a scanning signature ANCHORED on an already-known secret.

    The single implementation behind the CLI ``export-key-pattern`` command, the
    HTTP ``POST /api/analysis/key-pattern`` route, the MCP
    ``export_key_pattern`` tool and ``memdiver.services.export_key_pattern``.

    ``export_pattern`` guesses WHERE the key is (largest volatile region) and
    then describes it. This producer is handed the key, locates it per dump, and
    describes its NEIGHBOURHOOD — which is the artifact a Volatility/YARA
    consumer actually needs, because the key bytes themselves are what the rule
    must wildcard.

    How the mask set is chosen, because it is the whole trick
    --------------------------------------------------------
    The static mask is computed over EVERY searched dump — the ones that hold
    the key AND the ones that provably do not. That is measured, not stylistic.
    On the reference 8-dump OpenSSL TLS 1.2 run the key survives in 2 dumps; a
    mask over those 2 is 100 % static and the emitted rule embeds the secret
    verbatim with no wildcard at all, matching that one key and nothing else.
    A mask over all 8 wildcards exactly the 48 key bytes (128 of 176 static) and
    generalises. The six wiped dumps ARE the wildcard mechanism.

    An absent dump has no occurrence of its own to anchor on, so it can only
    join by borrowing the shared offset — which exists only when
    ``offsets_agree``. Under drift the absent dumps are EXCLUDED (and
    ``mask_subset`` + ``offset_drift`` say so) rather than masked at an offset
    that means nothing in them.

    Padding is COMMON to every dump in the mask set, never clamped per dump: a
    dump near a view boundary that got less left padding would place the key at
    a different index inside its window, and the positional byte-wise comparison
    would then be comparing the key against its own context.

    Diagnostics, not refusals
    -------------------------
    ``key_fully_static`` (WARNING) fires when the key span carries no wildcard
    at all. Nothing else notices this: ``min_static_ratio`` is a LOWER bound, so
    a 100 %-static window sails through, and all three exporters render only
    ``wildcard_pattern`` — so the rule quietly ships the raw secret. See also
    ``degenerate_anchors``, which fires at the default context on the real
    corpus key (its surroundings are zeros). Both WARN and still return the
    pattern: a weak signature an analyst can see beats a refusal they cannot.

    Returns:
        ``format`` / ``content`` / ``pattern`` (and ``pattern_path`` when
        ``output_dir`` is set) exactly as ``export_pattern`` does, plus
        ``region``, the top-level ``offsets_agree``, the key-span static counts,
        the mask-set census, ``windows``, the nested ``location`` block, and
        ``diagnostics``.

    Raises:
        CapabilityError: PRECONDITION for fewer than 2 dumps or a verdict of
            ``not_searched``, INVALID_INPUT for a negative ``context`` and the
            input-form errors, UNSUPPORTED for an unknown ``fmt``.
        KeyNotFoundError: (404/NOT_FOUND) when the key is provably absent from
            every searched dump. Deliberately NOT ``InsufficientStaticError``,
            which would blame the data for a missing key.
        FileNotFoundServiceError: when any supplied dump does not exist.
    """
    from memdiver.app import export_service
    from memdiver.architect.pattern_generator import PatternGenerator
    from memdiver.engine.key_location import locate_key_across_dumps

    resolved = _resolve_key_needle(key_hex, keylog_line, secret)
    needle_length = len(resolved.needle)

    paths = [Path(p).expanduser() for p in dump_paths]
    if len(paths) < 2:
        # Unlike ``locate_key``, which answers a single-dump question, a STATIC
        # MASK is a comparison: ``StaticChecker.check_regions`` over one region
        # never enters its loop and returns all-True, i.e. a silent
        # ``static_ratio == 1.0`` and a perfect-looking rule from one dump.
        raise CapabilityError(
            f"Need at least 2 dumps to measure a static mask, got {len(paths)}",
            category=ErrorCategory.PRECONDITION,
        )
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")
    if fmt.lower() not in export_service.SUPPORTED_FORMATS:
        raise export_service.UnknownFormatError(fmt)
    if context < 0:
        raise CapabilityError(
            f"context must be non-negative, got {context}",
            category=ErrorCategory.INVALID_INPUT,
        )

    def _observe(source: Any) -> None:
        _raise_if_locked(source)
        if on_source is not None:
            on_source(source)

    km = _resolve_key_material(key_material, key_file, passphrase, kem_key_file)
    # The ENGINE function, not ``locate_key``: a producer calling a producer
    # would shape the payload twice and nest a ``diagnostics`` list inside a
    # ``diagnostics`` list. The shared payload helper is reused instead.
    result = locate_key_across_dumps(
        [str(p) for p in paths],
        resolved.needle,
        view=view,
        key_material=km,
        max_offsets=max_offsets,
        on_source=_observe,
    )
    location = _locate_key_payload(
        result,
        needle=resolved.needle,
        secret_type=resolved.secret_type,
        client_random=resolved.client_random,
        input_form=resolved.input_form,
        view=view,
        max_offsets=max_offsets,
    )

    # -- gate on the verdict, with a DISTINCT error for each of the three ---
    if result.verdict == "not_searched":
        # Nothing was read at all. A static-ratio complaint here would blame
        # the data for what is an access problem.
        raise CapabilityError(
            f"None of the {result.dumps_total} dumps could be searched, so the "
            f"key's location is unknown — not absent. Fix the inputs listed in "
            f"details and retry.",
            category=ErrorCategory.PRECONDITION,
            details={"verdict": result.verdict, "dumps": {
                d.dump_path: (d.status + (f": {d.detail}" if d.detail else ""))
                for d in result.dumps}},
        )
    if result.verdict == "absent":
        raise export_service.KeyNotFoundError(
            f"The secret is absent from all {result.dumps_searched} searched "
            f"dumps, so there is no location to anchor a pattern on.",
            verdict=result.verdict,
        )

    # -- anchor + mask set --------------------------------------------------
    anchors = _key_pattern_anchors(result)
    present_rows = list(result.present)
    mask_rows = list(present_rows)
    excluded: List[str] = [
        d.dump_path for d in result.dumps if not d.searched
    ]
    if result.offsets_agree:
        common = int(result.common_offset or 0)
        for row in result.absent:
            anchors[row.dump_path] = common
            mask_rows.append(row)
    else:
        excluded.extend(d.dump_path for d in result.absent)

    # REFERENCE DUMP FIRST: ``StaticChecker.check_regions`` takes ``regions[0]``
    # as its reference, so ``hex_pattern`` (and the YARA key meta) would not
    # hold the key at all if a dump that lacks it led the list.
    reference_row = present_rows[0]
    in_mask = {id(r) for r in mask_rows}
    ordered = [reference_row] + [
        d for d in result.dumps if id(d) in in_mask and d is not reference_row
    ]

    # -- COMMON padding, feasible for every dump in the mask set -----------
    pad_left = min(min(context, anchors[d.dump_path]) for d in ordered)
    pad_right = max(0, min(
        min(context, d.size_for_view - (anchors[d.dump_path] + needle_length))
        for d in ordered))
    window_length = pad_left + needle_length + pad_right

    windows = [(d.dump_path, anchors[d.dump_path] - pad_left) for d in ordered]
    export = export_service.located_export_pattern(
        windows,
        window_length,
        key_offset=pad_left,
        key_length=needle_length,
        fmt=fmt,
        name=name,
        min_static_ratio=min_static_ratio,
        key_material=km,
        view=view,
        return_regions=include_window_hex,
    )

    static_mask = export["static_mask"]
    key_static_count = sum(
        1 for flag in static_mask[pad_left:pad_left + needle_length] if flag)
    key_wildcard_count = needle_length - key_static_count

    payload = _export_payload(export, name=name, output_dir=output_dir)
    region = dict(payload["region"])
    region.update({
        "key_offset_in_pattern": pad_left,
        "context_requested": int(context),
        "context_before": pad_left,
        "context_after": pad_right,
    })
    payload["region"] = region
    # HOISTED to the top level because it decides whether ``region.offset`` is
    # usable at all: under drift that offset is the REFERENCE dump's window
    # start and generalises to nothing. ``ArchitectPlaceholder.tsx``'s
    # ``runAutoExport`` already reads ``region.offset`` straight into a hex-view
    # highlight, so a consumer must be able to see the caveat without walking
    # into ``location``.
    payload["offsets_agree"] = result.offsets_agree
    payload["key_static_count"] = key_static_count
    payload["key_wildcard_count"] = key_wildcard_count
    payload["mask_regions"] = len(ordered)
    payload["mask_dumps_present"] = len(present_rows)
    payload["mask_dumps_absent"] = len(ordered) - len(present_rows)
    payload["excluded_dumps"] = excluded

    regions = export.get("regions") or []
    window_rows: List[Dict[str, Any]] = []
    for index, row in enumerate(ordered):
        entry: Dict[str, Any] = {
            "dump_path": row.dump_path,
            "name": row.name,
            "window_start": anchors[row.dump_path] - pad_left,
            "key_start": anchors[row.dump_path],
            "present": row.present is True,
            "reference": row is reference_row,
        }
        if include_window_hex and index < len(regions):
            entry["hex"] = bytes(regions[index]).hex()
        window_rows.append(entry)
    payload["windows"] = window_rows
    payload["location"] = location

    diagnostics: List[Diagnostic] = []
    if key_wildcard_count == 0:
        diagnostics.append(Diagnostic(
            code=KEY_PATTERN_STATIC_KEY_CODE,
            message=(
                f"All {needle_length} key bytes came out STATIC, so the "
                f"exported rule contains the secret verbatim and will match "
                f"this one key and nothing else. Every dump in the mask set "
                f"holds the same bytes at the anchor, so there was nothing to "
                f"wildcard. Add dumps in which the key is ABSENT (a later "
                f"lifecycle phase, or a run of the same binary without this "
                f"session) — those are what turn the key span into '??'."
            ),
            severity=Severity.WARNING,
            details={
                "key_static_count": key_static_count,
                "mask_regions": len(ordered),
                "mask_dumps_absent": len(ordered) - len(present_rows),
            },
        ))

    distinctiveness = PatternGenerator.anchor_distinctiveness(
        bytes.fromhex(export["pattern"]["hex_pattern"].replace(" ", "")),
        static_mask,
    )
    if (distinctiveness["distinct_bytes"] < KEY_PATTERN_MIN_ANCHOR_BYTES
            or distinctiveness["shannon_bits"] < KEY_PATTERN_MIN_ANCHOR_BITS):
        diagnostics.append(Diagnostic(
            code=KEY_PATTERN_DEGENERATE_ANCHORS_CODE,
            message=(
                f"The static anchors carry only "
                f"{distinctiveness['distinct_bytes']} distinct byte value(s) "
                f"({distinctiveness['shannon_bits']} bits/byte, longest "
                f"constant run {distinctiveness['longest_constant_run']}), so "
                f"this rule will match almost anywhere. On the reference "
                f"corpus the real key's surroundings are zeros, and the "
                f"resulting rule matches 5,311 positions in its own source "
                f"dump. Raise --context until the window reaches structural "
                f"bytes, or combine this pattern with a coarser locator."
            ),
            severity=Severity.WARNING,
            details=dict(distinctiveness),
        ))

    if len(ordered) < result.dumps_total:
        diagnostics.append(Diagnostic(
            code=KEY_PATTERN_SUBSET_CODE,
            message=(
                f"The static mask was measured over {len(ordered)} of "
                f"{result.dumps_total} dumps; {len(excluded)} were excluded "
                f"("
                + ("the key sits at different offsets, so a dump that lacks it "
                   "has no offset to borrow" if not result.offsets_agree
                   else "never searched, so nothing is known about them")
                + "). Fewer dumps in the mask means fewer wildcards, and a "
                "pattern that generalises less than the count suggests."
            ),
            severity=Severity.INFO,
            details={
                "mask_regions": len(ordered),
                "dumps_total": result.dumps_total,
                "excluded_dumps": excluded,
                "offsets_agree": result.offsets_agree,
            },
        ))

    if pad_left == 0 and pad_right == 0:
        diagnostics.append(Diagnostic(
            code=KEY_PATTERN_NO_ANCHORS_CODE,
            message=(
                f"The window is the key span alone (context_before = "
                f"context_after = 0 for context={context}), so the rule has no "
                f"static anchor OUTSIDE the key. Such a pattern can only match "
                f"the key bytes themselves, which is exactly what a scanning "
                f"signature must not rely on."
            ),
            severity=Severity.WARNING,
            details={"context_requested": int(context)},
        ))

    # The location diagnostics are carried into this list too, so one read of
    # ``diagnostics`` sees everything about the result — including
    # ``offset_drift``, which is what makes ``mask_subset`` above legible. The
    # locate-only subset stays available under ``location.diagnostics``.
    payload["diagnostics"] = location["diagnostics"] + [
        d.to_dict() for d in diagnostics]
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
# shared secret-dict validation  (export-keylog AND the key-location path)
# ----------------------------------------------------------------------


def _crypto_secret_from_dict(
    item: Any, *, index: Optional[int] = None,
) -> Any:
    """Validate one JSON secret dict into a :class:`CryptoSecret`.

    Extracted VERBATIM from :func:`keylog_result`'s inline loop body (the three
    guards and their exact wording are unchanged) so the key-location producers
    validate a ``secret=`` argument identically. Two producers with two copies
    of "is this secret_type canonical?" is how one of them ends up accepting a
    label Wireshark cannot load, or rejecting one it can.

    ``index`` names the item inside a list (``secrets[3] ...``); leave it
    ``None`` for a single ``secret=`` argument (``secret ...``). Everything
    after the label is byte-identical between the two spellings.

    Raises:
        CapabilityError: INVALID_INPUT for a missing required key, a
            non-canonical ``secret_type`` label, or malformed hex.
    """
    from memdiver.core.keylog import ALL_SECRET_TYPES
    from memdiver.core.models import CryptoSecret

    label = "secret" if index is None else f"secrets[{index}]"
    try:
        secret_type = item["secret_type"]
        client_random = item["client_random"]
        secret = item["secret"]
    except (KeyError, TypeError) as exc:
        raise CapabilityError(
            f"{label} missing required key {exc}; each item needs "
            "'secret_type', 'client_random', 'secret'",
            category=ErrorCategory.INVALID_INPUT,
        ) from exc
    if secret_type not in ALL_SECRET_TYPES:
        raise CapabilityError(
            f"{label} has non-canonical secret_type {secret_type!r}; "
            f"expected one of {sorted(ALL_SECRET_TYPES)}",
            category=ErrorCategory.INVALID_INPUT,
        )
    try:
        return CryptoSecret(
            secret_type=secret_type,
            identifier=bytes.fromhex(client_random),
            secret_value=bytes.fromhex(secret),
        )
    except (ValueError, TypeError) as exc:
        raise CapabilityError(
            f"{label} has malformed hex: {exc}",
            category=ErrorCategory.INVALID_INPUT,
        ) from exc


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
    from memdiver.core.keylog import format_keylog_lines
    from memdiver.core.models import CryptoSecret

    crypto_secrets: List[CryptoSecret] = [
        _crypto_secret_from_dict(item, index=i) for i, item in enumerate(secrets)
    ]

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
    include_fields: bool = False,
    detect_protocols: bool = False,
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

    ``include_fields`` (C2) opts into the byte-addressed view of each handshake
    — "which bytes of this session could I go looking for in a memory dump, and
    where on the wire did each come from?". It is OFF by default and the default
    response is byte-identical to the one above, because every existing caller
    (the arm step, the run's cap echo, the corpus sweep) wants the session facts
    and would only pay for a second parse. Switched on, three keys appear:

    * ``fields`` on each session — one
      :meth:`~memdiver.engine.resources.protocol_fields.ProtocolField.as_dict`
      per extractable field, carrying ``field_id``, ``value_hex``, ``length``,
      ``source``, wire ``provenance`` and ``searchable``. Read ``searchable``
      before using a field as a dump needle: it is DERIVED (a byte/string run of
      at least ``MIN_SEARCHABLE_LEN``), and a field with ``searchable: false``
      matches everywhere, so a hit on it means nothing.
    * ``field_notes`` on each session — ``{"code", "detail"}`` entries saying why
      a field a caller might reasonably expect is legitimately absent. The
      load-bearing one is TLS 1.3: RFC 8446 encrypts the Certificate message, so
      no TLS 1.3 capture can carry one, and an empty ``certificate.0`` would
      claim a parse failure where there was nothing to parse.
    * ``field_index`` at the top level — a CATALOGUE, not values: ``field_id`` ->
      ``{label, type, source, searchable, sessions: [<session_index>, ...]}``, so
      a picker can offer "the ids this capture has" without walking every
      session. Field ids are unique per session by construction (C1 prefixes
      extension ids ``client_ext.``/``server_ext.`` precisely because 0x000b
      appears in both hellos), which is what makes an id-keyed index safe.

    Turning it on costs a second read of the capture: ``describe_fields`` parses
    independently of ``describe_capture`` and the resource caches nothing. That
    is the whole reason the flag exists rather than the fields always being
    there.

    ``detect_protocols`` (C4a) answers the question this producer could not
    answer before: **"if this capture has no TLS sessions, what does it have?"**
    A parseable capture with zero TLS handshakes already returns
    ``session_count: 0`` rather than erroring, and that zero was the whole
    report — true, and no help at all to someone who captured QUIC. Switched on,
    one additive key appears:

    * ``protocols`` — one dict per protocol the capture was found to carry
      (``protocol``, ``resource_type``, ``decryptable``, ``flows``, ``detail``,
      ``evidence``), decryptable ones first. See
      :func:`~memdiver.engine.resources.protocol_detect.detect_protocols`;
      ``decryptable`` is read from the LIVE resource registry, so a third-party
      oracle installed through the ``memdiver.oracles`` entry-point group makes
      its protocol report as decryptable with no change here.

    Detection NEVER raises: an unreadable or unrecognisable capture yields an
    empty ``protocols`` list, because this is the key a caller reads while
    working out why something else failed. Like ``include_fields`` it is off by
    default and costs an extra read of the capture (two, for the UDP peek QUIC
    and DTLS need), and the default response is byte-identical without it.
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
        resource = TlsPcapResource(pcap_path, **resource_caps)
        capture = resource.describe_capture()
        # Inside the SAME funnel as the summary parse: a capture that survives
        # ``describe_capture`` can still fail the second read (a file replaced
        # underneath us), and that has to surface as INVALID_INPUT rather than a
        # bare PcapParseError escaping the producer.
        described_fields = resource.describe_fields() if include_fields else []
    except (PcapParseError, OSError, ValueError) as exc:
        raise CapabilityError(
            f"could not parse capture {pcap_path!r}: {exc}",
            category=ErrorCategory.INVALID_INPUT,
        ) from exc

    sessions = capture["sessions"]
    if include_fields:
        sessions = _sessions_with_fields(sessions, described_fields)
    payload: Dict[str, Any] = {
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
    if include_fields:
        # Added only under the flag, so ``include_fields=False`` leaves the
        # response byte-identical rather than growing an always-empty key.
        payload["field_index"] = _pcap_field_index(sessions)
    if detect_protocols:
        # Same rule, same reason: additive under the flag only. Aliased on
        # import because the parameter shadows the function name, and imported
        # lazily so a caller that never asks pays nothing for the UDP pass.
        from memdiver.engine.resources.protocol_detect import (
            detect_protocols as _detect_protocols,
        )

        payload["protocols"] = [
            candidate.as_dict() for candidate in _detect_protocols(pcap_path)
        ]
    return payload


def _sessions_with_fields(
    sessions: Sequence[Dict[str, Any]],
    described_fields: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Attach each session's C2 fields + notes, WITHOUT mutating the input.

    ``describe_capture`` and ``describe_fields`` are two independent parses of
    the same file, so they are joined on ``client_random`` — the session's
    identity — rather than on list position. Position would work today (both
    walk ``_parse_sessions`` in flow order) and would silently mis-attribute a
    capture's fields the day either walk changes.

    A session with no matching entry gets an EMPTY ``fields`` list, not a
    missing key: a caller that asked for fields must be able to tell "this
    session yielded none" from "this response predates the flag".
    """
    by_random = {entry["client_random"]: entry for entry in described_fields}
    enriched: List[Dict[str, Any]] = []
    for session in sessions:
        entry = by_random.get(session["client_random"], {})
        enriched.append({
            **session,
            "fields": entry.get("fields", []),
            "field_notes": entry.get("notes", []),
        })
    return enriched


def _pcap_field_index(sessions: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Catalogue the field IDS a capture offers, and which sessions carry each.

    Values are deliberately NOT in here: a capture's two sessions both have a
    ``client_random`` field with different bytes, so an id-keyed map of values
    could only be wrong. What a caller needs before it can name a field
    symbolically is the id, whether it is worth searching for, and where to look
    it up — which is exactly this.

    ``searchable`` here means "searchable in AT LEAST ONE of the listed
    sessions", because the flag is derived from a length and two sessions can
    legitimately disagree (one 3-byte SNI, one 12-byte). The authoritative
    per-session flag stays on the session's own field, and that is the one
    ``_needle_from_pcap_field`` checks — this key is a hint for a picker, not a
    permission.
    """
    index: Dict[str, Any] = {}
    for position, session in enumerate(sessions):
        for field in session.get("fields", []):
            entry = index.setdefault(field["field_id"], {
                "label": field["label"],
                "type": field["type"],
                "source": field["source"],
                "searchable": False,
                "sessions": [],
            })
            entry["searchable"] = entry["searchable"] or field["searchable"]
            entry["sessions"].append(position)
    return index


# _emit/_progress_bridge/_experiment_check_cancelled MOVED to memdiver.app._progress (P3.1)
# experiment orchestration MOVED to memdiver.app.experiment_orchestration (P3.1)
