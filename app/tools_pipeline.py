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
import re
import tempfile
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
# One more of the same kind, for ``score_detector_matches``'s
# ``tolerance_bytes`` keyword default. The scoring COMPUTE (score_intervals /
# aggregate_detector_report) stays function-local inside that producer; only
# this number has to resolve at import time, so the CLI flag and the Pydantic
# model advertise the SAME alignment slack the library applies.
from memdiver.engine.detector_metrics import DEFAULT_TOLERANCE_BYTES
# Two DEFAULT VALUES, imported (never re-literalled) exactly as
# DEFAULT_NEIGHBORHOOD_PAD above is: they are keyword defaults in this module's
# signatures, so they must resolve at import time. The key-location COMPUTE is
# still imported function-locally inside the producers, so ``app`` does not pull
# ``engine.key_location`` at module scope.
from memdiver.engine.key_location import (
    DEFAULT_KEY_CONTEXT,
    DEFAULT_MAX_KEY_OFFSETS,
)
# Two more of the same kind, for ``scan_yara_rule``'s keyword defaults. The
# scanning COMPUTE (compile_rules / scan_source) stays function-local inside
# that producer; only these two numbers have to resolve at import time so the
# CLI parser and the Pydantic model can advertise the SAME cap and budget the
# library applies.
from memdiver.engine.yara_scan import (
    DEFAULT_MAX_MATCHES,
    DEFAULT_TIMEOUT_S,
)
# And two more for ``verify_vol3_plugin``'s keyword defaults, from the two
# runtimes it drives. ``vol3_subproc`` deliberately imports no ``volatility3``
# at all, and ``vol3_verify``'s import of it is soft-probed, so pulling these
# names costs the optional ``vol`` extra nothing and cannot break an install
# that lacks it. The COMPUTE in both modules stays function-local inside the
# producer, as everywhere else in this file.
from memdiver.engine.vol3_subproc import (
    DEFAULT_TIMEOUT_SECONDS as _VOL3_DEFAULT_TIMEOUT_SECONDS,
)
from memdiver.engine.vol3_verify import (
    DEFAULT_MAX_HITS as _VOL3_DEFAULT_MAX_HITS,
)

from .composition import open_dump_source, raise_if_locked

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

#: The emitted pattern is WIDER than the installed libyara will verify, so the
#: artifact about to be written matches nothing at all. Shared by the
#: key-anchored export and the auto/manual pattern exports, because all three
#: can write a dead rule and none of them used to say so.
#:
#: Emit-time rather than scan-time is the point: ``scan_yara_rule`` can only
#: refuse to call a dead rule "clean" AFTER someone runs it, and a signature
#: written to disk outlives the session that made it. Note the trap this
#: closes: ``degenerate_anchors`` above advises raising ``--context`` to reach
#: structural bytes, and following that advice to ``--context 512`` produces a
#: ~1072-byte pattern that is silently dead. The two diagnostics are meant to
#: be read together.
PATTERN_OVER_SCAN_LIMIT_CODE = "export.pattern.over_scan_limit"

#: ``degenerate_anchors`` thresholds, CALIBRATED ON MEASURED SELECTIVITY.
#:
#: The previous values (4 distinct bytes / 1.0 bit per byte) were reasoned from
#: two points on one run -- pad 64 on the OpenSSL TLS 1.2 anchor key carries 0.0
#: bits, pad 256 carries 1.26 -- so 1.0 looked like a boundary. Pad 128 was never
#: measured. It is 0.6502 bits and its rule is PERFECT (one firing per dump,
#: ``key_offset`` precision 1.0), so the 1.0-bit floor warned about a flawless
#: rule. That is the worst failure mode a diagnostic has: it teaches the reader
#: to skip the firing that matters. ``engine/candidate_stats.py`` is this repo's
#: standing scar for calibrating on reasoning instead of data, so these two
#: numbers were re-derived by measuring.
#:
#: THE SWEEP. 99 ``(run, pad)`` cells: pads 64/128/256/512 over 25 runs spanning
#: all 13 corpus TLS libraries and both TLS 1.2 and 1.3. Each cell was emitted
#: through the real ``export_key_pattern`` -> ``PatternGenerator`` ->
#: ``YaraExporter`` chain from the run's own ``keylog.csv``, then scanned with
#: ``scan_yara_rule(max_matches=None, include_matches=False)`` -- the uncapped
#: COUNT-ONLY census, the only affordable way to ask the question (an uncapped
#: pad-64 scan of eight dumps materialises 6.6M matches of 352 hex characters
#: each: a 4.0 GB JSON). Precision came from ``score_detector_matches`` on the
#: ``key_offset`` criterion. 92 cells were judgeable; 7 are excluded because
#: libyara declines to match the pattern at all (see the last note below).
#:
#: THE RESULT. Selectivity is governed by ``distinct_bytes``, and the outcome is
#: in three sharply separated groups -- there is nothing between 6 firings and
#: 750,000:
#:
#: ============  =====  ====================  ==============  =================
#: distinct       cells  firings / dump        precision       verdict
#: ============  =====  ====================  ==============  =================
#: 1                20  752,908 - 1,000,000   1.0e-06         non-detector
#: 2                 2  2 and 6               0.5 and 0.167   imprecise
#: >= 3             70  exactly 1, all 70     1.0             perfect
#: ============  =====  ====================  ==============  =================
#:
#: So ``distinct_bytes < 3`` is a PERFECT classifier over all 92 judgeable
#: cells: 22 true alarms, **0 false alarms**, 0 missed, 70 correctly quiet. The
#: old gate scored 22 true and **21 FALSE** on the same cells -- it cried wolf
#: on nearly half of its firings. The boundary is measured on BOTH sides:
#: ``distinct_bytes == 2`` fires 2-6 times per dump (TLS13 libressl pads 64/128)
#: and ``== 3`` fires exactly once (5 cells, mbedtls and libressl).
#:
#: WHY BYTES IS 3 AND NOT 2. An earlier, narrower sweep (36 cells, 9 runs) saw
#: only ``distinct_bytes`` 1 and >= 3 and would have justified 2. Widening the
#: sweep to every library turned up the two ``== 2`` cells, which are imprecise.
#: A threshold of 2 would have gone silent on them -- the exact mistake of
#: fitting a boundary to a value nothing had measured.
#:
#: WHY THE BITS FLOOR IS RETIRED (set to 0.0, and doing no work).
#: ``shannon_bits`` was measured to be a POOR PREDICTOR -- not merely
#: mis-calibrated. The failing cells span ``[0.0, 0.2623]`` and the passing ones
#: span ``[0.0521, 6.7383]``: those ranges OVERLAP, so no floor of any value can
#: separate them. A cell at 0.2623 bits is unselective while one at 0.0521 is
#: perfect, because per-byte entropy says nothing about how much anchor there is
#: or whether a real process image contains the same filler. Nor can a positive
#: floor even express "more than one distinct value": the smallest non-zero
#: entropy an anchor can carry shrinks with its size -- 0.1068 at 71 static
#: bytes, 0.0659 at 128, 0.0261 at 385, 0.0107 at 1072 -- and ``context`` is
#: unbounded, so every positive constant becomes a false alarm at some window
#: width. 0.0 is therefore not a tuned value but the retirement of the signal:
#: it fires only on "the anchors carry no information whatsoever", which is
#: arithmetically identical to ``distinct_bytes == 1`` and hence already inside
#: the bytes clause. Measured confusion is byte-for-byte identical with and
#: without it. It is KEPT rather than dropped because the payload publishes
#: ``shannon_bits`` in ``details``, and a gate that ignored a number it shows
#: the operator would be free to drift from it.
#:
#: A SEPARATE DEFECT THE SWEEP TURNED UP, unrelated to these thresholds and NOT
#: fixed here: 7 cells at pad 512 emitted a ~1056-1072-byte pattern that libyara
#: matches ZERO times, even in the dump the bytes were read from (verified
#: byte-identical at ``region["offset"]``). The cause is ``YR_RE_SCAN_LIMIT``,
#: which yara-python 4.5.3/4.5.4 regressed from 4096 to **1024** (upstream PR
#: #2144, reverted in 4.5.5): a hex string containing ``??`` compiles to a
#: regexp, and libyara verifies backward and forward from one chosen atom with
#: each direction clamped to that limit, silently reporting no match on overrun.
#: A rule therefore matches only while both ``atom_offset`` and
#: ``pattern_length - atom_offset`` stay under 1024, and the atom's position is
#: content-chosen -- which is why pad 512 works on wolfssl (atom at ~496) and
#: fails on openssl and gnutls. Recall 0 is worse than a false-positive storm,
#: ``scan_yara_rule`` reports it as a confident ``clean``, and no emit-time
#: signal sees it. Those cells are EXCLUDED above rather than counted as
#: "selective". Guarding it means checking ``pattern_length`` against the
#: engine's reachable span at emit time -- a different diagnostic than this one.
#:
#: ``tests/test_degenerate_anchor_calibration.py`` re-derives every claim here.
KEY_PATTERN_MIN_ANCHOR_BYTES = 3
KEY_PATTERN_MIN_ANCHOR_BITS = 0.0


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
    # Checked BEFORE the caller sees it (and before ``output_dir`` writes it):
    # an emitted pattern wider than libyara will verify matches nothing at all,
    # and a signature on disk outlives the session that made it. No ``context``
    # to name here -- these two producers size their window from a region.
    return _attach_scan_limit_diagnostic(
        _export_payload(result, name=name, output_dir=output_dir))


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
    # Checked BEFORE the caller sees it (and before ``output_dir`` writes it):
    # an emitted pattern wider than libyara will verify matches nothing at all,
    # and a signature on disk outlives the session that made it. No ``context``
    # to name here -- these two producers size their window from a region.
    return _attach_scan_limit_diagnostic(
        _export_payload(result, name=name, output_dir=output_dir))


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


def _scan_limit_diagnostic(
    pattern: Dict[str, Any], *, context: Optional[int] = None,
) -> Optional[Diagnostic]:
    """Warn when *pattern* is too wide for libyara to verify, else ``None``.

    Consulted by every producer that WRITES a pattern, before the artifact is
    handed back or written to disk. ``context`` is named in the message when
    the caller has one (:func:`export_key_pattern`), because the context is the
    knob that caused the width and the reader needs to know which number to
    turn down; the auto/manual exports size their window from a region instead
    and pass ``None``.

    ``None`` is returned for a pattern with NO wildcard, and that exemption is
    measured rather than assumed: a hex string without ``??`` compiles to a
    literal, not a regexp, and libyara matches an 8 KiB literal without
    complaint. Only the regexp path is clamped.
    """
    from memdiver.engine.yara_scan import (
        measure_hex_string_widths,
        pattern_exceeds_scan_limit,
        regexp_scan_limit,
    )

    wildcard_pattern = pattern.get("wildcard_pattern")
    if not isinstance(wildcard_pattern, str) or "?" not in wildcard_pattern:
        return None
    # Prefer the emitter's own measured length; fall back to counting the
    # tokens actually in the string, so a pattern dict with a missing or
    # unparseable ``length`` still gets checked instead of skipped.
    declared = pattern.get("length")
    width: Optional[int] = declared if isinstance(declared, int) and declared > 0 else None
    if width is None:
        measured, _ = measure_hex_string_widths("= {" + wildcard_pattern + "}")
        width = max(measured) if measured else None
    if not pattern_exceeds_scan_limit(width):
        return None
    limit = regexp_scan_limit()
    if context is not None and limit is not None:
        # ``width == 2 * context + key_span``, so the key span falls out of the
        # two numbers we have. Deriving it beats reading ``key_length`` off the
        # pattern dict, which does NOT carry it (``YaraExporter.export`` takes
        # it as a separate argument) -- that gave a key span of 0 and advised
        # exactly the ``--context`` that had just produced a dead rule.
        key_span = max(0, width - 2 * context)
        safe_context = max(0, (limit - key_span) // 2)
        context_clause = (
            f"--context {context} produced it; re-emit with --context "
            f"{safe_context} or less, which keeps the window "
            f"({2 * safe_context + key_span} bytes for this "
            f"{key_span}-byte key span) inside the limit. "
        )
    else:
        context_clause = (
            f"Narrow the exported region until the pattern is at most "
            f"{limit} bytes wide. "
        )
    return Diagnostic(
        code=PATTERN_OVER_SCAN_LIMIT_CODE,
        message=(
            f"This pattern is {width} bytes wide, over the {limit} bytes the "
            f"installed libyara will verify, so the rule being emitted matches "
            f"NOTHING — not even the dump its own bytes were read from. "
            f"libyara compiles a hex string containing '??' to a regexp and "
            f"verifies it outward from one chosen atom, clamped to "
            f"YR_RE_SCAN_LIMIT (yara-python 4.5.3/4.5.4 regressed that "
            f"constant from 4096 to 1024), reporting no match on overrun with "
            f"no error of any kind. " + context_clause +
            f"A wider window is NOT available by upgrading: the upstream "
            f"revert is unreleased, so 4.5.4 is the newest wheel published."
        ),
        severity=Severity.WARNING,
        details={"pattern_length": width, "scan_limit": limit,
                 "context_requested": context},
    )


def _attach_scan_limit_diagnostic(
    payload: Dict[str, Any], *, context: Optional[int] = None,
) -> Dict[str, Any]:
    """Append :func:`_scan_limit_diagnostic` to *payload*, in place.

    The key is created ONLY when there is something to report, so an export of
    a normally-sized pattern keeps the exact payload shape it has always had
    (the auto/manual export bodies carry no ``diagnostics`` list otherwise, and
    the web ``/auto-export`` response body is asserted against that shape).
    """
    diagnostic = _scan_limit_diagnostic(payload.get("pattern") or {},
                                        context=context)
    if diagnostic is not None:
        payload.setdefault("diagnostics", []).append(diagnostic.to_dict())
    return payload


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


# ---------------------------------------------------------------------------
# D1 — running the rules MemDiver emits
# ---------------------------------------------------------------------------
#
# ``architect.yara_exporter`` has been able to WRITE a YARA rule since the
# architect layer landed, and ``engine.yara_scan`` can now RUN one. Between the
# two sat nothing: no surface could ask "does the detector I just emitted
# actually fire on my corpus?", which is the only question that makes an
# emitted detector worth anything. This producer is that missing middle, and it
# is deliberately shaped like ``locate_field_across_pairs`` — N sources in,
# one typed row per source out, a roll-up and a verdict — because a scan is the
# same kind of census as a search and should read like one.

#: What HAPPENED to one dump, two-valued for exactly the reason
#: :data:`PAIR_STATUSES` is three-valued: "scanned, and nothing matched" and
#: "could not be scanned" are DIFFERENT facts. Collapsing them deflates the
#: denominator of every detection rate computed from the result, which is the
#: precise failure mode a detector evaluation cannot survive.
YARA_SCANNED = "scanned"
YARA_UNREADABLE = "unreadable"
YARA_SCAN_STATUSES = (YARA_SCANNED, YARA_UNREADABLE)

#: The cross-dump verdict. FOUR-valued rather than three, because a YARA scan
#: has a degraded state a byte search does not: libyara can exhaust its timeout
#: budget, or a chunk can fail to read, and the dump is then neither "matched"
#: nor honestly "clean" — part of it was never looked at.
#:
#: * ``"matched"``      — at least one dump matched.
#: * ``"clean"``        — at least one dump was scanned end to end and matched
#:                        nothing, and NO scanned dump was degraded. This is
#:                        the only value that may be rendered as an absence.
#: * ``"inconclusive"`` — every zero-match scan in the set was degraded
#:                        (timed out, or hit a read error), so the zeros are
#:                        unproven. Claims nothing.
#: * ``"not_scanned"``  — no dump was scanned at all. Claims nothing either.
YARA_MATCHED = "matched"
YARA_CLEAN = "clean"
YARA_INCONCLUSIVE = "inconclusive"
YARA_NOT_SCANNED = "not_scanned"
YARA_SCAN_VERDICTS = (
    YARA_MATCHED, YARA_CLEAN, YARA_INCONCLUSIVE, YARA_NOT_SCANNED,
)

#: How the rule set was supplied. Recorded on the payload so a reader can tell
#: an inline rule apart from one compiled off disk without re-deriving it from
#: which request field happened to be set.
YARA_INTAKE_SOURCE = "source"
YARA_INTAKE_PATHS = "paths"

YARA_SCAN_NOT_SCANNED_CODE = "analysis.yara_scan.not_scanned"
YARA_SCAN_INCONCLUSIVE_CODE = "analysis.yara_scan.inconclusive"
YARA_SCAN_CLEAN_CODE = "analysis.yara_scan.clean"
YARA_SCAN_PARTIAL_CODE = "analysis.yara_scan.partial"
YARA_SCAN_UNREADABLE_CODE = "analysis.yara_scan.unreadable"
YARA_SCAN_TRUNCATED_CODE = "analysis.yara_scan.truncated"
YARA_SCAN_TIMED_OUT_CODE = "analysis.yara_scan.timed_out"
YARA_SCAN_ERRORS_CODE = "analysis.yara_scan.scan_errors"
YARA_SCAN_ZERO_BYTES_CODE = "analysis.yara_scan.zero_bytes"
YARA_SCAN_COUNT_ONLY_CODE = "analysis.yara_scan.count_only"

#: The rule set cannot match AT ALL, because its widest wildcard pattern is
#: wider than the installed libyara will verify. Not an error and not a clean
#: result -- the one verdict such a scan may never be given. See
#: :func:`engine.yara_scan.regexp_scan_limit`.
YARA_SCAN_OVER_SCAN_LIMIT_CODE = "analysis.yara_scan.pattern_over_scan_limit"

#: We could not establish how wide the rules' patterns are, so we could not
#: check them against the limit above. Fires only on an otherwise-CLEAN
#: verdict, which is the only place the unknown actually costs the reader
#: anything: a zero they might otherwise trust.
YARA_SCAN_WIDTH_UNKNOWN_CODE = "analysis.yara_scan.pattern_width_unknown"

#: Whether a scan payload carries its per-match LISTS. ``True`` — the historical
#: and only previous behaviour — is the default on every surface, so nothing
#: about an existing call changes.
#:
#: It exists as a named constant for the same reason ``DEFAULT_MAX_RETURNED_REGIONS``
#: does: the CLI flag, the Pydantic model and the MCP tool must advertise the
#: SAME shape the library produces, and a re-literalled ``True``/``False`` in
#: four places is exactly how that drifts. The CLI spells its flag as the
#: negation of this constant rather than a bare ``False``.
DEFAULT_INCLUDE_MATCHES = True


def _yara_scan_payload(
    scan: Dict[str, Any], *, include_matches: bool
) -> Dict[str, Any]:
    """Shape ONE scanned row's payload for the requested verbosity.

    ``include_matches=True`` returns :meth:`engine.yara_scan.ScanResult.to_dict`
    completely untouched — the same dict object, not a copy — so the default
    payload is byte-identical to the one this producer has always returned.

    ``include_matches=False`` REMOVES the ``matches`` key and marks the row
    ``matches_omitted``. Removing it is deliberate, and the alternative is the
    bug: setting ``matches`` to ``[]`` would make a count-only row with 825,779
    hits indistinguishable from a proven-clean one to any caller that checks
    ``len(scan["matches"])`` or ``if scan["matches"]``, which is the same silent
    false-absence the ``scan: None`` nesting in :func:`_yara_scan_row` exists to
    prevent. An ABSENT key cannot be misread as an empty one; a ``KeyError`` or
    an ``undefined`` is a question, while ``[]`` is a confident wrong answer.

    Every COUNT and every degraded flag survives untouched — ``match_count``,
    ``truncated``, ``timed_out``, ``errors``, ``scanned_bytes``, ``chunks``,
    ``strategy``, ``view``, ``rule_names`` — because those are the whole point
    of asking for a count-only census, and the roll-up below reads them (it
    never reads ``matches``), so the verdict and every number in ``counts`` are
    identical to the full form's.

    Note that a count-only row is NOT scorable: ``score_detector_matches``
    consumes ``dumps[].scan.matches``, so a count-only scan has to be re-run in
    the full form to be measured. The count-only diagnostic says so.
    """
    if include_matches:
        return scan
    stripped = {k: v for k, v in scan.items() if k != "matches"}
    stripped["matches_omitted"] = True
    return stripped


def _yara_scan_row(
    path: Path,
    *,
    status: str,
    scan: Optional[Dict[str, Any]] = None,
    detail: str = "",
) -> Dict[str, Any]:
    """One dump's row, in ONE shape whatever happened to that dump.

    ``scan`` carries :meth:`engine.yara_scan.ScanResult.to_dict` verbatim on a
    scanned row and is ``None`` on every other, mirroring :func:`_pair_row`'s
    ``location``. Nesting it — rather than flattening zeros onto an unreadable
    row — is what keeps "we scanned and found nothing" distinguishable from "we
    never scanned this": there is simply no ``match_count: 0`` to misread.

    The status/scan biconditional is asserted for the same reason
    :func:`_pair_row` asserts its own: the roll-up below trusts it, so a
    ``"scanned"`` row without a payload (or an ``"unreadable"`` one with one) is
    a programming error rather than a strange result to be tolerated.
    """
    if status not in YARA_SCAN_STATUSES:
        raise ValueError(
            "unknown yara scan status " + repr(status) + "; expected one of "
            + ", ".join(repr(s) for s in YARA_SCAN_STATUSES))
    if (status == YARA_SCANNED) != (scan is not None):
        raise ValueError(
            "yara scan status " + repr(status) + " contradicts scan payload "
            + ("present" if scan is not None else "absent"))
    return {
        "dump_path": str(path),
        "name": path.name,
        "status": status,
        # Why this dump could not be scanned; "" on a scanned row. A scanned
        # row's own degraded state lives in ``scan.errors`` / ``scan.timed_out``
        # instead, because it is per-chunk and there can be several.
        "detail": detail,
        "scan": scan,
    }


def _yara_row_degraded(scan: Dict[str, Any]) -> bool:
    """True when a scanned row did NOT cover the bytes it claims to have.

    ``timed_out`` means at least one chunk's bytes were never handed to
    libyara; ``errors`` means at least one chunk could not be read or the
    overlap could not be sized wide enough for the rules' widest pattern. In
    both cases a zero match count is unproven, so the roll-up must not fold
    such a row into ``dumps_clean`` — that fold is precisely how a scan reports
    a silent miss as an all-clear.

    ``scanned_bytes == 0`` is the MAXIMAL case of the same fault and belongs
    here for exactly the same reason, even though it arrives by a quieter road:
    a view that sizes to 0 -- an empty file, or an ``.msl`` whose container
    holds nothing this view can project -- runs the chunk loop zero times, so it
    reports no timeout and no error and would otherwise fall straight through
    into ``dumps_clean``. Declaring a dump clean having compared ZERO bytes
    against the rules is the same false all-clear the four-valued verdict exists
    to prevent, and it is the worst instance of it: not "we missed a chunk" but
    "we looked at nothing at all".

    ``truncated`` is deliberately NOT degradation: it can only occur when
    matches were found (the cap is a cap on hits), so it never manufactures a
    zero. It is reported separately, and in its own diagnostic.
    """
    return (
        bool(scan["timed_out"])
        or bool(scan["errors"])
        or not scan["scanned_bytes"]
    )


def _yara_scan_diagnostics(
    rows: List[Dict[str, Any]],
    *,
    verdict: str,
    counts: Dict[str, int],
    rule_labels: Sequence[str],
    include_matches: bool = DEFAULT_INCLUDE_MATCHES,
    max_matches: Optional[int] = DEFAULT_MAX_MATCHES,
    widest_pattern: Optional[int] = None,
    scan_limit: Optional[int] = None,
    exceeds_scan_limit: bool = False,
    width_unknown: bool = False,
) -> List[Diagnostic]:
    """Qualify a scan result — every degraded channel gets a voice.

    The three "bad news" fields on :class:`engine.yara_scan.ScanResult` exist so
    a caller that ignores them does so knowingly. A caller reading a rendered
    payload cannot ignore what it never sees, so each one is lifted into a
    diagnostic here as well as left on the row.

    ``include_matches`` / ``max_matches`` are the shape of the REQUEST rather
    than of any row, and they are here because the count-only form's honesty
    depends on both of them together: a count taken under a cap is a FLOOR, and
    the caller who asked for counts instead of lists is precisely the one most
    likely to read ``matches_total`` as a census. Both default to the values
    every pre-existing call used, so a default scan's diagnostic list is
    unchanged.
    """
    diagnostics: List[Diagnostic] = []
    names = ", ".join(rule_labels) or "(no rules)"

    # FIRST, and unconditional on the verdict, because it disqualifies every
    # zero in the result at once rather than degrading one dump: a pattern the
    # installed libyara will not verify matches nothing anywhere, including in
    # the dump its own bytes were read from.
    if exceeds_scan_limit:
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_OVER_SCAN_LIMIT_CODE,
            message=(
                f"{names} carries a {widest_pattern}-byte wildcard pattern, "
                f"wider than the {scan_limit} bytes the installed libyara will "
                f"verify — so it matches NOTHING, anywhere, including the dump "
                f"its own bytes came from. libyara compiles a hex string "
                f"containing '??' to a regexp and verifies it outward from one "
                f"chosen atom, clamped to YR_RE_SCAN_LIMIT, reporting no match "
                f"on overrun without any error. Every zero below is therefore "
                f"UNPROVEN and this result is not an absence. Re-emit the "
                f"signature with a smaller --context so the pattern fits under "
                f"{scan_limit} bytes."
            ),
            severity=Severity.WARNING,
            details={
                "widest_pattern_length": widest_pattern,
                "scan_limit": scan_limit,
            },
        ))
    elif width_unknown and verdict == YARA_CLEAN:
        # Only on a CLEAN verdict. Anywhere else the reader is already being
        # told not to trust the zeros, and an unknown we cannot act on is
        # noise; here it is the difference between a proven absence and an
        # unfalsifiable one.
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_WIDTH_UNKNOWN_CODE,
            message=(
                f"{names} declares no pattern_length meta and its hex "
                f"string(s) use syntax this producer does not measure (jump, "
                f"alternation or negation), so the widest wildcard pattern is "
                f"UNKNOWN and could not be checked against the "
                f"{scan_limit}-byte libyara verification limit. A pattern over "
                f"that limit matches nothing at all, silently — so read this "
                f"clean result as unverified rather than as an absence. Emit "
                f"the rules through YaraExporter (which sets pattern_length), "
                f"or confirm by hand that no wildcarded hex string exceeds "
                f"{scan_limit} bytes."
            ),
            severity=Severity.WARNING,
            details={"scan_limit": scan_limit},
        ))

    if verdict == YARA_NOT_SCANNED:
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_NOT_SCANNED_CODE,
            message=(
                f"NOTHING was scanned: all {counts['dumps_total']} dump(s) were "
                f"unreadable. This is not a clean result — no bytes were "
                f"compared against {names}, so the rule set is neither "
                f"confirmed nor refuted."
            ),
            severity=Severity.WARNING,
            details={"dumps_total": counts["dumps_total"]},
        ))
    elif verdict == YARA_INCONCLUSIVE and (
        counts["dumps_timed_out"]
        or counts["dumps_with_errors"]
        or counts["dumps_zero_bytes"]
    ):
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_INCONCLUSIVE_CODE,
            message=(
                f"No dump matched, and every zero-match scan was DEGRADED "
                f"({counts['dumps_timed_out']} timed out, "
                f"{counts['dumps_with_errors']} reported read/overlap errors, "
                f"{counts['dumps_zero_bytes']} scanned ZERO bytes). "
                f"Those zeros are unproven — raise timeout_s, widen "
                f"overlap_bytes, or check that --view names a view these dumps "
                f"actually have, before reading this as an absence."
            ),
            severity=Severity.WARNING,
            details={
                "dumps_inconclusive": counts["dumps_inconclusive"],
                "dumps_timed_out": counts["dumps_timed_out"],
                "dumps_with_errors": counts["dumps_with_errors"],
                "dumps_zero_bytes": counts["dumps_zero_bytes"],
            },
        ))
    elif verdict == YARA_CLEAN:
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_CLEAN_CODE,
            message=(
                f"{names} matched NOTHING in "
                f"{counts['dumps_clean']} fully-scanned dump(s). For an emitted "
                f"key signature that is a recall result, not an error: the rule "
                f"generalises to none of these dumps."
            ),
            severity=Severity.INFO,
            details={"dumps_clean": counts["dumps_clean"]},
        ))

    if counts["dumps_matched"] and counts["dumps_clean"]:
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_PARTIAL_CODE,
            message=(
                f"PARTIAL: matched in {counts['dumps_matched']} of "
                f"{counts['dumps_scanned']} scanned dump(s) and clean in "
                f"{counts['dumps_clean']}. Partial coverage is the NORMAL shape "
                f"of a real signature across a process lifecycle, not a failure."
            ),
            severity=Severity.INFO,
            details={
                "dumps_matched": counts["dumps_matched"],
                "dumps_clean": counts["dumps_clean"],
            },
        ))

    if counts["dumps_unreadable"]:
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_UNREADABLE_CODE,
            message=(
                f"{counts['dumps_unreadable']} of {counts['dumps_total']} dump(s) "
                f"could not be scanned at all. They are ROWS with "
                f"status={YARA_UNREADABLE!r} and no scan payload, so every rate "
                f"below is over dumps_scanned — never over dumps_total."
            ),
            severity=Severity.WARNING,
            details={
                "dumps": [r["dump_path"] for r in rows
                          if r["status"] == YARA_UNREADABLE],
            },
        ))

    if counts["dumps_truncated"]:
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_TRUNCATED_CODE,
            message=(
                f"{counts['dumps_truncated']} dump(s) hit the max_matches cap, so "
                f"their match lists STOP at the cap and matches_total is a floor, "
                f"not a total. Pass max_matches=None for an uncapped census."
            ),
            severity=Severity.WARNING,
            details={
                "dumps": [r["dump_path"] for r in rows
                          if r["scan"] and r["scan"]["truncated"]],
            },
        ))

    if counts["dumps_zero_bytes"]:
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_ZERO_BYTES_CODE,
            message=(
                f"{counts['dumps_zero_bytes']} dump(s) were opened but scanned "
                f"ZERO bytes: the view sized to 0, so the rules were never "
                f"compared against a single byte. Such a row is INCONCLUSIVE, "
                f"never clean — check the file is not empty and that the view "
                f"scanned (see each row's scan.view) is one these dumps have."
            ),
            severity=Severity.WARNING,
            details={
                "dumps": [r["dump_path"] for r in rows
                          if r["scan"] and not r["scan"]["scanned_bytes"]],
            },
        ))

    if counts["dumps_timed_out"]:
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_TIMED_OUT_CODE,
            message=(
                f"{counts['dumps_timed_out']} dump(s) exhausted the "
                f"libyara timeout budget; the bytes in the affected chunk(s) "
                f"were NEVER scanned."
            ),
            severity=Severity.WARNING,
            details={
                "dumps": [r["dump_path"] for r in rows
                          if r["scan"] and r["scan"]["timed_out"]],
            },
        ))

    if counts["dumps_with_errors"]:
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_ERRORS_CODE,
            message=(
                f"{counts['dumps_with_errors']} dump(s) reported per-chunk "
                f"errors (unreadable chunk, or an overlap too narrow for the "
                f"widest pattern). Read scan.errors on those rows: a match that "
                f"straddles such a boundary is simply not found."
            ),
            severity=Severity.WARNING,
            details={
                "errors": {r["dump_path"]: r["scan"]["errors"] for r in rows
                           if r["scan"] and r["scan"]["errors"]},
            },
        ))

    if not include_matches:
        # ALWAYS emitted in the count-only form, even on a clean or unscanned
        # result, because the omission is a property of the ANSWER and not of
        # what was found: a reader handed a row with no ``matches`` key has to
        # be told that this is a requested shape rather than a truncated
        # payload or an older version of the producer.
        #
        # The message splits on the cap for the reason the truncated diagnostic
        # above exists at all. Under a cap, a count-only ``matches_total`` is a
        # floor and the numbers a selectivity question wants ("how many
        # positions does this rule fire on?") are simply not in the payload —
        # and unlike the full form there is not even a match list whose length
        # betrays the cap. Uncapped, it is the honest census, and saying so
        # explicitly is what stops a cautious reader discounting a real number.
        capped = max_matches is not None
        diagnostics.append(Diagnostic(
            code=YARA_SCAN_COUNT_ONLY_CODE,
            message=(
                (
                    f"COUNT-ONLY under a max_matches={max_matches} cap: every "
                    f"count and degraded flag is present and the per-match "
                    f"lists were omitted, but each row's match_count STOPS at "
                    f"the cap, so matches_total ({counts['matches_total']}) is "
                    f"a FLOOR, not a census. Pass max_matches=None "
                    f"(--no-max-matches) for the honest total."
                ) if capped else (
                    f"COUNT-ONLY, uncapped: the per-match lists were omitted "
                    f"and every count and degraded flag is present, so "
                    f"matches_total ({counts['matches_total']}) is the full "
                    f"census. Nothing bounds the SCAN — libyara still finds "
                    f"every match — only the payload."
                )
                + " Scoring needs the lists: re-run without count-only to "
                  "feed score_detector_matches."
            ),
            severity=Severity.WARNING if capped else Severity.INFO,
            details={
                "matches_total": counts["matches_total"],
                "max_matches": max_matches,
                "matches_total_is_floor": capped,
            },
        ))
    return diagnostics


def scan_yara_rule(
    *,
    dump_paths: Sequence[str],
    rule_source: Optional[str] = None,
    rule_paths: Optional[Sequence[str]] = None,
    view: Optional[str] = None,
    max_matches: Optional[int] = DEFAULT_MAX_MATCHES,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    overlap_bytes: int = 0,
    include_matches: bool = DEFAULT_INCLUDE_MATCHES,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """Compile ONE YARA rule set and scan N dumps with it.

    The single implementation behind the CLI ``scan-yara`` command, the HTTP
    ``POST /api/scan/yara`` route, the MCP ``scan_yara_rule`` tool and
    ``memdiver.services.scan_yara_rule``.

    This closes MemDiver's own loop. ``export_key_pattern`` /
    ``export_pattern`` EMIT a signature; until now nothing could RUN one, so
    every emitted detector was unevaluated by construction — you could publish
    a rule and never learn whether it fires on the corpus it was derived from,
    let alone on a held-out one. Point this at the rule and the dumps and the
    answer is a census.

    Rules arrive as TEXT or as rule FILES, in exactly ONE of ``rule_source`` /
    ``rule_paths``, and never as a precompiled ``.yarc``: a compiled rule file
    is executable libyara bytecode, so loading one has the trust properties of
    importing a module (see :func:`engine.yara_scan.compile_rules`). Do not add
    such a form here either.

    The rule set is compiled ONCE and reused for every dump. That is the whole
    point of the engine's content-addressed rule cache — on a corpus sweep,
    recompiling per dump dominates the runtime — and it is also what makes the
    per-dump rows comparable: they were all produced by the same rules.

    Args:
        dump_paths: The dumps to scan. Rows come back in THIS order.
        rule_source: Inline YARA rule text. Mutually exclusive with
            *rule_paths*, with no precedence.
        rule_paths: Paths to ``.yar`` rule files, each compiled into its own
            namespace so two files may define the same rule name.
        view: Byte view to scan. ``None`` keeps each format's own default
            (``"raw"`` for raw dumps, ``"vas"`` for ``.msl``), so a mixed set
            is scanned in the coordinates each dump actually has.
        max_matches: Matches kept per dump; the row's ``scan.truncated`` says
            when the cap bit. Must be positive, or ``None`` for no cap at all
            (the engine refuses ``0`` rather than reading it as "unlimited").
        timeout_s: libyara budget, per chunk on the chunked strategy and once
            for the whole file on the filepath strategy.
        overlap_bytes: Bytes stitched between chunks so a straddling match is
            still seen whole. ``0`` means "size it from the rules'
            ``pattern_length`` meta", which is what an emitted rule carries.
        include_matches: Whether each scanned row carries its per-match LIST.
            ``True`` (the default, and the only previous behaviour) is
            byte-identical to before. ``False`` — the count-only census — drops
            the ``matches`` key from every row and marks it ``matches_omitted``,
            keeping every count and every flag: ``match_count`` per row,
            ``matches_total``, ``truncated``, ``timed_out``, ``errors``,
            ``scanned_bytes``, ``chunks``, ``strategy`` and the ``verdict`` are
            all identical to the full form's.

            This is an OUTPUT bound, not a scan bound, and the distinction
            matters: libyara still finds every match and the engine still
            builds every ``RuleMatch``, so count-only is no faster and saves no
            peak memory — it bounds only what is serialized. That is the part
            that had run away: a 64-byte-pad rule over an 8-dump corpus emits
            6.6M matches, each carrying up to 512 bytes of ``matched_hex``
            (352+ hex characters), for a 4.0 GB JSON. ``max_matches`` bounds
            MEMORY and never bounded the payload's per-match cost.

            It is deliberately ORTHOGONAL to ``max_matches``: neither implies
            the other. Asking for counts does not silently uncap the scan (that
            would change the cost of a request the caller sized on purpose) and
            a cap does not silently disable the counts. The consequence is that
            a count-only run UNDER a cap reports a floor, which is why it always
            carries the ``analysis.yara_scan.count_only`` diagnostic saying so —
            pass ``max_matches=None`` alongside it for the honest census.

            A count-only payload is not scorable: ``score_detector_matches``
            reads ``dumps[].scan.matches``.
        key_file / passphrase / kem_key_file / key_material: Decryption
            material for encrypted ``.msl`` containers.
        on_source: Called with each freshly opened source before anything is
            read from it; runs AFTER the locked-container guard below.

    Returns:
        A bare dict carrying ``verdict``, the ``rules`` that were compiled, the
        ``caps`` they ran under, ``counts``, one row per dump in the SUPPLIED
        order, and ``diagnostics``.

        Read ``verdict`` before any count — only ``"clean"`` is an absence;
        ``"inconclusive"`` and ``"not_scanned"`` claim NOTHING (see
        :data:`YARA_SCAN_VERDICTS`) — and read each row's ``status`` before its
        ``scan``, which is ``None`` on every unreadable row.

        With ``include_matches=False`` the shape is the same one key lighter:
        each scanned row's ``scan`` has NO ``matches`` key (see
        :func:`_yara_scan_payload` for why it is absent rather than empty) and
        carries ``matches_omitted: True`` instead. Everything else — including
        every number in ``counts`` — is unchanged.

    Raises:
        CapabilityError: INVALID_INPUT for zero or both rule forms and for the
            engine's own argument refusals (``yara.bad_max_matches``,
            ``yara.bad_overlap``, ``yara.rules_too_large``,
            ``yara.namespace_collision``, a libyara compile error);
            PRECONDITION for an empty ``dump_paths`` and for a missing
            ``yara-python`` (a BASE dependency, so its absence is a broken
            environment — the engine owns that message and it is deliberately
            not re-categorised here).
        FileNotFoundServiceError: when any supplied dump or rule file does not
            exist. Checked up front, so a typo is reported before N dumps are
            read.
        EncryptedDumpLockedError: for a locked encrypted container. Non-
            negotiable: a locked ``.msl`` reads back EMPTY rather than failing,
            so without the guard every locked dump would be reported as an
            honest zero-match scan — a silent false negative, and the exact
            class ``test_g9_producers_surface_locked_dump`` exists to prevent.
    """
    # Function-local so the ``app`` layer does not pull the engine's compute at
    # module import time (the repo-wide idiom; see ``locate_field_across_pairs``
    # above). Only the two keyword DEFAULTS are imported at module scope, since
    # those must resolve when this signature is built. ELAPSED_PRECISION is
    # shared with the key-location producers so ``elapsed_s`` rounds identically
    # across the whole family.
    from memdiver.engine.key_location import ELAPSED_PRECISION
    from memdiver.engine.yara_scan import (
        compile_rules,
        max_pattern_length,
        measure_hex_string_widths,
        pattern_exceeds_scan_limit,
        regexp_scan_limit,
        rule_names,
        scan_source,
    )

    # Exactly one rule form, named by BOTH names in the refusal. No precedence:
    # silently preferring one would mean a caller who set the wrong field gets a
    # complete, confident census produced by rules they did not intend.
    if (rule_source is None) == (rule_paths is None):
        raise CapabilityError(
            "scan_yara_rule() takes exactly ONE of rule_source= (inline rule "
            "text) or rule_paths= (.yar files); "
            + ("both were supplied" if rule_source is not None else "neither was")
            + ". There is no precedence between them.",
            category=ErrorCategory.INVALID_INPUT,
        )

    paths = [Path(p).expanduser() for p in dump_paths]
    if not paths:
        raise CapabilityError(
            "Need at least 1 dump to scan, got 0",
            category=ErrorCategory.PRECONDITION,
        )
    rule_files = [Path(p).expanduser() for p in (rule_paths or ())]
    # Existence over BOTH the dumps and the rule files, up front, so a mistyped
    # path is a NOT_FOUND rather than eight scans followed by one. Same posture
    # as ``locate_key`` / ``locate_field_across_pairs``.
    missing = [str(p) for p in [*paths, *rule_files] if not p.exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")

    # ONE compile for N dumps. Every ``CapabilityError`` this can raise — a
    # missing yara-python, oversized rule text, a namespace collision, a libyara
    # syntax error — propagates verbatim, so all four surfaces report a bad rule
    # in the engine's own words.
    if rule_source is not None:
        rules = compile_rules(source=rule_source)
        intake = YARA_INTAKE_SOURCE
    else:
        rules = compile_rules(paths=rule_files)
        intake = YARA_INTAKE_PATHS
    compiled_names = list(rule_names(rules))

    # How wide is the widest WILDCARD pattern in this rule set, and will the
    # installed libyara actually verify something that wide?
    #
    # This is not a nicety. A hex string containing '??' compiles to a regexp,
    # and libyara verifies a regexp outward from one chosen atom with each
    # direction clamped to YR_RE_SCAN_LIMIT -- a constant that yara-python
    # 4.5.3/4.5.4 regressed from 4096 to 1024. Past the clamp libyara reports
    # NO MATCH, with no error and no warning, for a pattern that is present in
    # the data byte for byte. Scanning with such a rule and calling the result
    # "clean" is a false all-clear, so the width has to be known BEFORE the
    # zeros are interpreted.
    #
    # TWO sources, because neither alone covers both kinds of rule set:
    #
    # * ``max_pattern_length`` reads the ``pattern_length`` meta, which only
    #   rules MemDiver emitted carry. Authoritative when present.
    # * ``measure_hex_string_widths`` measures the rule TEXT, which is what a
    #   third-party ``.yar`` gives us. Without it, a hand-written rule with a
    #   2 KiB wildcard pattern would be waved through as "no meta, assume
    #   fine" -- reopening the hole for exactly the rules MemDiver did not
    #   write.
    #
    # The wider of the two wins, and ``unmeasured`` counts the blocks whose
    # syntax the measurer declines to parse; together with an absent meta that
    # is the "we do not know" state, reported as its own diagnostic rather
    # than resolved in either direction.
    declared_width = max_pattern_length(rules)
    if rule_source is not None:
        rule_text = rule_source
        unmeasured = 0
    else:
        # Re-read rather than thread the text out of ``compile_rules``: the
        # files are already known to exist (checked above) and a rule file is
        # kilobytes. An unreadable one cannot have been compiled, but the read
        # is guarded anyway so a race degrades to "unknown width" instead of
        # taking down a scan that libyara already accepted.
        chunks: List[str] = []
        unmeasured = 0
        for rule_file in rule_files:
            try:
                chunks.append(rule_file.read_text(errors="replace"))
            except OSError as exc:
                logger.warning(
                    "%s: could not re-read rule file to measure its pattern "
                    "widths (%s); width will be reported as unknown.",
                    rule_file, exc)
                unmeasured += 1
        rule_text = "\n".join(chunks)
    measured_widths, text_unmeasured = measure_hex_string_widths(rule_text)
    unmeasured += text_unmeasured
    # Does this rule set contain a WILDCARDED hex string at all? The limit
    # clamps libyara's regexp verification, and a wildcard-free hex string
    # compiles to a literal, which is not clamped (verified: an 8 KiB literal
    # matches fine). So the declared meta may only be believed once we have
    # seen a wildcard somewhere -- otherwise a fully-static 2 KiB pattern,
    # which is a perfectly good rule, gets flagged as dead. The measured
    # widths already carry that exemption (they skip literal blocks); the meta
    # does not, because ``pattern_length`` describes the window's width and
    # says nothing about whether any byte of it is volatile.
    has_wildcard_string = bool(measured_widths) or unmeasured > 0
    candidate_widths = [w for w in measured_widths if w]
    if has_wildcard_string and declared_width:
        candidate_widths.append(declared_width)
    widest_pattern = max(candidate_widths) if candidate_widths else None
    scan_limit = regexp_scan_limit()
    exceeds_scan_limit = pattern_exceeds_scan_limit(widest_pattern)
    # "Unknown" means we found no width we trust AND something was there we
    # could not measure. A rule set of pure literals yields no widths at all
    # and is NOT unknown: the verification limit does not apply to literals.
    width_unknown = widest_pattern is None and unmeasured > 0

    def _observe(source: Any) -> None:
        # FIRST, before a single byte is read. A locked encrypted dump reads
        # back EMPTY instead of raising, so this is the difference between "we
        # could not open your container" and N confident zero-match rows over
        # bytes nobody decrypted.
        _raise_if_locked(source)
        if on_source is not None:
            on_source(source)

    km = _resolve_key_material(key_material, key_file, passphrase, kem_key_file)
    started = time.perf_counter()
    rows: List[Dict[str, Any]] = []

    for path in paths:
        try:
            with open_dump_source(str(path), km) as source:
                _observe(source)
                result = scan_source(
                    source,
                    rules,
                    view=view,
                    overlap_bytes=overlap_bytes,
                    max_matches=max_matches,
                    timeout_s=timeout_s,
                )
        except (OSError, ValueError) as exc:
            # NARROW ON PURPOSE, exactly as ``locate_key_across_dumps``'s own
            # handler is. ``EncryptedDumpLockedError`` is a ``CapabilityError``
            # and neither an ``OSError`` nor a ``ValueError``, so it propagates
            # straight through here; widening this tuple to ``Exception`` would
            # silently convert a forgotten key into N clean scans. The engine's
            # argument refusals (bad overlap, bad max_matches) propagate for the
            # same reason: they are a mistake in the request, not a bad dump.
            logger.warning(
                "%s: unreadable while scanning with YARA (%s); claiming nothing"
                " about this dump.", path, exc)
            rows.append(_yara_scan_row(
                path, status=YARA_UNREADABLE, detail=str(exc)))
            continue
        # ``_yara_scan_payload`` returns ``result.to_dict()`` UNTOUCHED in the
        # default form, so the shaping hook costs the historical payload
        # nothing — not even a copy.
        rows.append(_yara_scan_row(
            path, status=YARA_SCANNED,
            scan=_yara_scan_payload(
                result.to_dict(), include_matches=include_matches)))

    scanned = [r for r in rows if r["status"] == YARA_SCANNED]
    matched = [r for r in scanned if r["scan"]["match_count"]]
    # A zero-match scan is only "clean" when the whole view was actually
    # covered; a timed-out or erroring one is INCONCLUSIVE. See
    # :func:`_yara_row_degraded` — this split is the silent-miss guard.
    zero_match = [r for r in scanned if not r["scan"]["match_count"]]
    if exceeds_scan_limit:
        # The SECOND way a zero can be unproven, and it is not per-dump like
        # the first: nothing is wrong with these dumps or with how much of them
        # we read: the RULE cannot fire, so every zero in the set is
        # meaningless at once. Folding even one such row into ``dumps_clean``
        # would let a rule that matches nothing anywhere report an all-clear
        # over a fully-scanned corpus -- the worst shape of this bug, because
        # every coverage signal reads perfect.
        #
        # A ``matched`` row is left alone deliberately. ``widest_pattern`` is a
        # MAXIMUM over the set, so a mixed rule file can hold one over-limit
        # pattern and one that is fine; the fine one's hits are real. Only the
        # zeros are in doubt.
        clean = []
        inconclusive = list(zero_match)
    else:
        clean = [r for r in zero_match if not _yara_row_degraded(r["scan"])]
        inconclusive = [r for r in zero_match if _yara_row_degraded(r["scan"])]

    counts = {
        "dumps_total": len(rows),
        "dumps_scanned": len(scanned),
        "dumps_unreadable": len(rows) - len(scanned),
        "dumps_matched": len(matched),
        "dumps_clean": len(clean),
        "dumps_inconclusive": len(inconclusive),
        # The degraded-state census, kept as counts of its own rather than
        # inferred from the verdict: a dump can match AND have timed out, in
        # which case its match list is real but incomplete.
        "dumps_truncated": sum(1 for r in scanned if r["scan"]["truncated"]),
        "dumps_timed_out": sum(1 for r in scanned if r["scan"]["timed_out"]),
        "dumps_with_errors": sum(1 for r in scanned if r["scan"]["errors"]),
        # The quiet third degraded channel: a row that was opened and handed to
        # the scanner but whose view sized to 0. It reports neither a timeout
        # nor an error, so it is counted here explicitly rather than inferred
        # from the absence of the other two.
        "dumps_zero_bytes": sum(
            1 for r in scanned if not r["scan"]["scanned_bytes"]),
        # A FLOOR when dumps_truncated is non-zero, which is what that count is
        # there to tell you.
        "matches_total": sum(r["scan"]["match_count"] for r in scanned),
        "scanned_bytes": sum(r["scan"]["scanned_bytes"] for r in scanned),
    }

    if matched:
        verdict = YARA_MATCHED
    elif clean and not inconclusive:
        verdict = YARA_CLEAN
    elif scanned:
        # Something was read, nothing matched, and at least one of the zeros is
        # unproven. Reporting "clean" here is the all-clear-over-unscanned-bytes
        # error; reporting "not_scanned" would be equally wrong, because bytes
        # WERE compared.
        verdict = YARA_INCONCLUSIVE
    else:
        verdict = YARA_NOT_SCANNED

    return {
        "verdict": verdict,
        "intake": intake,
        "view": view,
        "rules": {
            "names": compiled_names,
            "count": len(compiled_names),
            # Echoed as SUPPLIED (not resolved) so a caller can see which files
            # it named; the compiled identities are ``names`` above.
            "paths": [str(p) for p in rule_files],
            # The widest pattern the rules declare, i.e. exactly the width a
            # chunk overlap has to cover. ``None`` when the rules carry no
            # ``pattern_length`` meta — which is itself the signal that the
            # automatic overlap had nothing to size itself from.
            "max_pattern_length": declared_width,
            # The widest wildcard pattern actually in the set, from the meta or
            # measured off the rule text, and what the installed libyara will
            # verify. ``exceeds_scan_limit`` true means the rule set matches
            # nothing at all and every zero above is unproven.
            "widest_pattern_length": widest_pattern,
            "scan_limit": scan_limit,
            "exceeds_scan_limit": exceeds_scan_limit,
            "pattern_width_unknown": width_unknown,
        },
        "caps": {
            "max_matches": max_matches,
            "timeout_s": timeout_s,
            "overlap_bytes": overlap_bytes,
        },
        "counts": counts,
        "dumps": rows,
        "elapsed_s": round(time.perf_counter() - started, ELAPSED_PRECISION),
        "diagnostics": [
            d.to_dict() for d in _yara_scan_diagnostics(
                rows,
                verdict=verdict,
                counts=counts,
                rule_labels=compiled_names,
                # The request's shape, so the count-only form can say whether
                # its matches_total is a census or a floor.
                include_matches=include_matches,
                max_matches=max_matches,
                widest_pattern=widest_pattern,
                scan_limit=scan_limit,
                exceeds_scan_limit=exceeds_scan_limit,
                width_unknown=width_unknown,
            )
        ],
    }


# ---------------------------------------------------------------------------
# D2 — scoring the detectors D1 runs
# ---------------------------------------------------------------------------
#
# ``scan_yara_rule`` above answers "did the rule fire?". It cannot answer "was
# it RIGHT?", and a census of firings with no ground truth beside it measures
# nothing: a rule that matches every 4 KiB page produces a beautiful
# ``dumps_matched`` count and is worthless. ``engine/detector_metrics.py``
# is the other half — interval precision/recall under three criteria, with the
# fan-in/fan-out structure kept visible — and until this producer it was, like
# ``engine/yara_scan.py`` before it, fully built, fully tested, and reachable
# from NO surface. This is the join: feed a scan's ``dumps[].scan.matches``
# straight in with the key's known intervals and you get the score.
#
# This producer reads NO dump. It takes matches and truths as data, so there is
# no ``open_dump_source``, no key material and no locked-container guard here —
# ``_raise_if_locked`` guards producers that read bytes, and adding it to one
# that reads a list would be cargo cult.

#: What could be established about ONE (detector, dump) row. Two-valued, and
#: the split is the recall DENOMINATOR: a row with no truth intervals has
#: nothing to be measured against, so its rates are vacuous zeros rather than
#: bad ones. See :data:`SCORE_ROW_UNSCORABLE`.
SCORE_ROW_SCORED = "scored"
#: The row carried ZERO truth intervals. Its ``metrics`` is ``None`` — not a
#: block of zeros — and it is left OUT of the roll-up entirely, because
#: including it would charge its firings to the precision denominator and so
#: assert they are false positives, which is exactly the claim a row with no
#: truth set cannot support. Its firing count is still published, so a caller
#: who KNOWS those dumps hold no key can compute the strict rate themselves.
SCORE_ROW_UNSCORABLE = "unscorable"
SCORE_ROW_STATUSES = (SCORE_ROW_SCORED, SCORE_ROW_UNSCORABLE)

#: The cross-row verdict. THREE-valued, and only ONE of the three is a
#: measurement — read it before any number in the report:
#:
#: * ``"scored"``      — at least one row had both truths and firings, so the
#:                       precision and recall in ``report`` mean something.
#: * ``"no_matches"``  — rows carried truths and the detector fired on NONE of
#:                       them. ``recall == 0.0`` here is a MEASURED total miss:
#:                       a real result, and the one that should hurt.
#: * ``"no_truths"``   — no row carried a truth interval, so nothing was
#:                       scorable. ``report`` is ``None`` and every rate that
#:                       would have been reported would have been a vacuous
#:                       zero. Claims NOTHING — least of all that the
#:                       detector's firings were wrong.
SCORE_SCORED = "scored"
SCORE_NO_MATCHES = "no_matches"
SCORE_NO_TRUTHS = "no_truths"
SCORE_DETECTOR_VERDICTS = (SCORE_SCORED, SCORE_NO_MATCHES, SCORE_NO_TRUTHS)

#: How the work was supplied: ONE (matches, truths) pair, or N pre-grouped
#: rows. Echoed on the payload so a reader need not re-derive it from which
#: argument happened to be set.
SCORE_INTAKE_PAIR = "pair"
SCORE_INTAKE_ROWS = "rows"
SCORE_DETECTOR_INTAKES = (SCORE_INTAKE_PAIR, SCORE_INTAKE_ROWS)

SCORE_DETECTOR_SCORED_CODE = "analysis.score_detector.scored"
SCORE_DETECTOR_NO_TRUTHS_CODE = "analysis.score_detector.no_truths"
SCORE_DETECTOR_NO_MATCHES_CODE = "analysis.score_detector.no_matches"
SCORE_DETECTOR_UNSCORABLE_ROWS_CODE = "analysis.score_detector.unscorable_rows"
SCORE_DETECTOR_FAN_OUT_CODE = "analysis.score_detector.fan_out"
SCORE_DETECTOR_FAN_IN_CODE = "analysis.score_detector.fan_in"
SCORE_DETECTOR_NO_KEY_OFFSET_CODE = "analysis.score_detector.no_key_offset"


class _ScoredMatch(NamedTuple):
    """One detector firing, as an ATTRIBUTE-carrying object.

    THIS CLASS IS THE WHOLE POINT of the normalisation below, so it is worth
    being blunt about why it exists. ``engine/detector_metrics.py`` reads every
    input through ``getattr`` — deliberately, and documented as such: "anything
    exposing those attributes works", which is what keeps the metric module
    independent of whichever scanner produced the hits (see
    ``engine/detector_metrics.py`` lines 146-152, and the two test modules that
    rely on it with ad-hoc objects). Combined with ``_int_or(None) -> 0``, that
    duck typing has one sharp edge:

        getattr({"offset": 370672, "length": 48}, "offset", None)  ->  None
        _int_or(None)                                              ->  0

    A plain dict therefore scores as ``offset 0, length 0`` — SILENTLY, with
    nothing raised and a full, plausible-looking report of entirely fictional
    precision and recall. And dicts are precisely what arrives here:
    ``scan_yara_rule`` serialises its matches through ``RuleMatch.to_dict()``,
    and the web and MCP surfaces deliver JSON.

    The fix belongs on THIS side of the boundary — the engine's duck typing is
    a designed property, not an oversight — so every incoming row is converted
    into one of these before the engine ever sees it, and a row that cannot be
    converted is REFUSED (see :func:`_score_offset`) rather than quietly
    becoming a firing at offset 0.
    """

    offset: int
    length: int
    key_offset: Optional[int]
    key_length: Optional[int]


class _ScoredTruth(NamedTuple):
    """One known-true key interval, shaped like ``TruthInterval``.

    ``start`` (with ``offset`` accepted as the alias the engine itself falls
    back to) and ``length`` are the geometry; ``source`` is the provenance the
    engine reads to keep a sparse ledger corroboration from being mistaken for
    complete key-log truth. It is carried here for exactly that reason and
    defaults to ``""``, which the engine drops rather than reporting as a
    source named "empty string".
    """

    start: int
    length: int
    source: str


class _ScoreRow(NamedTuple):
    """One (detector, dump) row, normalised — the single internal shape.

    Both intakes funnel into a list of these (the pair form is simply a list of
    one), so the scoring below has exactly one input shape to reason about,
    exactly as ``_PcapPair`` does for ``locate_field_across_pairs``.
    """

    detector: str
    dump: str
    matches: Tuple[_ScoredMatch, ...]
    truths: Tuple[_ScoredTruth, ...]
    truth_sources: Tuple[str, ...]


def _score_field(row: Any, name: str) -> Any:
    """Read *name* off a dict-shaped OR an attribute-shaped input row.

    Both are supported on purpose: the web, MCP and CLI surfaces hand over
    JSON dicts, while a library caller can pass the real
    ``engine.yara_scan.RuleMatch`` / ``engine.truth_labels.TruthInterval``
    objects it already holds and should not have to serialise first.
    """
    if isinstance(row, Mapping):
        return row.get(name)
    return getattr(row, name, None)


def _score_coerce_int(value: Any, field: str, *, kind: str, index: int) -> int:
    """``int()`` one incoming field, refusing anything that would only LOOK right.

    ``bool`` is refused explicitly because ``int(True) == 1``: a ``key_offset``
    of ``true`` would otherwise score as a one-byte prediction instead of as
    the mistake it is. A non-integral float is refused for the same reason —
    truncation would move a byte boundary and never say so.
    """
    coerced: Optional[int] = None
    if isinstance(value, bool):
        coerced = None
    elif isinstance(value, int):
        coerced = value
    elif isinstance(value, float) and value.is_integer():
        coerced = int(value)
    elif isinstance(value, str):
        try:
            coerced = int(value.strip(), 10)
        except ValueError:
            coerced = None
    if coerced is None:
        raise CapabilityError(
            f"{kind}[{index}].{field} must be a whole number of bytes, got "
            f"{value!r} ({type(value).__name__})",
            category=ErrorCategory.INVALID_INPUT,
        )
    return coerced


def _score_offset(
    row: Any, field: str, *, kind: str, index: int, alt: Optional[str] = None,
) -> int:
    """A REQUIRED, non-negative byte position — absent is an error, not a zero.

    This refusal is the second half of the ``getattr`` guard described on
    :class:`_ScoredMatch`. The metrics engine coerces a missing field to ``0``,
    so a row that simply forgot ``offset`` would be scored as a firing at the
    start of the dump and would contribute real-looking true positives or false
    positives to the report. There is no safe default for "where did it fire",
    so the row is refused BY INDEX and BY FIELD and the caller fixes it.
    """
    value = _score_field(row, field)
    used = field
    if value is None and alt is not None:
        value, used = _score_field(row, alt), alt
    if value is None:
        raise CapabilityError(
            f"{kind}[{index}] carries no {field!r}"
            + (f" (nor {alt!r})" if alt else "")
            + f": every {kind[:-1]} needs an explicit byte position, because a "
            f"missing one would be scored as {field}=0 — a firing at the very "
            f"start of the dump — and would produce a plausible-looking report "
            f"of entirely fictional precision and recall. Supply it, or drop "
            f"the row.",
            category=ErrorCategory.INVALID_INPUT,
        )
    coerced = _score_coerce_int(value, used, kind=kind, index=index)
    if coerced < 0:
        raise CapabilityError(
            f"{kind}[{index}].{used} must be >= 0, got {coerced}",
            category=ErrorCategory.INVALID_INPUT,
        )
    return coerced


def _score_optional_int(row: Any, field: str, *, kind: str, index: int) -> Optional[int]:
    """An OPTIONAL field: ``None`` stays ``None``, and that is meaningful.

    A match with no ``key_offset`` makes no positional claim at all, and the
    engine excludes it from the ``key_offset``/``exact`` precision denominator
    rather than charging it as a false positive. Defaulting it to ``0`` here
    would turn "this rule predicts nothing about where the key is" into "this
    rule predicts the key is at the start of its window", which is a different
    and much worse claim.
    """
    value = _score_field(row, field)
    if value is None:
        return None
    return _score_coerce_int(value, field, kind=kind, index=index)


def _as_scored_match(match: Any, index: int) -> _ScoredMatch:
    """Normalise one incoming firing. See :class:`_ScoredMatch` for the why."""
    return _ScoredMatch(
        offset=_score_offset(match, "offset", kind="matches", index=index),
        length=_score_offset(match, "length", kind="matches", index=index),
        key_offset=_score_optional_int(
            match, "key_offset", kind="matches", index=index),
        key_length=_score_optional_int(
            match, "key_length", kind="matches", index=index),
    )


def _as_scored_truth(truth: Any, index: int) -> _ScoredTruth:
    """Normalise one incoming truth interval.

    ``start`` falls back to ``offset`` because the engine's own ``_truth_start``
    accepts both, and a caller pasting a hit row from ``locate_key`` has
    ``offset``. The fallback is spelled here so the two sides cannot diverge.
    """
    return _ScoredTruth(
        start=_score_offset(
            truth, "start", kind="truths", index=index, alt="offset"),
        length=_score_offset(truth, "length", kind="truths", index=index),
        source=str(_score_field(truth, "source") or ""),
    )


def _as_score_row(
    row: Any,
    index: int,
    *,
    matches: Any = None,
    truths: Any = None,
    detector: Optional[str] = None,
    dump: Optional[str] = None,
    truth_sources: Optional[Sequence[str]] = None,
) -> _ScoreRow:
    """Build one :class:`_ScoreRow` from a row mapping, or from loose parts.

    *row* is ``None`` for the single-pair intake, where the parts arrive as the
    producer's own keyword arguments instead. Either way the geometry goes
    through the same converters, so the two intakes cannot be scored by
    different rules.
    """
    if row is not None:
        if not isinstance(row, Mapping):
            raise CapabilityError(
                f"rows[{index}] must be an object with 'matches' / 'truths' "
                f"keys, got {type(row).__name__}",
                category=ErrorCategory.INVALID_INPUT,
            )
        matches = row.get("matches")
        truths = row.get("truths")
        detector = row.get("detector")
        dump = row.get("dump")
        truth_sources = row.get("truth_sources")
    scored_truths = tuple(
        _as_scored_truth(t, i) for i, t in enumerate(truths or ()))
    # Derived exactly as ``engine.detector_metrics._row_truth_sources`` derives
    # it, and then handed to the engine EXPLICITLY on every row, so the sources
    # this payload echoes are the ones the report was actually grouped by —
    # there is no second derivation to drift from this one.
    sources = (
        tuple(str(s) for s in truth_sources) if truth_sources
        else tuple(sorted({t.source for t in scored_truths} - {""}))
    )
    return _ScoreRow(
        detector=str(detector or "unknown"),
        dump=str(dump or ""),
        matches=tuple(_as_scored_match(m, i) for i, m in enumerate(matches or ())),
        truths=scored_truths,
        truth_sources=sources,
    )


def _score_detector_row(
    row: _ScoreRow,
    *,
    status: str,
    metrics: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """One row's payload, in ONE shape whatever could be established about it.

    ``metrics`` carries one ``IntervalDetectionMetrics.to_dict()`` per criterion
    on a scored row and is ``None`` on an unscorable one, mirroring
    ``_yara_scan_row``'s ``scan``. Nesting it — rather than flattening zeros
    onto a row that had nothing to be measured against — is what keeps "the
    detector missed every key" distinguishable from "there were no keys to
    miss": there is simply no ``recall: 0.0`` to misread.

    The status/metrics biconditional is asserted for the same reason
    ``_yara_scan_row`` asserts its own: the roll-up and the verdict below trust
    it, so a violation is a programming error rather than a strange result.
    """
    if status not in SCORE_ROW_STATUSES:
        raise ValueError(
            "unknown detector-score row status " + repr(status)
            + "; expected one of "
            + ", ".join(repr(s) for s in SCORE_ROW_STATUSES))
    if (status == SCORE_ROW_SCORED) != (metrics is not None):
        raise ValueError(
            "detector-score row status " + repr(status)
            + " contradicts metrics payload "
            + ("present" if metrics is not None else "absent"))
    return {
        "detector": row.detector,
        "dump": row.dump,
        "status": status,
        # Both denominators, on every row including an unscorable one: they are
        # what the engine's own docstring says a consumer must check before
        # treating a zero as a failure, so they must be readable without
        # descending into ``metrics`` (which is ``None`` exactly when the
        # question is sharpest).
        "matches": len(row.matches),
        "truths": len(row.truths),
        "truth_sources": list(row.truth_sources),
        "metrics": metrics,
    }


def _score_detector_diagnostics(
    rows: List[Dict[str, Any]],
    *,
    verdict: str,
    counts: Dict[str, int],
    tolerance_bytes: int,
    containment: Optional[Dict[str, Any]],
    key_offset: Optional[Dict[str, Any]],
) -> List[Diagnostic]:
    """Qualify a score — every way these numbers can mislead gets a voice.

    ``engine/detector_metrics.py`` publishes ``max_matches_per_truth`` and
    ``max_truths_per_match`` "precisely so that structure stays visible rather
    than being laundered into a single flattering score". A caller reading a
    rendered payload will not go looking for them, so the two ways they turn a
    good-looking rate into a meaningless one are lifted into diagnostics here
    as well as left on the metrics.

    *containment* / *key_offset* are the micro-averaged blocks from the
    report's ``overall``, or ``None`` when nothing was scorable.
    """
    diagnostics: List[Diagnostic] = []

    if verdict == SCORE_NO_TRUTHS:
        diagnostics.append(Diagnostic(
            code=SCORE_DETECTOR_NO_TRUTHS_CODE,
            message=(
                f"NOTHING was scorable: none of the {counts['rows_total']} "
                f"row(s) carried a truth interval, so the "
                f"{counts['matches_total']} firing(s) are neither confirmed "
                f"nor refuted. ``report`` is null rather than a block of "
                f"zeros — a precision of 0.0 here would read as 'every firing "
                f"was wrong', which is not what an empty truth set says."
            ),
            severity=Severity.WARNING,
            details={
                "rows_total": counts["rows_total"],
                "matches_total": counts["matches_total"],
            },
        ))
    elif verdict == SCORE_NO_MATCHES:
        diagnostics.append(Diagnostic(
            code=SCORE_DETECTOR_NO_MATCHES_CODE,
            message=(
                f"The detector fired on NONE of the {counts['truths_total']} "
                f"truth interval(s) across {counts['rows_scored']} scored "
                f"row(s). Unlike the no_truths case this recall of 0.0 is a "
                f"MEASURED total miss: the denominator is real, and the rule "
                f"generalises to none of these dumps."
            ),
            severity=Severity.INFO,
            details={
                "truths_total": counts["truths_total"],
                "rows_scored": counts["rows_scored"],
            },
        ))
    elif containment is not None and key_offset is not None:
        diagnostics.append(Diagnostic(
            code=SCORE_DETECTOR_SCORED_CODE,
            message=(
                f"Scored {counts['rows_scored']} row(s): containment "
                f"precision {containment['precision']:.3f} recall "
                f"{containment['recall']:.3f} (F1 {containment['f1']:.3f}) "
                f"over {containment['matches']} firing(s) and "
                f"{containment['truths']} key(s); key_offset recall "
                f"{key_offset['recall']:.3f} within {tolerance_bytes}B. Read "
                f"the criteria TOGETHER: containment says the window enclosed "
                f"the key, key_offset says the predicted position was right to "
                f"within alignment slack."
            ),
            severity=Severity.INFO,
            details={
                "containment": {
                    "precision": containment["precision"],
                    "recall": containment["recall"],
                    "f1": containment["f1"],
                },
                "key_offset": {
                    "precision": key_offset["precision"],
                    "recall": key_offset["recall"],
                    "f1": key_offset["f1"],
                },
            },
        ))

    if counts["rows_unscorable"]:
        diagnostics.append(Diagnostic(
            code=SCORE_DETECTOR_UNSCORABLE_ROWS_CODE,
            message=(
                f"{counts['rows_unscorable']} of {counts['rows_total']} row(s) "
                f"carried NO truth interval and were EXCLUDED from the report, "
                f"along with their {counts['matches_unscorable']} firing(s), so "
                f"no rate below is over them. Pooling them in would assert "
                f"those firings are false positives — a claim a row with no "
                f"truth set cannot support. If you KNOW those dumps hold no "
                f"key, matches_unscorable is published so you can compute the "
                f"stricter precision yourself."
            ),
            severity=Severity.WARNING,
            details={
                "rows": [r["dump"] or r["detector"] for r in rows
                         if r["status"] == SCORE_ROW_UNSCORABLE],
                "matches_unscorable": counts["matches_unscorable"],
            },
        ))

    if containment is not None and containment["max_truths_per_match"] > 1:
        swallowed = (
            containment["truths"] > 1
            and containment["max_truths_per_match"] == containment["truths"]
        )
        diagnostics.append(Diagnostic(
            code=SCORE_DETECTOR_FAN_OUT_CODE,
            message=(
                f"FAN-OUT {containment['max_truths_per_match']}: one firing's "
                f"window contained that many distinct keys"
                + (
                    f" — EVERY key in its row. A recall of "
                    f"{containment['recall']:.3f} reached this way is a "
                    f"property of how wide the emitted window is, not of the "
                    f"detector localising anything; narrow the pattern before "
                    f"reporting that number."
                    if swallowed else
                    ". Recall is truth-indexed, so a wide window can lift it "
                    "without the detector localising any single key."
                )
            ),
            severity=Severity.WARNING if swallowed else Severity.INFO,
            details={
                "max_truths_per_match": containment["max_truths_per_match"],
                "truths": containment["truths"],
                "recall": containment["recall"],
            },
        ))

    if containment is not None and containment["max_matches_per_truth"] > 1:
        diagnostics.append(Diagnostic(
            code=SCORE_DETECTOR_FAN_IN_CODE,
            message=(
                f"FAN-IN {containment['max_matches_per_truth']}: one key was "
                f"hit by that many separate firings. Precision is "
                f"match-indexed, so all of them count as true positives — "
                f"which flatters a rule set whose members overlap. This is "
                f"published rather than deduplicated because collapsing it "
                f"would hide whichever rule is redundant."
            ),
            severity=Severity.INFO,
            details={
                "max_matches_per_truth": containment["max_matches_per_truth"],
            },
        ))

    if (containment is not None and key_offset is not None
            and key_offset["matches"] < containment["matches"]):
        silent = containment["matches"] - key_offset["matches"]
        diagnostics.append(Diagnostic(
            code=SCORE_DETECTOR_NO_KEY_OFFSET_CODE,
            message=(
                f"{silent} of {containment['matches']} firing(s) carry no "
                f"key_offset, make NO positional claim, and are excluded from "
                f"the key_offset/exact precision denominator rather than "
                f"charged as false positives. Every MemDiver-emitted rule "
                f"carries the meta; a hand-written one may not — so those two "
                f"criteria are measured over {key_offset['matches']} firing(s) "
                f"while containment is measured over {containment['matches']}."
            ),
            severity=Severity.INFO,
            details={
                "matches_without_key_offset": silent,
                "key_offset_matches": key_offset["matches"],
                "containment_matches": containment["matches"],
            },
        ))
    return diagnostics


def score_detector_matches(
    *,
    matches: Optional[Sequence[Any]] = None,
    truths: Optional[Sequence[Any]] = None,
    detector: Optional[str] = None,
    dump: Optional[str] = None,
    truth_sources: Optional[Sequence[str]] = None,
    rows: Optional[Sequence[Any]] = None,
    tolerance_bytes: int = DEFAULT_TOLERANCE_BYTES,
) -> Dict[str, Any]:
    """Score detector firings against known-true key intervals.

    The single implementation behind the CLI ``score-detector`` command, the
    HTTP ``POST /api/scan/score`` route, the MCP ``score_detector_matches``
    tool and ``memdiver.services.score_detector_matches``.

    This is the second half of :func:`scan_yara_rule`. That producer answers
    "did the rule fire?"; it cannot answer "was it right?", and a census of
    firings with no ground truth beside it measures nothing — a rule matching
    every page yields a perfect ``dumps_matched`` and is worthless. Hand this
    producer a scan's ``dumps[].scan.matches`` and the key's known intervals
    and you get interval precision/recall under all three of the engine's
    criteria, with the many-to-many structure kept visible.

    NO dump is opened. Everything arrives as data, which is why there is no key
    material, no view and no locked-container guard in this signature.

    Supply the work in exactly ONE of two intakes:

    * ``matches`` + ``truths`` (+ optional ``detector`` / ``dump`` /
      ``truth_sources``) — ONE (detector, dump) pair.
    * ``rows`` — N pre-grouped rows, each a mapping with those same five keys.
      Rows are scored INDEPENDENTLY and only their counts are summed; pooling
      the intervals first would let a firing from one dump pair with a truth
      from another whose offsets happen to line up, inventing true positives.

    Each match may be a dict (``RuleMatch.to_dict()``, or JSON off the wire) or
    an object carrying the attributes; likewise each truth
    (``TruthInterval.to_dict()``, or the dataclass). Dicts are converted into
    attribute-carrying rows HERE, before the engine sees them, because
    ``engine/detector_metrics.py`` reads its inputs by ``getattr`` and coerces
    a missing field to ``0`` — so an unconverted dict scores as a firing at
    offset 0 with nothing raised. :class:`_ScoredMatch` spells that out; a row
    missing ``offset`` or ``length`` is refused rather than defaulted.

    Args:
        matches: Detector firings for the single-pair intake. Each needs
            ``offset`` and ``length``; ``key_offset`` / ``key_length`` are
            optional, and a firing without ``key_offset`` makes no positional
            claim and is excluded from the ``key_offset``/``exact``
            denominators rather than charged as a false positive.
        truths: Known-true key intervals. Each needs ``start`` (or ``offset``)
            and ``length``; ``source`` is carried so ledger corroboration is
            never laundered into a key-log recall denominator.
        detector: Rule/detector name for the single-pair intake. Defaults to
            ``"unknown"``, which is also what the engine would use.
        dump: Optional label for the single-pair intake, carried through for
            provenance.
        truth_sources: Optional override of the provenance derived from the
            intervals' own ``source`` fields.
        rows: The N-row intake. Mutually exclusive with the four arguments
            above, with no precedence.
        tolerance_bytes: Slack for the ``key_offset`` criterion. Defaults to
            :data:`DEFAULT_TOLERANCE_BYTES` (16), matching the ``alignment=16``
            of :func:`core.alignment_filter.alignment_filter`, so a detected
            region starting up to 15 bytes below the true key still counts as
            the same finding. The ``exact`` criterion always runs at 0.

    Returns:
        A bare dict carrying ``verdict``, the ``intake``, ``counts``, one row
        per input row, the micro-averaged ``report``, and ``diagnostics``.

        Read ``verdict`` before any number — only ``"scored"`` is a
        measurement (see :data:`SCORE_DETECTOR_VERDICTS`) — and read each row's
        ``truths`` count before its ``metrics``, exactly as the engine's own
        docstring requires: ``recall == 0.0`` with ``truths == 0`` means there
        was nothing to find, and only ``recall == 0.0`` with ``truths > 0``
        means the detector missed.

        ``report`` is ``None`` — not a block of zeros — when no row was
        scorable, for the same reason an unreadable dump's ``scan`` is ``None``
        in :func:`scan_yara_rule`.

    Raises:
        CapabilityError: INVALID_INPUT for zero or both intakes, for the
            pair-only decorations passed alongside ``rows``, for a negative
            ``tolerance_bytes``, and for any match/truth row whose byte
            geometry is missing or is not a whole non-negative number;
            PRECONDITION for an empty ``rows`` list.
    """
    # Function-local, the repo-wide idiom: the ``app`` layer must not pull the
    # engine's compute at module import time. Only DEFAULT_TOLERANCE_BYTES is
    # imported at module scope, because it is a keyword default in this
    # signature and so has to resolve when the signature is built.
    from memdiver.engine.detector_metrics import (
        CRITERIA,
        CRITERION_CONTAINMENT,
        CRITERION_KEY_OFFSET,
        aggregate_detector_report,
        score_intervals,
    )
    from memdiver.engine.key_location import ELAPSED_PRECISION

    # ``detector`` / ``dump`` / ``truth_sources`` count as the pair form too:
    # in the rows intake every row carries its own, so one supplied out here is
    # provenance the caller asked to record that nothing would ever read. It is
    # refused rather than ignored.
    supplied = [
        name for name, arg in (
            ("matches", matches), ("truths", truths), ("detector", detector),
            ("dump", dump), ("truth_sources", truth_sources),
        )
        if arg is not None
    ]
    # Exactly one intake, naming BOTH forms and every colliding argument, with
    # no precedence — the same posture ``scan_yara_rule`` takes over its two
    # rule forms, and for the same reason: silently preferring one would hand
    # the caller a complete, confident report scored over data they did not
    # mean.
    if bool(supplied) == (rows is not None):
        raise CapabilityError(
            "score_detector_matches() takes exactly ONE of matches=/truths= "
            "(one detector, one dump, optionally labelled with detector=/"
            "dump=/truth_sources=) or rows= (N pre-grouped rows, each carrying "
            "its own labels); "
            + (
                f"both were supplied (rows= alongside "
                f"{'=, '.join(supplied)}=)" if rows is not None
                else "neither was"
            )
            + ". There is no precedence between them.",
            category=ErrorCategory.INVALID_INPUT,
        )
    if tolerance_bytes < 0:
        # Refused rather than clamped: the engine clamps the RELATION to 0
        # (``max(tolerance_bytes, 0)``) but publishes ``tolerance_bytes``
        # verbatim on every metrics block, so a negative value would be
        # reported as the slack that was applied when it was not.
        raise CapabilityError(
            f"tolerance_bytes must be >= 0, got {tolerance_bytes}; 0 is the "
            f"exact-match criterion and is already reported alongside every "
            f"tolerant one",
            category=ErrorCategory.INVALID_INPUT,
        )

    started = time.perf_counter()
    if rows is not None:
        supplied = list(rows)
        if not supplied:
            raise CapabilityError(
                "Need at least 1 row to score, got 0",
                category=ErrorCategory.PRECONDITION,
            )
        normalized = [_as_score_row(r, i) for i, r in enumerate(supplied)]
        intake = SCORE_INTAKE_ROWS
    else:
        normalized = [_as_score_row(
            None, 0, matches=matches, truths=truths, detector=detector,
            dump=dump, truth_sources=truth_sources)]
        intake = SCORE_INTAKE_PAIR

    payload_rows: List[Dict[str, Any]] = []
    for row in normalized:
        if not row.truths:
            # Unscorable, and NOT merely "scored badly": with an empty truth
            # set every rate the engine would return is a vacuous zero, so the
            # row gets ``metrics: None`` and stays out of the roll-up.
            payload_rows.append(
                _score_detector_row(row, status=SCORE_ROW_UNSCORABLE))
            continue
        # Per-row metrics come from ``score_intervals`` and the roll-up from
        # ``aggregate_detector_report``, which scores each row again
        # internally. The relation is therefore computed twice — knowingly:
        # it is pure compute over two small interval lists, and the pass is
        # what buys the per-row ``pairs`` (every related (match, truth, delta)
        # triple) that the micro-average deliberately empties because its
        # indices are only meaningful within one row. Without it a report over
        # eight dumps could say the detector is imprecise and never say which
        # dump, nor by how many bytes it was off.
        scored = score_intervals(
            row.matches, row.truths, tolerance_bytes=tolerance_bytes)
        payload_rows.append(_score_detector_row(
            row,
            status=SCORE_ROW_SCORED,
            metrics={c: m.to_dict() for c, m in scored.items()},
        ))

    scorable = [r for r in normalized if r.truths]
    counts = {
        "rows_total": len(normalized),
        "rows_scored": len(scorable),
        "rows_unscorable": len(normalized) - len(scorable),
        # Rows that HAD keys to find and where the detector fired at all. A
        # scored row with no firings is a genuine total miss for that row, and
        # is counted here so it cannot be confused with an unscorable one.
        "rows_without_matches": sum(1 for r in scorable if not r.matches),
        "matches_total": sum(len(r.matches) for r in normalized),
        # THE precision denominator: firings on scorable rows only.
        "matches_scored": sum(len(r.matches) for r in scorable),
        "matches_unscorable": sum(
            len(r.matches) for r in normalized if not r.truths),
        "truths_total": sum(len(r.truths) for r in normalized),
        "detectors": len({r.detector for r in normalized}),
        "dumps": len({r.dump for r in normalized if r.dump}),
    }

    # Only the scorable rows are handed to the engine. See
    # :data:`SCORE_ROW_UNSCORABLE`: including a row with no truth set would put
    # its firings in the precision denominator with nothing to match them
    # against, which asserts they are false positives.
    report = aggregate_detector_report(
        [
            {
                "matches": row.matches,
                "truths": row.truths,
                "detector": row.detector,
                "dump": row.dump,
                "truth_sources": list(row.truth_sources),
            }
            for row in scorable
        ],
        tolerance_bytes=tolerance_bytes,
    ) if scorable else None

    if scorable and counts["matches_scored"]:
        verdict = SCORE_SCORED
    elif scorable:
        # Truths existed and the detector fired on none of them anywhere. A
        # real, measured total miss — which is exactly why it is NOT folded in
        # with ``no_truths`` below.
        verdict = SCORE_NO_MATCHES
    else:
        verdict = SCORE_NO_TRUTHS

    overall = report["overall"]["metrics"] if report else {}
    return {
        "verdict": verdict,
        "intake": intake,
        "tolerance_bytes": tolerance_bytes,
        "criteria": list(CRITERIA),
        "counts": counts,
        "rows": payload_rows,
        # ``None``, never a block of zeros, when nothing was scorable.
        "report": report,
        "elapsed_s": round(time.perf_counter() - started, ELAPSED_PRECISION),
        "diagnostics": [
            d.to_dict() for d in _score_detector_diagnostics(
                payload_rows,
                verdict=verdict,
                counts=counts,
                tolerance_bytes=tolerance_bytes,
                containment=overall.get(CRITERION_CONTAINMENT),
                key_offset=overall.get(CRITERION_KEY_OFFSET),
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
    # FIRST in the list on purpose: every other diagnostic below is a QUALITY
    # judgement on a rule that at least works, while this one says the rule
    # cannot fire at all. A reader who acts on only the first entry should act
    # on that one.
    over_limit = _scan_limit_diagnostic(payload.get("pattern") or {},
                                        context=context)
    if over_limit is not None:
        diagnostics.append(over_limit)
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
    # ``<=`` on the bits clause, not ``<``: the calibrated floor IS 0.0 (see the
    # constants block, which measures why), and ``bits < 0.0`` can never be true
    # -- a silently dead predicate of the kind this tree has been bitten by
    # before. With the floor at 0.0 the clause fires exactly when the anchors
    # carry no information at all, which is ``distinct_bytes == 1`` and so
    # already inside the bytes clause: the bits half now adds no alarm the
    # measured sweep did not already attribute to ``distinct_bytes``. It is kept
    # because ``details`` publishes ``shannon_bits`` to the operator, and a gate
    # that ignored a number it shows them would be free to drift from it.
    #
    # DECIDING clause is the FIRST one. ``distinct_bytes < 3`` is what separates
    # the 22 unselective cells from the 70 perfect ones with no false alarm.
    if (distinctiveness["distinct_bytes"] < KEY_PATTERN_MIN_ANCHOR_BYTES
            or distinctiveness["shannon_bits"] <= KEY_PATTERN_MIN_ANCHOR_BITS):
        diagnostics.append(Diagnostic(
            code=KEY_PATTERN_DEGENERATE_ANCHORS_CODE,
            message=(
                f"The static anchors carry only "
                f"{distinctiveness['distinct_bytes']} distinct byte value(s) "
                f"({distinctiveness['shannon_bits']} bits/byte, longest "
                f"constant run {distinctiveness['longest_constant_run']} of "
                f"{distinctiveness['static_bytes']} static bytes), so what "
                f"this rule pins is filler rather than structure and it can "
                f"fire wherever the same filler occurs. MEASURE YOUR OWN "
                f"rule rather than trust a figure from someone else's "
                f"corpus: write it out with --output-dir, then "
                f"`memdiver scan-yara --rule-file <rule> --count-only "
                f"--no-max-matches <dumps>` reports the uncapped census "
                f"without the match lists. For scale, on the reference "
                f"corpus this shape fires 825,779 times in its own 11 MB "
                f"source dump under libyara and 5,311 times under "
                f"Volatility3's non-overlapping RegExScanner (pinned by "
                f"tests/test_vol3_verify.py) — the same rule and the same "
                f"dump, 155x apart, which is why a selectivity count means "
                f"nothing without the engine that produced it. Raise "
                f"--context until the window reaches structural bytes, or "
                f"combine this pattern with a coarser locator."
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


# ---------------------------------------------------------------------------
# D3 — VERIFYING the plugin we emit, in both of the ways a user runs it
# ---------------------------------------------------------------------------
#
# ``scan_yara_rule`` (D1) runs the YARA half of an export. The Volatility3 half
# had the same hole and a worse one: for most of this repo's life an emitted
# plugin was checked only by ``ast.parse`` and substring assertions over the
# generated text, so a plugin that could not be IMPORTED -- let alone find a key
# -- passed every test in the suite. Phase B's four real bugs were all found by
# RUNNING things, one of them a vol3 export that disagreed with the YARA rule it
# embedded.
#
# ``engine/vol3_verify.py`` (in-process) and ``engine/vol3_subproc.py``
# (subprocess) were written to make that repeatable and were reachable from NO
# surface at all -- the same shape of hole ``engine/yara_scan.py`` sat in before
# D1. This producer is both of them, on all four surfaces.
#
# Why BOTH paths and not just the cheap one: they answer different questions and
# on this machine they answer with different framework versions. In-process
# asks "does the plugin work against the Volatility3 MemDiver imports?"
# (measured 2.27.0 here). Subprocess asks "does it work the way the user runs
# it?" -- ``vol -p <dir> -f <dump> <module>.<Class>`` against the user's own
# checkout (measured 2.27.1 here, from a tree whose ``pip show`` says 2.27.1 and
# whose bare ``import volatility3`` says 2.28.2). A verification result that
# does not name the framework that produced it is worthless, which is why every
# row carries its ``mode_used`` and its RESOLVED ``framework_version``.

#: Which runtime ran the plugin.
#:
#: * ``"auto"`` (the default) prefers IN-PROCESS -- the PyPI ``volatility3`` in
#:   MemDiver's own environment -- and falls back to an external launcher. That
#:   ordering is the user's stated requirement ("by default the pypi version
#:   should be used but users should also be able to set the path to the actual
#:   tool") and it is also the only order that can serve a ``.msl``: see
#:   :data:`VOL3_MODE_SUBPROCESS` below.
#: * ``"in_process"`` forces :mod:`engine.vol3_verify`.
#: * ``"subprocess"`` forces :mod:`engine.vol3_subproc`.
VOL3_MODE_AUTO = "auto"
VOL3_MODE_IN_PROCESS = "in_process"
VOL3_MODE_SUBPROCESS = "subprocess"
VOL3_MODES = (VOL3_MODE_AUTO, VOL3_MODE_IN_PROCESS, VOL3_MODE_SUBPROCESS)

#: What HAPPENED to one dump. Three-valued, and the third value is the one this
#: producer exists to keep separate from a zero:
#:
#: * ``"verified"``   — the plugin ran over this dump's bytes. ``run`` is
#:                      present and its ``match_count`` is a measurement.
#: * ``"unreadable"`` — the dump could not be opened. ``run`` is ``None``.
#: * ``"unsupported"``— the requested MODE cannot address this dump's bytes at
#:                      all. ``run`` is ``None``. MEASURED, not theoretical:
#:                      ``vol`` takes a bare file path and never goes through
#:                      MemDiver's container layer, so on an ``.msl`` it scans
#:                      the CONTAINER FILE. On the ground-truth run that means
#:                      it reports the key at 371752 where every MemDiver
#:                      coordinate says 370672 — skewed by the container's own
#:                      header size (1080 bytes for that import; it is not a
#:                      constant), i.e. a confident WRONG offset, not a zero.
#:                      A wrong answer is worse than no answer, so a forced
#:                      ``subprocess`` over a container refuses this dump and
#:                      says why.
VERIFY_VERIFIED = "verified"
VERIFY_UNREADABLE = "unreadable"
VERIFY_UNSUPPORTED = "unsupported"
VERIFY_PLUGIN_STATUSES = (VERIFY_VERIFIED, VERIFY_UNREADABLE, VERIFY_UNSUPPORTED)

#: The cross-dump verdict, in :data:`YARA_SCAN_VERDICTS`' four-valued shape and
#: for its reasons — only ONE of the four is an absence.
#:
#: * ``"hit"``          — the plugin fired on at least one dump.
#: * ``"no_hit"``       — at least one dump was scanned end to end with no row,
#:                        and no such zero was degraded. The ONLY value that may
#:                        be read as "this plugin does not fire here".
#: * ``"inconclusive"`` — nothing fired, and every zero came off a degraded run
#:                        (a view that sized to 0 bytes), so the zeros are
#:                        unproven.
#: * ``"not_run"``      — no dump was verified at all: no runtime was usable for
#:                        them, or every dump was unreadable. Claims NOTHING,
#:                        and in particular is what a forced ``subprocess`` over
#:                        an ``.msl`` returns instead of a zero.
VERIFY_HIT = "hit"
VERIFY_NO_HIT = "no_hit"
VERIFY_INCONCLUSIVE = "inconclusive"
VERIFY_NOT_RUN = "not_run"
VERIFY_PLUGIN_VERDICTS = (
    VERIFY_HIT, VERIFY_NO_HIT, VERIFY_INCONCLUSIVE, VERIFY_NOT_RUN,
)

#: How the plugin was supplied. Echoed so a reader need not re-derive it from
#: which request field happened to be set.
VERIFY_INTAKE_PATH = "path"
VERIFY_INTAKE_SOURCE = "source"

VERIFY_PLUGIN_NOT_RUN_CODE = "analysis.verify_plugin.not_run"
VERIFY_PLUGIN_INCONCLUSIVE_CODE = "analysis.verify_plugin.inconclusive"
VERIFY_PLUGIN_NO_HIT_CODE = "analysis.verify_plugin.no_hit"
VERIFY_PLUGIN_PARTIAL_CODE = "analysis.verify_plugin.partial"
VERIFY_PLUGIN_UNREADABLE_CODE = "analysis.verify_plugin.unreadable"
VERIFY_PLUGIN_UNSUPPORTED_CODE = "analysis.verify_plugin.unsupported"
VERIFY_PLUGIN_ZERO_BYTES_CODE = "analysis.verify_plugin.zero_bytes"
VERIFY_PLUGIN_VERSION_SKEW_CODE = "analysis.verify_plugin.version_skew"
VERIFY_PLUGIN_KEY_MISSING_CODE = "analysis.verify_plugin.key_not_recovered"
VERIFY_PLUGIN_HITS_CAPPED_CODE = "analysis.verify_plugin.hits_capped"
VERIFY_PLUGIN_COUNT_ONLY_CODE = "analysis.verify_plugin.count_only"
VERIFY_PLUGIN_PID_UNPROVEN_CODE = "analysis.verify_plugin.pid_unproven"

#: Whether a verified row carries its per-hit LIST. ``True`` is the default on
#: every surface, exactly as :data:`DEFAULT_INCLUDE_MATCHES` is for D1, and for
#: the same reason: an unselective pattern (the emitter's default 64-byte pad
#: over a zero run) fires thousands of times per dump and each hit carries the
#: key hex, so the payload has to be boundable independently of the run.
DEFAULT_INCLUDE_HITS = True


def _verify_plugin_source(
    plugin_path: Optional[str], plugin_source: Optional[str],
) -> Tuple[str, str, Optional[Path]]:
    """Resolve the emitted plugin to ``(intake, source_text, path_or_None)``.

    Exactly ONE of the two forms, named by BOTH names in the refusal and with
    no precedence between them — the posture :func:`scan_yara_rule` takes over
    its two rule forms, for its reason: silently preferring one would hand back
    a confident verification of a plugin the caller did not mean to test.

    The existence probe is wrapped, and that guard is load-bearing rather than
    defensive. An emitted plugin's SOURCE is ~20 KB, which is far longer than
    ``NAME_MAX`` on every ordinary filesystem, and ``Path.is_file()`` RAISES
    ``OSError`` (ENAMETOOLONG) for such a value instead of returning ``False``.
    So a caller who puts the source text in ``plugin_path=`` by mistake would
    get a bare ``OSError`` traceback out of a path check rather than this
    module's own refusal. Same guard, for the same measured reason, as
    ``_score_json_from_args`` in ``cli/pipeline.py``.
    """
    if (plugin_path is None) == (plugin_source is None):
        raise CapabilityError(
            "verify_vol3_plugin() takes exactly ONE of plugin_path= (a .py "
            "file on disk) or plugin_source= (the plugin's Python text); "
            + ("both were supplied" if plugin_path is not None else "neither was")
            + ". There is no precedence between them.",
            category=ErrorCategory.INVALID_INPUT,
        )
    if plugin_source is not None:
        return VERIFY_INTAKE_SOURCE, plugin_source, None
    path = Path(str(plugin_path)).expanduser()
    try:
        exists = path.is_file()
    except OSError:
        exists = False
    if not exists:
        raise FileNotFoundServiceError(f"File not found: {path}")
    return VERIFY_INTAKE_PATH, path.read_text(), path


def _verify_plugin_hits_from_rows(rows: Sequence[Dict[str, Any]]) -> List[Any]:
    """Turn ``vol``'s ``-r json`` rows into the same ``Vol3Hit``s in-process makes.

    One shape for both runtimes is the whole point: the payload's ``run`` block
    is built by :func:`_verify_plugin_run` from a list of ``Vol3Hit``, so a
    caller comparing an in-process verification against a subprocess one is
    comparing like with like rather than two hand-shaped dicts that agreed on
    the day they were written.

    Columns are read BY NAME, never by position, so a reordered ``_COLUMNS`` in
    the emitted template cannot silently swap ``KeyOffset`` for
    ``PatternOffset``.
    """
    from memdiver.engine.vol3_verify import Vol3Hit

    hits: List[Any] = []
    for row in rows:
        pattern_offset = int(row["PatternOffset"])
        key_absolute = int(row["KeyOffset"])
        hits.append(Vol3Hit(
            offset=pattern_offset,
            # ``vol`` does not print PATTERN_LENGTH as a column, so the window
            # width comes from the plugin's own module constant, read by the
            # caller and passed in below.
            length=0,
            key_offset=key_absolute - pattern_offset,
            key_length=int(row["KeyLength"]),
            key_hex=str(row["KeyHex"]),
            key_entropy=float(row["KeyEntropy"]),
            static_ratio=float(row["StaticRatio"]),
        ))
    return hits


def _verify_plugin_run(
    *,
    plugin_class_name: str,
    layer_scanned: str,
    layer_bytes: int,
    window_length: int,
    hits: Sequence[Any],
    match_count: int,
    expected_offset: Optional[int],
    anchor_bytes: int,
    anchor_distinct_bytes: int,
    key_bytes: Optional[bytes],
    include_hits: bool,
) -> Dict[str, Any]:
    """ONE run's payload, in ONE shape whichever runtime produced it.

    ``expected_offset_reported`` is EXACT membership with no tolerance, which is
    :class:`engine.vol3_verify.Vol3VerifyReport`'s own choice and is kept here
    deliberately: the failure this instrument exists to catch is "the plugin
    reported a hit 64 bytes from the real key", and a tolerance would score
    that as a near miss instead of the miss it is.

    ``key_recovered`` is the strongest single claim available — not "a hit
    landed near the key" but "the plugin handed back the key's exact bytes" —
    and is ``None``, never ``False``, when no ``key_hex`` was supplied. It is
    computed over the RETAINED hits, so ``hits_capped`` below is the flag that
    says a ``False`` might be an artefact of the cap rather than a real absence.

    ``include_hits=False`` REMOVES the ``hits`` key rather than emptying it, for
    the reason :func:`_yara_scan_payload` removes ``matches``: an empty list
    would make a count-only row with thousands of firings indistinguishable
    from a proven-clean one to ``len(run["hits"])``, and an absent key cannot be
    misread as an empty one.
    """
    retained = list(hits)
    reported = expected_offset is not None and any(
        hit.key_absolute_offset == expected_offset for hit in retained
    )
    per_mib = match_count / (layer_bytes / (1024 * 1024)) if layer_bytes else 0.0
    run: Dict[str, Any] = {
        "plugin_class_name": plugin_class_name,
        "layer_scanned": layer_scanned,
        "layer_bytes": layer_bytes,
        "window_length": window_length,
        "match_count": match_count,
        "hits_retained": len(retained),
        # A FLOOR on ``hits`` (never on ``match_count``, which is always the
        # honest total) — and the reason ``key_recovered`` may be a false
        # negative, so it is published rather than inferred.
        "hits_capped": match_count > len(retained),
        "expected_offset": expected_offset,
        "expected_offset_reported": reported,
        "key_recovered": (
            None if key_bytes is None
            else any(hit.key_hex == key_bytes.hex() for hit in retained)
        ),
        "anchor_bytes": anchor_bytes,
        # The single most predictive number for selectivity: an anchor of 128
        # zero bytes has ``anchor_distinct_bytes == 1`` and fires anywhere a
        # long zero run exists, however high its static ratio looks.
        "anchor_distinct_bytes": anchor_distinct_bytes,
        "matches_per_mib": round(per_mib, 4),
    }
    if include_hits:
        run["hits"] = [
            {
                "offset": hit.offset,
                "length": window_length,
                "key_offset": hit.key_offset,
                "key_absolute_offset": hit.key_absolute_offset,
                "key_length": hit.key_length,
                "key_hex": hit.key_hex,
                "key_entropy": hit.key_entropy,
                "static_ratio": hit.static_ratio,
            }
            for hit in retained
        ]
    else:
        run["hits_omitted"] = True
    return run


def _verify_plugin_row(
    path: Path,
    *,
    status: str,
    mode_used: Optional[str] = None,
    framework_version: Optional[Sequence[int]] = None,
    view: Optional[str] = None,
    run: Optional[Dict[str, Any]] = None,
    detail: str = "",
) -> Dict[str, Any]:
    """One dump's row, in ONE shape whatever happened to that dump.

    ``run`` is ``None`` on every row that is not ``"verified"``, mirroring
    :func:`_yara_scan_row`'s ``scan``: there is simply no ``match_count: 0`` on
    an unreadable or unsupported row for a falsy check to misread as a proven
    absence.

    ``mode_used`` and ``framework_version`` are per-ROW rather than per-request
    because under ``mode="auto"`` the fallback can legitimately differ per dump
    (in-process for a container, the launcher for a flat dump), and because a
    result that does not name the framework that produced it cannot be acted on
    — three Volatility3 trees commonly coexist on one machine and they disagree.
    """
    if status not in VERIFY_PLUGIN_STATUSES:
        raise ValueError(
            "unknown verify-plugin status " + repr(status) + "; expected one of "
            + ", ".join(repr(s) for s in VERIFY_PLUGIN_STATUSES))
    if (status == VERIFY_VERIFIED) != (run is not None):
        raise ValueError(
            "verify-plugin status " + repr(status) + " contradicts run payload "
            + ("present" if run is not None else "absent"))
    return {
        "dump_path": str(path),
        "name": path.name,
        "status": status,
        # Why this dump was not verified; "" on a verified row.
        "detail": detail,
        "mode_used": mode_used,
        "framework_version": list(framework_version) if framework_version else None,
        # The view the bytes came from. ``None`` in subprocess mode, where the
        # bytes are whatever ``vol`` mapped off the path — which is exactly why
        # a container is refused there rather than reported in the wrong space.
        "view": view,
        "run": run,
    }


def _verify_row_degraded(run: Dict[str, Any]) -> bool:
    """True when a verified row did NOT cover any bytes.

    The quiet false-absence channel, and the same one
    :func:`_yara_row_degraded` guards: a view that sizes to 0 — an empty file,
    or an ``.msl`` whose container holds nothing this view can project — is
    handed to the plugin, reports no error, finds nothing, and would otherwise
    fall straight into ``dumps_no_hit``. Declaring a plugin non-firing having
    compared ZERO bytes is the worst instance of a silent all-clear.
    """
    return not run["layer_bytes"]


#: Wall-clock ceiling for ONE subprocess plugin run, re-exported from the
#: engine rather than re-literalled so the CLI flag, the Pydantic model and the
#: MCP tool advertise the same budget the library applies.
VOL3_SUBPROC_TIMEOUT_S = _VOL3_DEFAULT_TIMEOUT_SECONDS

#: Hits RETAINED per dump, from :mod:`engine.vol3_verify`, for the same reason.
VOL3_MAX_HITS = _VOL3_DEFAULT_MAX_HITS


class _VerifyShape(NamedTuple):
    """The per-REQUEST facts both runners need to shape a row identically.

    The whole value of running a plugin two ways is that the two answers are
    comparable; twelve repeated keyword arguments across two call sites is how
    that stops being true. Handing both runners one object makes a divergence a
    type error rather than a subtly different payload.
    """

    plugin_class: str
    window_length: int
    anchor_bytes: int
    anchor_distinct: int
    expected_offset: Optional[int]
    key_bytes: Optional[bytes]
    pid: Optional[int]
    max_hits: int
    include_hits: bool


def _verify_plugin_class_name(source: str) -> str:
    """The emitted plugin's class name, read out of its own text.

    Read from the source rather than derived from a filename because the
    emitter derives the two independently — the same reason
    :func:`engine.vol3_subproc.plugin_module_name` reads it.
    """
    match = re.search(r"^class\s+(\w+)\s*\(", source, re.M)
    if match is None:
        raise CapabilityError(
            "the supplied plugin declares no class at all, so there is "
            "nothing to run. Pass an emitted Volatility3 plugin (the "
            "``vol3`` format of export_key_pattern / export_pattern).",
            category=ErrorCategory.INVALID_INPUT,
        )
    return match.group(1)


def _verify_in_process(
    source: Any,
    *,
    source_text: str,
    path: Path,
    view: str,
    flat_file: bool,
    shape: _VerifyShape,
) -> Dict[str, Any]:
    """Run the plugin in THIS interpreter, over bytes MemDiver resolved.

    The byte-source choice mirrors :func:`engine.yara_scan.scan_source`'s
    exactly, and for its reasons:

    * a raw dump read in its ``raw`` view goes through
      :func:`engine.vol3_verify.run_over_file`, which registers a flat
      ``physical.FileLayer`` — the file offset IS the view offset there, and it
      is the only option that does not materialise a multi-GB dump;
    * everything else goes through :func:`~engine.vol3_verify.run_over_buffer`
      with the PROJECTED view, because an ``.msl``'s bytes have to be decrypted
      and/or VAS-projected before an offset means anything. This is the branch
      that makes a container verifiable at all, and it is why ``mode="auto"``
      prefers this runtime.

    Note what ``run_over_file`` deliberately does NOT do: it never runs
    Volatility3's ``LayerStacker``. MemDiver's flat dumps carry an ELF header
    with ``e_type = ET_DYN``, so the stacker would wrap the dump in an
    ``Elf64Layer`` exposing ~6 KB of an 11 MB file and the scan would see
    nothing. The emitted plugin's own layer walk is what handles that in the
    subprocess path, where the stacker DOES run.
    """
    from memdiver.engine.vol3_verify import run_over_buffer, run_over_file

    extra_config = {"pid": shape.pid} if shape.pid is not None else None
    if flat_file:
        report = run_over_file(
            source_text, Path(source.path),
            expected_offset=shape.expected_offset,
            extra_config=extra_config,
            max_hits=shape.max_hits,
        )
    else:
        report = run_over_buffer(
            source_text, source.read_all(view),
            expected_offset=shape.expected_offset,
            extra_config=extra_config,
            max_hits=shape.max_hits,
        )
    return _verify_plugin_row(
        path,
        status=VERIFY_VERIFIED,
        mode_used=VOL3_MODE_IN_PROCESS,
        framework_version=report.framework_version,
        view=view,
        run=_verify_plugin_run(
            plugin_class_name=report.plugin_class_name,
            layer_scanned=report.layer_scanned,
            layer_bytes=report.layer_bytes,
            window_length=shape.window_length,
            hits=report.hits,
            match_count=report.match_count,
            expected_offset=shape.expected_offset,
            anchor_bytes=shape.anchor_bytes,
            anchor_distinct_bytes=shape.anchor_distinct,
            key_bytes=shape.key_bytes,
            include_hits=shape.include_hits,
        ),
    )


def _verify_subprocess(
    *,
    path: Path,
    plugin_file: Path,
    launcher: Any,
    framework_version: Optional[Sequence[int]],
    layer_bytes: int,
    timeout_s: int,
    shape: _VerifyShape,
) -> Dict[str, Any]:
    """Run the plugin through a REAL ``vol`` launcher, the way a user does.

    ``--pid`` and any other plugin flag go in ``plugin_args``, appended AFTER
    the target, because ``vol``'s CLI is an argparse subcommand parser: the same
    flag placed before the plugin name exits 2 with "unrecognized arguments"
    (measured against the author's 2.27.1 checkout).

    The hit list is capped HERE rather than by the launcher, so ``match_count``
    stays the honest total: ``vol`` has no cap to ask for, and truncating the
    count as well as the list would turn a selectivity measurement into a
    reading of ``max_hits``.
    """
    from memdiver.engine.vol3_subproc import run_plugin

    plugin_args: List[str] = []
    if shape.pid is not None:
        plugin_args += ["--pid", str(shape.pid)]
    rows = run_plugin(
        launcher, plugin_file, path,
        plugin_args=plugin_args, timeout=timeout_s,
    )
    hits = _verify_plugin_hits_from_rows(rows)
    return _verify_plugin_row(
        path,
        status=VERIFY_VERIFIED,
        mode_used=VOL3_MODE_SUBPROCESS,
        framework_version=framework_version,
        # ``None`` on purpose: ``vol`` mapped the FILE, not a MemDiver view. The
        # only reason that is comparable to the in-process row at all is that a
        # container never reaches this runner — it is refused as
        # ``"unsupported"`` upstream.
        view=None,
        run=_verify_plugin_run(
            plugin_class_name=shape.plugin_class,
            # The plugin walks ``layer.dependencies`` down to the lowest layer
            # by default, so the bytes it scanned are the FILE's. Named for what
            # it is rather than borrowed from the in-process layer name.
            layer_scanned="file",
            layer_bytes=layer_bytes,
            window_length=shape.window_length,
            hits=hits[:shape.max_hits],
            match_count=len(hits),
            expected_offset=shape.expected_offset,
            anchor_bytes=shape.anchor_bytes,
            anchor_distinct_bytes=shape.anchor_distinct,
            key_bytes=shape.key_bytes,
            include_hits=shape.include_hits,
        ),
    )


#: Pulls ``PATTERN_LENGTH`` out of an emitted plugin's text.
#:
#: Needed because ``vol`` does not print the window width as a column, so the
#: subprocess path has no other way to report a hit's ``length`` — and reporting
#: ``0`` there while in-process reports 560 would make the two runtimes
#: incomparable, which is the one thing this producer must not allow.
_VERIFY_PATTERN_LENGTH = re.compile(r"^PATTERN_LENGTH\s*=\s*(\d+)\s*$", re.M)

#: Pulls ``PATTERN_NAME`` out, for naming the temp module a ``plugin_source``
#: intake is written to. Only cosmetic — ``plugin_module_name`` reads the CLASS
#: out of the source itself.
_VERIFY_PATTERN_NAME = re.compile(r"^PATTERN_NAME\s*=\s*[\"'](.*)[\"']\s*$", re.M)


def _verify_plugin_window_length(source: str) -> int:
    match = _VERIFY_PATTERN_LENGTH.search(source)
    return int(match.group(1)) if match else 0


def _verify_plugin_module_stem(source: str) -> str:
    match = _VERIFY_PATTERN_NAME.search(source)
    stem = re.sub(r"\W+", "_", match.group(1)) if match else "memdiver_plugin"
    # A leading digit is a legal filename and an illegal module name, and
    # ``vol -p`` addresses the file AS a module.
    return stem if stem and not stem[0].isdigit() else f"p_{stem}"


def _verify_plugin_runtime(
    *, mode: str, vol_bin: Optional[str], vol_python: Optional[str],
) -> Dict[str, Any]:
    """Resolve BOTH runtimes and describe them, before a single dump is opened.

    The returned block is the part of the payload that makes a verification
    actionable, and it is not optional decoration. Three Volatility3 trees
    commonly coexist on one machine and they disagree; on this one the PyPI
    package MemDiver imports is 2.27.0 while the author's checkout answers
    2.27.1 as a script (and 2.28.2 to a bare ``import``, from the same venv,
    because an editable install's finder points at a sibling). A row that says
    "1 hit at 370672" without saying which framework produced it cannot be
    reproduced, so ``framework_version`` is resolved for both runtimes and
    ``versions_agree`` states the answer rather than leaving it to be eyeballed.

    The launcher's version is read by :func:`engine.vol3_subproc.probe_version`,
    which probes WITH ``cwd`` set to the launcher's own directory. Do not
    "simplify" that away: the script directory shadows the editable finder, so
    it is the only invocation whose answer matches what ``vol.py`` will load.
    """
    from memdiver.engine import vol3_subproc
    from memdiver.engine.vol3_verify import HAS_VOLATILITY3, framework_version

    in_process: Dict[str, Any] = {"available": bool(HAS_VOLATILITY3)}
    in_process["framework_version"] = (
        list(framework_version()) if HAS_VOLATILITY3 else None
    )

    # Resolved again for the runner's use. Resolution only STATS files -- the
    # expensive part, ``probe_version``, ran once inside
    # ``_verify_plugin_runtime`` above -- so this is deliberately a second cheap
    # call rather than a launcher threaded out of a function whose job is to
    # describe runtimes.
    launcher = vol3_subproc.resolve_launcher(vol_bin=vol_bin, vol_python=vol_python)
    subprocess_block: Dict[str, Any] = {
        "available": launcher is not None,
        "framework_version": None,
        # The launcher's identity, in full. ``cwd`` and ``python`` are as
        # load-bearing as the path: which framework a checkout's ``vol.py``
        # loads depends on all three.
        "launcher": launcher.describe() if launcher else None,
        "argv": list(launcher.argv) if launcher else None,
        "cwd": str(launcher.cwd) if launcher else None,
        "python": launcher.python if launcher else None,
        "source": launcher.source if launcher else None,
    }
    if launcher is not None:
        version = vol3_subproc.probe_version(launcher)
        subprocess_block["framework_version"] = list(version) if version else None

    both = (in_process["framework_version"], subprocess_block["framework_version"])
    return {
        "mode_requested": mode,
        "in_process": in_process,
        "subprocess": subprocess_block,
        # ``None`` — not ``True`` — when either side is unknown. "We could not
        # tell" and "they match" are different facts.
        "versions_agree": (
            None if None in both else both[0] == both[1]
        ),
        "launcher": vol3_subproc.launcher_report(
            vol_bin=vol_bin, vol_python=vol_python,
        ),
    }


def _verify_plugin_diagnostics(
    rows: Sequence[Dict[str, Any]],
    *,
    verdict: str,
    counts: Dict[str, Any],
    runtime: Dict[str, Any],
    key_bytes: Optional[bytes],
    include_hits: bool,
    pid: Optional[int],
) -> List[Diagnostic]:
    """Everything qualifying the numbers above, in the order it should be read."""
    diagnostics: List[Diagnostic] = []

    if verdict == VERIFY_NOT_RUN:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_NOT_RUN_CODE,
            message=(
                f"No dump was verified: {counts['dumps_unsupported']} could not "
                f"be addressed by the requested runtime and "
                f"{counts['dumps_unreadable']} could not be read. This result "
                f"claims NOTHING about the plugin — it is not a zero."
            ),
            severity=Severity.WARNING,
            details={
                "dumps_total": counts["dumps_total"],
                "dumps_unsupported": counts["dumps_unsupported"],
                "dumps_unreadable": counts["dumps_unreadable"],
            },
        ))
    elif verdict == VERIFY_INCONCLUSIVE:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_INCONCLUSIVE_CODE,
            message=(
                "The plugin fired nowhere, but every zero came off a run that "
                "covered 0 bytes, so the zeros are UNPROVEN. Do not read this "
                "as 'the plugin does not fire here'."
            ),
            severity=Severity.WARNING,
            details={"dumps_zero_bytes": counts["dumps_zero_bytes"]},
        ))
    elif verdict == VERIFY_NO_HIT:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_NO_HIT_CODE,
            message=(
                f"The plugin ran end to end over "
                f"{counts['dumps_verified']} dump(s) and fired on none of "
                f"them. This zero is MEASURED."
            ),
            severity=Severity.INFO,
            details={"dumps_verified": counts["dumps_verified"]},
        ))
    elif counts["dumps_verified"] and counts["dumps_hit"] < counts["dumps_verified"]:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_PARTIAL_CODE,
            message=(
                f"Fired on {counts['dumps_hit']} of "
                f"{counts['dumps_verified']} verified dump(s). Partial "
                f"survival is the normal shape of a real key across a process "
                f"lifecycle; the silent dumps are evidence, not a shortfall."
            ),
            severity=Severity.INFO,
            details={
                "dumps_hit": counts["dumps_hit"],
                "dumps_verified": counts["dumps_verified"],
            },
        ))

    unsupported = [r for r in rows if r["status"] == VERIFY_UNSUPPORTED]
    if unsupported:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_UNSUPPORTED_CODE,
            message=(
                f"{len(unsupported)} dump(s) were REFUSED by the requested "
                f"runtime rather than reported as zero: "
                + "; ".join(f"{r['name']}: {r['detail']}" for r in unsupported[:3])
                + ("; ..." if len(unsupported) > 3 else "")
            ),
            severity=Severity.WARNING,
            details={"dumps": [r["name"] for r in unsupported]},
        ))

    unreadable = [r for r in rows if r["status"] == VERIFY_UNREADABLE]
    if unreadable:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_UNREADABLE_CODE,
            message=(
                f"{len(unreadable)} dump(s) could not be read: "
                + "; ".join(f"{r['name']}: {r['detail']}" for r in unreadable[:3])
                + ("; ..." if len(unreadable) > 3 else "")
            ),
            severity=Severity.WARNING,
            details={"dumps": [r["name"] for r in unreadable]},
        ))

    if counts["dumps_zero_bytes"]:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_ZERO_BYTES_CODE,
            message=(
                f"{counts['dumps_zero_bytes']} verified dump(s) presented 0 "
                f"bytes to the plugin. Their zeros prove nothing — check the "
                f"view, and whether an encrypted container was unlocked."
            ),
            severity=Severity.WARNING,
            details={"dumps_zero_bytes": counts["dumps_zero_bytes"]},
        ))

    if runtime["versions_agree"] is False:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_VERSION_SKEW_CODE,
            message=(
                "The two runtimes resolve DIFFERENT Volatility3 versions: "
                f"in-process "
                f"{'.'.join(map(str, runtime['in_process']['framework_version']))}"
                f" vs launcher "
                f"{'.'.join(map(str, runtime['subprocess']['framework_version']))}"
                f" ({runtime['subprocess']['launcher']}). Each row's "
                f"framework_version says which one answered it."
            ),
            severity=Severity.INFO,
            details={
                "in_process": runtime["in_process"]["framework_version"],
                "subprocess": runtime["subprocess"]["framework_version"],
            },
        ))

    if key_bytes is not None and counts["dumps_verified"]:
        missing = [
            r["name"] for r in rows
            if r["status"] == VERIFY_VERIFIED and r["run"]["key_recovered"] is False
        ]
        if missing:
            diagnostics.append(Diagnostic(
                code=VERIFY_PLUGIN_KEY_MISSING_CODE,
                message=(
                    f"The supplied key was NOT among the plugin's own output on "
                    f"{len(missing)} verified dump(s) ({', '.join(missing[:4])}"
                    + (", ..." if len(missing) > 4 else "")
                    + "). On a dump that does hold the key this is the "
                      "strongest failure this harness reports."
                ),
                severity=Severity.WARNING,
                details={"dumps": missing},
            ))

    capped = [
        r["name"] for r in rows
        if r["status"] == VERIFY_VERIFIED and r["run"]["hits_capped"]
    ]
    if capped:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_HITS_CAPPED_CODE,
            message=(
                f"The hit list stopped at max_hits on {len(capped)} dump(s) "
                f"({', '.join(capped[:4])}"
                + (", ..." if len(capped) > 4 else "")
                + "). match_count is still the honest total, but "
                  "expected_offset_reported and key_recovered are computed over "
                  "the RETAINED hits and may be false negatives."
            ),
            severity=Severity.WARNING,
            details={"dumps": capped},
        ))

    if not include_hits:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_COUNT_ONLY_CODE,
            message=(
                "COUNT-ONLY: every per-hit list was omitted and every count and "
                "flag retained. Nothing bounds the RUN — the plugin still finds "
                "every hit — only the payload."
            ),
            severity=Severity.INFO,
            details={"hits_total": counts["hits_total"]},
        ))

    if pid is not None:
        diagnostics.append(Diagnostic(
            code=VERIFY_PLUGIN_PID_UNPROVEN_CODE,
            message=(
                f"pid={pid} was passed through to the plugin but is UNPROVEN "
                f"here. --pid needs a kernel image plus a matching ISF so the "
                f"OS PsList can hand back a process layer; a flat process dump "
                f"has neither, and the emitted plugin then logs a warning and "
                f"scans the whole layer anyway. Treat the rows as unrestricted."
            ),
            severity=Severity.WARNING,
            details={"pid": pid},
        ))

    return diagnostics


def verify_vol3_plugin(
    *,
    dump_paths: Sequence[str],
    plugin_path: Optional[str] = None,
    plugin_source: Optional[str] = None,
    mode: str = VOL3_MODE_AUTO,
    view: Optional[str] = None,
    expected_offset: Optional[int] = None,
    key_hex: Optional[str] = None,
    pid: Optional[int] = None,
    vol_bin: Optional[str] = None,
    vol_python: Optional[str] = None,
    timeout_s: int = VOL3_SUBPROC_TIMEOUT_S,
    max_hits: int = VOL3_MAX_HITS,
    include_hits: bool = DEFAULT_INCLUDE_HITS,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    on_source: Optional[Callable[[Any], None]] = None,
) -> Dict[str, Any]:
    """RUN a MemDiver-emitted Volatility3 plugin over N dumps, and say who ran it.

    The single implementation behind the CLI ``verify-plugin`` command, the HTTP
    ``POST /api/scan/verify-plugin`` route, the MCP ``verify_vol3_plugin`` tool
    and ``memdiver.services.verify_vol3_plugin``.

    This is the Volatility3 half of what :func:`scan_yara_rule` did for YARA,
    and it exists because "the suite is green" was never evidence about an
    emitted plugin: for most of this repo's life such a plugin was checked only
    by ``ast.parse`` and substring assertions over its generated text, so one
    that could not be imported passed everything. Both engine modules that fix
    that — :mod:`engine.vol3_verify` (in-process) and
    :mod:`engine.vol3_subproc` (a real ``vol`` launcher) — were reachable from
    no surface at all until this producer.

    **The two runtimes answer different questions**, which is why *mode*
    defaults to ``"auto"`` rather than to either one:

    * ``"in_process"`` execs the plugin's source, constructs it through
      Volatility3's own ``PluginInterface.__init__`` (running the real
      ``unsatisfied()`` requirement gate) and scans bytes MemDiver projected.
      It is the only runtime that can address a container: it can be handed the
      ``.msl``'s ``vas`` view directly.
    * ``"subprocess"`` runs ``vol -p <dir> -f <dump> <module>.<Class>`` against
      whichever Volatility3 the operator points at — the way a user actually
      runs a plugin, and frequently a different framework version from
      MemDiver's own.
    * ``"auto"`` prefers IN-PROCESS and falls back to the launcher.

    Point *vol_bin* / *vol_python* at a specific launcher and interpreter. They
    are first-class parameters, not just the :data:`engine.vol3_subproc.VOL3_BIN_ENV`
    / ``VOL3_PYTHON_ENV`` env vars, and they BEAT them — an environment variable
    is not a channel an HTTP body or an MCP tool call has, so env-only
    configuration would leave "let me use my own vol.py" reachable from the
    shell alone.

    Args:
        dump_paths: The dumps to run the plugin over. Rows come back in THIS
            order.
        plugin_path: A ``.py`` plugin on disk. Mutually exclusive with
            *plugin_source*, with no precedence.
        plugin_source: The plugin's Python TEXT — e.g. the ``content`` field
            ``export_key_pattern(fmt="vol3")`` just returned. In subprocess
            mode it is written to a temporary module, because ``vol`` addresses
            a plugin by ``-p <dir>`` plus ``<module>.<Class>``.
        mode: One of :data:`VOL3_MODES`.
        view: Byte view to project for the IN-PROCESS runtime. ``None`` keeps
            each format's own default (``"raw"`` for raw dumps, ``"vas"`` for
            ``.msl``) — the same resolution :func:`scan_yara_rule` applies, read
            from the same single declaration. Ignored in subprocess mode, where
            ``vol`` maps the file itself; see the ``"unsupported"`` status.
        expected_offset: A byte position the key is known to occupy. Membership
            is EXACT, with no tolerance: the failure worth catching is "a hit 64
            bytes from the real key", and a tolerance would score that as a near
            miss.
        key_hex: The secret's bytes, to assert the plugin handed the KEY back
            rather than merely fired near it (``engine.vol3_verify`` calls that
            claim ``verify_key_recovered``). Accepts ``"aa bb cc"`` and
            ``"0xaabbcc"``, exactly as the byte-search box does.
        pid: Passed through to the plugin's ``--pid``. **Explicitly unproven.**
            Narrowing needs a kernel image plus a matching ISF so the OS
            ``PsList`` can return a process layer; neither this repo nor the
            machine it was developed on has one, so nothing here demonstrates
            that the rows are restricted to that process — and the emitted
            plugin itself logs a warning and scans the whole layer when the
            kernel requirement is unfilled. A diagnostic says so on every run
            that passes one.
        vol_bin / vol_python: The launcher and the interpreter that owns its
            Volatility3. Both beat the env vars.
        timeout_s: Wall-clock ceiling for ONE subprocess run.
        max_hits: Hits RETAINED per dump; ``match_count`` is always the honest
            total and ``hits_capped`` says when the cap bit.
        include_hits: Whether each verified row carries its per-hit LIST.
            ``False`` is the count-only census: every count and flag, none of
            the lists. It bounds the PAYLOAD, not the run.
        key_file / passphrase / kem_key_file / key_material: Decryption
            material for encrypted ``.msl`` containers.
        on_source: Called with each freshly opened source before anything is
            read from it; runs AFTER the locked-container guard below.

    Returns:
        A bare dict carrying ``verdict``, the ``intake``, the ``plugin``
        identity, the ``runtime`` block (BOTH runtimes' availability and
        RESOLVED framework versions, plus the launcher's path, cwd and
        interpreter), the ``caps`` the run used, ``counts``, one row per dump in
        the SUPPLIED order, and ``diagnostics``.

        Read ``verdict`` before any count — only ``"no_hit"`` is an absence
        (see :data:`VERIFY_PLUGIN_VERDICTS`) — and read each row's ``status``
        before its ``run``, which is ``None`` on every row that did not run.

    Raises:
        CapabilityError: INVALID_INPUT for zero or both plugin forms, for an
            unknown *mode*, for a bad *key_hex*, and for the emitted plugin's
            own structural faults (no ``PluginInterface`` subclass, several of
            them, no ``_required_framework_version``, a ``TreeGrid`` missing
            columns — all raised by :mod:`engine.vol3_verify`); PRECONDITION for
            an empty ``dump_paths``; UNSUPPORTED when the requested runtime does
            not exist. That last one is CLASS 1, not class 2: ``volatility3`` is
            an optional extra (``memdiver[vol]``), so its absence is a forgotten
            install option rather than a broken environment, and the message
            names the remedy. When NEITHER runtime is available the single
            refusal names BOTH remedies.
        FileNotFoundServiceError: when a supplied dump or ``plugin_path`` does
            not exist. Checked up front, so a typo is reported before N dumps
            are opened.
        EncryptedDumpLockedError: for a locked encrypted container, in BOTH
            modes. Non-negotiable: a locked ``.msl`` reads back EMPTY rather
            than failing, so without the guard both paths would report a
            confident zero over bytes nobody decrypted — the silent false
            negative ``test_g9_producers_surface_locked_dump`` exists to
            prevent. The subprocess path opens the container purely for this
            guard (and to learn its format) before handing ``vol`` the path.
    """
    # Function-local, the repo-wide idiom: the ``app`` layer must not pull the
    # engine's compute at module import time. Only the keyword DEFAULTS resolve
    # at module scope. ``_default_view`` is imported from the YARA scanner ON
    # PURPOSE rather than re-derived here — it reads each source's own declared
    # default off its ``size_for`` signature, and that single declaration is
    # what keeps the two producers from disagreeing about which view an
    # ``.msl`` gets when the caller names none.
    from memdiver.engine import vol3_subproc
    from memdiver.engine.key_location import ELAPSED_PRECISION
    from memdiver.engine.vol3_verify import (
        HAS_VOLATILITY3,
        _require_volatility3,
        anchor_stats,
    )
    from memdiver.engine.yara_scan import _default_view

    if mode not in VOL3_MODES:
        raise CapabilityError(
            f"unknown mode {mode!r}; expected one of "
            + ", ".join(repr(m) for m in VOL3_MODES),
            category=ErrorCategory.INVALID_INPUT,
        )

    intake, source_text, resolved_plugin_path = _verify_plugin_source(
        plugin_path, plugin_source)

    paths = [Path(p).expanduser() for p in dump_paths]
    if not paths:
        raise CapabilityError(
            "Need at least 1 dump to verify against, got 0",
            category=ErrorCategory.PRECONDITION,
        )
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")

    key_bytes = _needle_from_key_hex(key_hex) if key_hex else None
    runtime = _verify_plugin_runtime(
        mode=mode, vol_bin=vol_bin, vol_python=vol_python)
    in_process_ok = bool(HAS_VOLATILITY3)
    launcher_ok = bool(runtime["subprocess"]["available"])

    # The runtime gate, once, before any dump is opened. ``mode="in_process"``
    # defers to ``engine.vol3_verify``'s own UNSUPPORTED message rather than
    # inventing a second one; the AUTO branch is the only place that has to
    # compose a refusal, because it is the only request that had two ways to be
    # satisfied and neither worked.
    if mode == VOL3_MODE_IN_PROCESS:
        _require_volatility3()
    elif mode == VOL3_MODE_SUBPROCESS and not launcher_ok:
        raise CapabilityError(
            f"mode='subprocess' needs a real Volatility3 launcher: "
            f"{runtime['launcher']}",
            category=ErrorCategory.UNSUPPORTED,
        )
    elif mode == VOL3_MODE_AUTO and not (in_process_ok or launcher_ok):
        from memdiver.engine.vol3_verify import VOL3_MISSING

        raise CapabilityError(
            f"No Volatility3 runtime is available, so the emitted plugin "
            f"cannot be run either way. Either install the in-process extra "
            f"({VOL3_MISSING}) OR point MemDiver at an existing launcher "
            f"(set {vol3_subproc.VOL3_BIN_ENV} or pass vol_bin=; a .py "
            f"launcher also wants {vol3_subproc.VOL3_PYTHON_ENV} / "
            f"vol_python=). Currently: {runtime['launcher']}",
            category=ErrorCategory.UNSUPPORTED,
        )

    window_length = _verify_plugin_window_length(source_text)
    anchor_bytes, anchor_distinct = anchor_stats(source_text)
    plugin_class = _verify_plugin_class_name(source_text)
    # Everything the two per-dump runners need that is the same for every dump,
    # bundled once. A NamedTuple rather than twelve repeated keywords: the two
    # runners have to shape their rows IDENTICALLY, and the surest way to keep
    # them doing that is for them to be handed the same object.
    shape = _VerifyShape(
        plugin_class=plugin_class,
        window_length=window_length,
        anchor_bytes=anchor_bytes,
        anchor_distinct=anchor_distinct,
        expected_offset=expected_offset,
        key_bytes=key_bytes,
        pid=pid,
        max_hits=max_hits,
        include_hits=include_hits,
    )
    launcher = vol3_subproc.resolve_launcher(vol_bin=vol_bin, vol_python=vol_python)

    def _observe(source: Any) -> None:
        # FIRST, before a single byte is read, in BOTH modes. A locked
        # encrypted dump reads back EMPTY instead of raising, so this is the
        # difference between "we could not open your container" and N confident
        # zero-hit rows over bytes nobody decrypted.
        _raise_if_locked(source)
        if on_source is not None:
            on_source(source)

    km = _resolve_key_material(key_material, key_file, passphrase, kem_key_file)
    started = time.perf_counter()
    rows: List[Dict[str, Any]] = []

    with ExitStack() as stack:
        # The temp module is created ONCE and only when a launcher run actually
        # needs it, because ``vol`` addresses a plugin as ``-p <dir>`` plus
        # ``<module>.<Class>`` and so cannot be handed source text.
        subprocess_plugin: Dict[str, Optional[Path]] = {"path": resolved_plugin_path}

        def _plugin_file() -> Path:
            if subprocess_plugin["path"] is None:
                directory = Path(stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="memdiver_vol3_")))
                written = directory / f"{_verify_plugin_module_stem(source_text)}.py"
                written.write_text(source_text)
                subprocess_plugin["path"] = written
            return subprocess_plugin["path"]

        for path in paths:
            row_mode = (
                mode if mode != VOL3_MODE_AUTO
                else (VOL3_MODE_IN_PROCESS if in_process_ok else VOL3_MODE_SUBPROCESS)
            )
            try:
                with open_dump_source(str(path), km) as source:
                    _observe(source)
                    fmt = getattr(source, "format_name", None)
                    resolved_view = (
                        view if view is not None else _default_view(source))
                    if row_mode == VOL3_MODE_SUBPROCESS and not (
                        fmt == "raw" and resolved_view == "raw"
                    ):
                        # MEASURED, not theoretical. ``vol`` gets a bare file
                        # path and never goes through MemDiver's container
                        # layer, so on the ground-truth ``.msl`` it reports the
                        # key at 371752 where every MemDiver coordinate says
                        # 370672 — skewed by the container's header size
                        # (1080 B for that import; not a constant). That is a
                        # confident WRONG offset, which is worse than a zero and
                        # far worse than a refusal, so refuse.
                        rows.append(_verify_plugin_row(
                            path,
                            status=VERIFY_UNSUPPORTED,
                            detail=(
                                f"mode='subprocess' hands `vol` the file path, "
                                f"so it would scan the {fmt!r} CONTAINER rather "
                                f"than the {resolved_view!r} view — measured as "
                                f"an offset skew of the container's header "
                                f"size (measured 1080 bytes on the "
                                f"ground-truth .msl). "
                                f"Use mode='in_process', which projects the "
                                f"view before scanning."
                            ),
                        ))
                        continue
                    if row_mode == VOL3_MODE_IN_PROCESS:
                        row = _verify_in_process(
                            source,
                            source_text=source_text,
                            path=path,
                            view=resolved_view,
                            flat_file=(fmt == "raw" and resolved_view == "raw"),
                            shape=shape,
                        )
                    else:
                        row = _verify_subprocess(
                            path=path,
                            plugin_file=_plugin_file(),
                            launcher=launcher,
                            framework_version=(
                                runtime["subprocess"]["framework_version"]),
                            layer_bytes=source.size_for(resolved_view),
                            timeout_s=timeout_s,
                            shape=shape,
                        )
            except (OSError, ValueError, RuntimeError) as exc:
                # NARROW ON PURPOSE, exactly as ``scan_yara_rule``'s own handler
                # is. ``EncryptedDumpLockedError`` is a ``CapabilityError`` and
                # is none of these, so it propagates straight through —
                # widening to ``Exception`` would silently convert a forgotten
                # key into N clean runs. ``RuntimeError`` is in the tuple
                # because that is what ``vol3_subproc.run_plugin`` raises for a
                # non-zero launcher exit -- degraded per-dump rather than
                # propagated, so one bad dump cannot abort a corpus sweep.
                #
                # Stated rather than hidden: a plugin that is broken for EVERY
                # dump therefore comes back as N ``"unreadable"`` rows instead
                # of one request-level error, because out-of-process there is no
                # way to tell "this dump" from "this plugin" -- only the
                # launcher's exit code. Each row's ``detail`` carries ``vol``'s
                # own stderr, and the unreadable diagnostic surfaces it, so the
                # cause is legible; the in-process runtime raises properly
                # (``load_plugin_class`` refuses a bad plugin up front), which
                # is another reason ``mode="auto"`` prefers it.
                logger.warning(
                    "%s: could not be verified (%s); claiming nothing about "
                    "this dump.", path, exc)
                rows.append(_verify_plugin_row(
                    path, status=VERIFY_UNREADABLE, detail=str(exc)))
                continue
            rows.append(row)

    verified = [r for r in rows if r["status"] == VERIFY_VERIFIED]
    hit = [r for r in verified if r["run"]["match_count"]]
    zero = [r for r in verified if not r["run"]["match_count"]]
    proven_zero = [r for r in zero if not _verify_row_degraded(r["run"])]
    unproven_zero = [r for r in zero if _verify_row_degraded(r["run"])]

    counts = {
        "dumps_total": len(rows),
        "dumps_verified": len(verified),
        "dumps_unreadable": sum(
            1 for r in rows if r["status"] == VERIFY_UNREADABLE),
        "dumps_unsupported": sum(
            1 for r in rows if r["status"] == VERIFY_UNSUPPORTED),
        "dumps_hit": len(hit),
        "dumps_no_hit": len(proven_zero),
        "dumps_inconclusive": len(unproven_zero),
        # Equal to ``dumps_inconclusive`` TODAY, and kept as its own key
        # deliberately rather than deduplicated. It names the CAUSE where the
        # other names the consequence: a zero-byte layer is currently the only
        # way a verified row can be degraded (there is no per-chunk timeout
        # here, which is what makes ``scan_yara_rule``'s two counts diverge),
        # so a reader must not have to infer "no bytes were compared" from a
        # verdict word. Add a second degradation channel and the two separate
        # on their own instead of one of them silently becoming wrong.
        "dumps_zero_bytes": len(unproven_zero),
        "dumps_hits_capped": sum(1 for r in verified if r["run"]["hits_capped"]),
        # NOT a floor: each row's ``match_count`` is the honest total even when
        # its LIST was capped, so this is a true census. ``hits_retained`` is
        # the capped one, and the two differ exactly when a cap bit.
        "hits_total": sum(r["run"]["match_count"] for r in verified),
        "hits_retained": sum(r["run"]["hits_retained"] for r in verified),
        "bytes_scanned": sum(r["run"]["layer_bytes"] for r in verified),
        # ``None`` when no key was supplied; otherwise how many verified dumps
        # handed the key's exact bytes back.
        "dumps_key_recovered": (
            None if key_bytes is None
            else sum(1 for r in verified if r["run"]["key_recovered"])
        ),
        "dumps_expected_offset_reported": (
            None if expected_offset is None
            else sum(
                1 for r in verified if r["run"]["expected_offset_reported"])
        ),
    }

    if hit:
        verdict = VERIFY_HIT
    elif proven_zero and not unproven_zero:
        verdict = VERIFY_NO_HIT
    elif verified:
        verdict = VERIFY_INCONCLUSIVE
    else:
        verdict = VERIFY_NOT_RUN

    return {
        "verdict": verdict,
        "intake": intake,
        "plugin": {
            "class_name": plugin_class,
            "path": str(resolved_plugin_path) if resolved_plugin_path else None,
            "window_length": window_length,
            "anchor_bytes": anchor_bytes,
            "anchor_distinct_bytes": anchor_distinct,
        },
        "runtime": runtime,
        "caps": {
            "mode": mode,
            "view": view,
            "max_hits": max_hits,
            "timeout_s": timeout_s,
            "pid": pid,
        },
        "counts": counts,
        "dumps": rows,
        "elapsed_s": round(time.perf_counter() - started, ELAPSED_PRECISION),
        "diagnostics": [
            d.to_dict() for d in _verify_plugin_diagnostics(
                rows,
                verdict=verdict,
                counts=counts,
                runtime=runtime,
                key_bytes=key_bytes,
                include_hits=include_hits,
                pid=pid,
            )
        ],
    }


# _emit/_progress_bridge/_experiment_check_cancelled MOVED to memdiver.app._progress (P3.1)
# experiment orchestration MOVED to memdiver.app.experiment_orchestration (P3.1)
