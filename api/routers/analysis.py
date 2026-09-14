"""Analysis router — run the full analysis pipeline."""

from __future__ import annotations

import json
import logging

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from memdiver.api.adapters import analyze_run_params, batch_run_params
from memdiver.api.dependencies import (
    task_manager_or_503 as _task_manager_or_503,
)
from memdiver.api.models import (
    AlignedWindowRequest,
    AnalysisCandidatesRequest,
    AnalysisRunResponse,
    AnalyzeFileRequest,
    AnalyzeRequestAPI,
    AutoExportRequest,
    BatchRunRequest,
    BatchRunResponse,
    ConsensusRegionsRequest,
    ConsensusRequest,
    ConvergenceRequest,
    ExportKeylogRequest,
    KeyPatternRequest,
    LocateKeyRequest,
    ManualExportRequest,
    VerifyKeyRequest,
)
from memdiver.api.services.consensus_session import (
    ConsensusSessionManager,
    get_consensus_manager,
)
from memdiver.api.config import Settings
from memdiver.api.dependencies import get_api_settings, upload_dir_or_409
from memdiver.api.path_safety import ensure_within
from memdiver.api.services.key_material import decode_key_material
from memdiver.core.service_errors import CapabilityError
from memdiver.core.variance import DEFAULT_THRESHOLDS
from memdiver.engine.consensus import MAX_CONSENSUS_WINDOW
from memdiver.engine.consensus_service import build_consensus

logger = logging.getLogger("memdiver.api.routers.analysis")

router = APIRouter()


@router.post("/run", response_model=AnalysisRunResponse)
def run_analysis(request: AnalyzeRequestAPI):
    """Submit the full library-analysis pipeline as a task and return a task_id.

    Previously this ran ``tools.analyze_library`` inline on the request
    thread ("Runs synchronously for now"). The GIL-bound algorithm work
    is now dispatched to the TaskManager's ProcessPool via
    ``app.pipeline.analysis_task_runner.run_analysis`` — the same async pattern
    as ``POST /api/analysis/batch`` and the pipeline endpoint. Progress
    streams over ``/ws/tasks/{task_id}`` and the full ``AnalysisResult``
    is downloadable as the ``analysis_result`` artifact.

    The identical algorithm logic still lives in
    ``mcp_server.tools.analyze_library`` (which the runner calls and the
    MCP server continues to use synchronously), so no behavior is lost.
    """
    manager = _task_manager_or_503()
    # Field mapping lives in the single conversion seam (api.adapters) so the
    # wire model and core AnalyzeRequest can't drift. This stays a dict (not a
    # core dataclass) so the ProcessPool payload is unchanged and library_dir
    # validation stays deferred to the worker.
    worker_params: dict = analyze_run_params(
        request, task_root=str(manager.artifact_store.root)
    )
    record = manager.submit(
        kind="analysis",
        params=worker_params,
        runner_dotted="memdiver.app.pipeline.analysis_task_runner.run_analysis",
        stage_names=["analyze"],
    )
    return AnalysisRunResponse(
        task_id=record.task_id,
        status=record.status.value,
    )


@router.post("/consensus")
def run_consensus(
    req: ConsensusRequest,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
):
    """Build consensus vector from multiple dumps."""
    if len(req.dump_paths) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 dumps")

    # Per-caller pre-check, as engine.consensus_service documents: reject an
    # obviously-missing path before any I/O, and name every one of them rather
    # than only the first the opener trips over. A path that vanishes between
    # here and the open still lands as a clean 404 via that module's
    # FileNotFoundServiceError translation.
    missing = [p for p in req.dump_paths if not Path(p).exists()]
    if missing:
        raise HTTPException(
            status_code=404, detail=f"Files not found: {missing[:3]}"
        )

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex) or {}
    # open+build is the shared skeleton; build_consensus opens each dump as a
    # context-managed source, builds the vector while they are all live, and
    # closes them once the vector holds its own copies. No disk writes here.
    cm = build_consensus(req.dump_paths, normalize=req.normalize, key_material=km)

    # Register the build under its own id so range queries are isolated per
    # client — no shared mutable state on a process-wide singleton.
    built = manager.register(cm)

    # ``classification`` travels with every row, exactly as the CLI
    # ``consensus`` command has always emitted it (cli/consensus.py). Dropping
    # it here forced the web UI to re-derive a region's class from its
    # ``mean_variance`` against hard-coded 0/200/3000 literals -- a second,
    # silently-drifting copy of ``core.variance``'s bands.
    static_regions = []
    for r in cm.get_static_regions():
        static_regions.append({
            "start": r.start,
            "end": r.end,
            "length": r.end - r.start,
            "mean_variance": float(r.mean_variance),
            "classification": r.classification,
        })

    volatile_regions = []
    for r in cm.get_volatile_regions():
        volatile_regions.append({
            "start": r.start,
            "end": r.end,
            "length": r.end - r.start,
            "mean_variance": float(r.mean_variance),
            "classification": r.classification,
        })

    return {
        "consensus_id": built.session_id,
        "size": cm.size,
        "num_dumps": cm.num_dumps,
        "counts": cm.classification_counts(),
        # The BANDS this build's classes were cut at, so a legend renders the
        # boundaries that actually produced these counts instead of the module
        # defaults. ``cm.thresholds`` is None for a build that took them, which
        # is precisely DEFAULT_THRESHOLDS -- resolved here rather than left as
        # null, because "null" reads to a client as "unknown", not "0/200/3000".
        # Same shape POST /candidates reports its resolved thresholds in.
        "thresholds": (cm.thresholds or DEFAULT_THRESHOLDS)._asdict(),
        "static_regions": static_regions,
        "volatile_regions": volatile_regions,
        # WHICH dumps (and under which ASLR setting) produced this build.
        # A consensus is only meaningful for the set it was built over: the
        # classes, the gaps and the cross-dump "differs" verdict all change
        # when one dump joins or leaves. Without this echo a client holds a
        # `consensus_id` it cannot attribute, and keeps projecting an old
        # build onto a selection it never saw — plausible classes over the
        # wrong bytes. Echoed from the REQUEST, not from `cm.dump_paths`, so
        # the caller can compare it against the selection it sent.
        "dump_paths": list(req.dump_paths),
        "normalize": req.normalize,
    }


@router.post("/candidates")
def analysis_candidates(req: AnalysisCandidatesRequest):
    """Rank candidate regions across N dumps — with NO oracle and no capture.

    The exploratory path the web UI previously could not reach at all: the only
    filter form lived inside the Pipeline wizard, which hard-refuses to run
    without an oracle or a pcap (``POST /api/pipeline/run``). That guard is
    correct for *that* flow, which exists to drive a brute force, so this is a
    separate route rather than a loosening of it — an analyst who cannot yet
    confirm a key still gets a ranked list to look at.

    Thin HTTP adapter over :func:`memdiver.app.tools_pipeline.analyze_candidates`,
    the same producer the CLI ``analyze-candidates`` command and the MCP
    ``analyze_candidates`` tool route through. Synchronous, like ``POST
    /consensus`` beside it and for the same reason: the result is a region list
    a human is waiting to read, not a long-running sweep with artifacts.

    Deliberately NO ``try/except``: a ``CapabilityError`` out of the producer is
    translated by the app's single global handler (``api.main``), which is what
    keeps the error contract identical to every other producer-backed route.
    """
    from memdiver.app.tools_pipeline import analyze_candidates

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex) or {}
    return analyze_candidates(
        dump_paths=list(req.dump_paths),
        classes=req.classes,
        min_variance=req.min_variance,
        min_region=req.min_region,
        max_region=req.max_region,
        alignment=req.alignment,
        block_size=req.block_size,
        density_threshold=req.density_threshold,
        entropy_window=req.entropy_window,
        entropy_threshold=req.entropy_threshold,
        order=req.order,
        max_returned=req.max_returned,
        normalize=req.normalize,
        project_id=req.project_id,
        key_material=km,
    )


@router.post("/locate-key")
def analysis_locate_key(req: LocateKeyRequest):
    """Locate a secret the caller ALREADY HOLDS across N dumps.

    Thin HTTP adapter over :func:`memdiver.app.tools_pipeline.locate_key`, the
    same producer the CLI ``locate-key`` command and the MCP ``locate_key`` tool
    route through. Synchronous, like ``POST /candidates`` beside it and for the
    same reason: the result is a per-dump census a human is waiting to read.

    ``secret_hex`` — NOT ``key_hex`` — carries the secret to search for; see the
    wire-collision note on ``api.models.KeyMaterialFields``.

    Deliberately NO ``try/except``: a ``CapabilityError`` out of the producer is
    translated by the app's single global handler (``api.main``). A key that is
    provably absent is a 200 with ``verdict == "absent"``, not an error — only
    a malformed request (400) or a missing dump (404) leaves through the handler.
    """
    from memdiver.app.tools_pipeline import locate_key

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex) or {}
    return locate_key(
        dump_paths=list(req.dump_paths),
        key_hex=req.secret_hex,
        keylog_line=req.keylog_line,
        secret=req.secret,
        view=req.view,
        max_offsets=req.max_offsets,
        key_material=km,
    )


@router.post("/key-pattern")
def analysis_key_pattern(req: KeyPatternRequest):
    """Export a scanning signature anchored on an already-known secret.

    Thin HTTP adapter over
    :func:`memdiver.app.tools_pipeline.export_key_pattern`. Same producer as the
    CLI ``export-key-pattern`` command and the MCP ``export_key_pattern`` tool.

    ``include_window_hex`` defaults to TRUE on this route only, because the web
    UI renders the per-dump windows in ``CrossLibraryHex`` and cannot fetch the
    bytes any other way. Same no-``try/except`` contract as the route above: a
    key absent from every searched dump reaches the client as a 404 via
    ``KeyNotFoundError``, and nothing was searched at all reaches it as a 400.
    """
    from memdiver.app.tools_pipeline import export_key_pattern

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex) or {}
    return export_key_pattern(
        dump_paths=list(req.dump_paths),
        key_hex=req.secret_hex,
        keylog_line=req.keylog_line,
        secret=req.secret,
        context=req.context,
        fmt=req.format,
        name=req.name,
        min_static_ratio=req.min_static_ratio,
        view=req.view,
        output_dir=req.output_dir,
        include_window_hex=req.include_window_hex,
        max_offsets=req.max_offsets,
        key_material=km,
    )


@router.get("/consensus/range")
def consensus_range(
    consensus_id: str,
    offset: int = 0,
    length: int = 1024,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
):
    """Get variance classifications for a byte range of a specific build.

    ``consensus_id`` is the id returned by ``POST /consensus``; range queries
    are scoped to that build so concurrent clients never read each other's
    results.
    """
    built = manager.get(consensus_id)
    if built is None:
        raise HTTPException(status_code=404, detail="No consensus computed yet")
    cm = built.matrix

    length = min(length, MAX_CONSENSUS_WINDOW)
    end = min(offset + length, cm.size)
    actual_offset = max(0, offset)

    classifications = cm.classifications[actual_offset:end].tolist()

    return {
        "offset": actual_offset,
        "length": end - actual_offset,
        "classifications": classifications,
    }


@router.get("/consensus/va-range")
def consensus_va_range(
    consensus_id: str,
    dump_path: str,
    va: int = 0,
    length: int = 1024,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
):
    """Per-byte 4-state classifications for one dump's virtual-address window.

    For an ALIGNED consensus the variance/classification arrays live in an
    aligned-slab coordinate, not a viewable offset. This maps a dump's VA
    window (``va``..``va+length``) back to those slab indices so the hex
    viewer's ``va`` view can paint the overlay on the correct bytes. Entries
    are ByteClass codes, or ``-1`` for VA gaps absent from the consensus.
    """
    built = manager.get(consensus_id)
    if built is None:
        raise HTTPException(status_code=404, detail="No consensus computed yet")
    cm = built.matrix
    if cm.msl_layout is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "VA range is only available for an aligned consensus "
                "(module-offset or virtual-address). This build used raw file "
                "offsets, which carry no virtual addresses to range over."
            ),
        )
    dump_index = cm.dump_index_for_path(dump_path)
    if dump_index < 0:
        raise HTTPException(status_code=404, detail="dump not part of this consensus")
    length = min(max(0, length), MAX_CONSENSUS_WINDOW)
    classes = cm.class_window_va(dump_index, va, length)
    return {"va": va, "length": length, "dump_index": dump_index, "classes": classes}


@router.get("/consensus/va-overview")
def consensus_va_overview(
    consensus_id: str,
    dump_path: str,
    bins: int = 256,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
):
    """Down-sampled change/variance heatmap over a dump's whole VA span.

    Feeds the variance minimap: per-bin fraction of *changing* bytes
    (class > invariant) and *high*-variance bytes (key-candidate), plus the
    peak class level. Only meaningful for an ALIGNED consensus.
    """
    built = manager.get(consensus_id)
    if built is None:
        raise HTTPException(status_code=404, detail="No consensus computed yet")
    cm = built.matrix
    if cm.msl_layout is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "VA overview is only available for an aligned consensus "
                "(module-offset or virtual-address). This build used raw file "
                "offsets, which carry no virtual addresses to range over."
            ),
        )
    dump_index = cm.dump_index_for_path(dump_path)
    if dump_index < 0:
        raise HTTPException(status_code=404, detail="dump not part of this consensus")
    bins = min(max(1, bins), 4096)
    return {"dump_index": dump_index, **cm.va_overview(dump_index, bins)}


def _per_dump_key_material(req) -> dict:
    """``{dump_path: open_dump kwargs}`` from the request's per-dump key list.

    One decode per entry through the same ``decode_key_material`` every other
    route uses, so malformed hex is the same 400 here as everywhere else.

    Shared by both consensus POST bodies (``AlignedWindowRequest`` and
    ``ConsensusRegionsRequest``), which carry the identical ``keys`` list: the
    per-dump channel exists because a corpus routinely mixes plaintext captures
    with containers encrypted under DIFFERENT keys, and that is as true of the
    anchor a region page opens as of the peers a window reads.
    """
    by_path = {}
    for entry in req.keys:
        km = decode_key_material(entry.passphrase, entry.key_hex, entry.kem_key_hex)
        if km:
            by_path[entry.dump_path] = km
    return by_path


def _aligned_window_anchor(req: AlignedWindowRequest) -> tuple[str | None, int | None]:
    """Resolve ``anchor`` to ``(anchor_path, slab_offset)``, refusing to guess.

    Each anchor mode REQUIRES its own field. Filling in a missing one would not
    return a worse window, it would return a window in a DIFFERENT COORDINATE:
    a dump-anchored request with no ``anchor_path`` falling through to a slab
    anchor serves real bytes at an address nobody asked about, which is the
    precise failure this route exists to eliminate. So both omissions are 400s.
    """
    if req.anchor == "dump":
        if not req.anchor_path:
            raise HTTPException(
                status_code=400,
                detail=(
                    'anchor="dump" needs anchor_path: a dump anchor phrases the '
                    "window in ONE dump's own coordinate, and with no dump named "
                    "there is no such coordinate to read from. Name the anchor "
                    'dump, or ask for anchor="slab" with an explicit slab_offset.'
                ),
            )
        return req.anchor_path, None
    if req.slab_offset is None:
        raise HTTPException(
            status_code=400,
            detail=(
                'anchor="slab" needs slab_offset: the slab offset IS the slab '
                "anchor, so defaulting it to 0 would silently serve the start of "
                "the aligned slab instead of the window you asked for. Pass "
                "slab_offset explicitly (0 is allowed, it just has to be said)."
            ),
        )
    return None, req.slab_offset


def _consensus_source(req, manager):
    """Resolve the request to ``(consensus vector or None, consensus_id)``.

    Exactly one of ``consensus_id`` / ``dump_paths``: neither and both are
    400s, because "which correspondence is this answer in" must have exactly
    one answer. An unknown ``consensus_id`` is a 404.

    Shared by the two either/or consensus routes (``/consensus/aligned-window``
    and ``/consensus/regions``) so the id/paths contract — and its two error
    codes — cannot drift between them.
    """
    if bool(req.consensus_id) == bool(req.dump_paths):
        raise HTTPException(
            status_code=400,
            detail="pass exactly one of consensus_id or dump_paths",
        )
    if not req.consensus_id:
        return None, None
    built = manager.get(req.consensus_id)
    if built is None:
        raise HTTPException(status_code=404, detail="No consensus computed yet")
    return built.matrix, req.consensus_id


def _require_dumps_in_build(consensus, dumps) -> None:
    """409 unless every entry of ``dumps`` belongs to ``consensus``'s build.

    A consensus is a statement ABOUT A SET OF DUMPS. Answer a window for a
    selection the build never saw and every number in the response is a
    confident lie: the classes were computed over other bytes, the gaps mark
    other holes, and the cross-dump "differs" ring fires on differences
    between dumps the analyst is not looking at. Silence is the worst outcome
    here, because nothing downstream can detect it.

    409 (conflict), not 404: the build exists and the dumps exist, they simply
    do not belong together. That is a state the client fixes by re-running the
    consensus over the current selection — which is exactly what the
    ``NoConsensusPrompt`` empty state offers.

    Matching is delegated to ``app.tools_consensus.dump_index_for``, the same
    resolver ``_select_dumps`` uses for the real read, so a request cannot pass
    this gate and then be rejected by the producer (or vice versa) over a
    difference in path spelling. ``ConsensusVector.dump_index_for_path`` behind
    it compares RESOLVED paths, so ``/a/c/../b.msl``, a symlinked parent and a
    relative spelling all find the dump the build stored.

    Skipped when there is no consensus (the selector IS the dump list), when
    the caller named no subset (the whole build is implied), and when the build
    recorded no paths at all — an incremental/upload fold holds bytes, not
    files, so there is nothing to check against and ``_select_dumps`` already
    reports that as its own 409.
    """
    from memdiver.app.tools_consensus import dump_index_for

    if consensus is None or not dumps:
        return
    if not consensus.dump_paths:
        return
    outside = [str(d) for d in dumps if dump_index_for(consensus, d) < 0]
    if not outside:
        return
    raise HTTPException(
        status_code=409,
        detail=(
            "this consensus was not built over "
            f"{outside[:3]}: a window is only meaningful for the dumps the "
            "build covers, so answering would return classes computed over "
            "other bytes. Re-run the consensus over the current selection."
        ),
    )


@router.post("/consensus/aligned-window")
def consensus_aligned_window(
    req: AlignedWindowRequest,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
):
    """One window, read in EVERY dump at the address the consensus aligned.

    Invariant W1 — the whole point of this route. For every dump ``d`` and
    every ``i`` in ``[0, length)``, ``dumps[d].bytes[i]`` is the byte ``d``
    holds at the address the consensus put in correspondence with the anchor's
    byte at ``offset + i``, and ``classes[i]`` is that correspondence's
    ByteClass. Where no correspondence exists: ``i`` falls in a ``gaps`` run,
    ``classes[i] == -1``, ``bytes[i] == 0x00``, and ``i`` is outside every
    ``bytes_valid`` run. THE CLIENT NEVER RECEIVES A PEER COORDINATE IT HAS TO
    APPLY — ``segments[].dumps[].va``/``offset`` are provenance only.

    ``variants`` (per index, like ``classes``) carries the cross-dump
    comparison: ``variants[i]`` counts the distinct values the PRESENT dumps
    hold at ``i`` — ``0`` = nobody present, ``1`` = every present dump agrees.
    So "the dumps disagree here" is ``variants[i] >= 2``; a byte only one dump
    holds counts ``1`` and is NOT a disagreement, because absence and change
    are different findings. There is deliberately no separate ``differs``
    field: it was exactly ``variants >= 2``, since a value is only counted
    once per distinct byte among those present.

    It is computed over exactly the dumps this request selected, which is why
    it cannot be derived client-side from a byte cache that still holds
    de-selected dumps.

    POST, not GET: N dump paths plus N key triples do not fit a query string,
    and key material must stay out of access logs, history and ``Referer``.

    The anchor is ``anchor_path`` + ``view`` + ``offset`` (``anchor: "dump"``)
    or ``slab_offset`` (``anchor: "slab"``); a missing anchor field is a 400,
    never a fallback to the other mode — see ``_aligned_window_anchor``.

    ``length`` is clamped twice — at ``MAX_CONSENSUS_WINDOW`` and at
    ``length * n_dumps <= MAX_WINDOW_TOTAL_BYTES`` — and a clamp always sets
    ``truncated`` and echoes ``requested_length``. It NEVER drops a dump: a
    silently missing dump reads as "this dump has nothing there".

    A peer nobody supplied a key for comes back as ``bytes: null`` with a
    populated ``key_status``, and every OTHER dump still returns its bytes.

    ``dumps`` must name dumps the ``consensus_id`` build actually covers; a
    selection the build never saw is a 409, never a silent answer — see
    ``_require_dumps_in_build``.
    """
    from memdiver.app.composition import build_tool_session
    from memdiver.app.tools_consensus import (
        aligned_window_from_vector,
        aligned_window_result,
    )

    consensus, consensus_id = _consensus_source(req, manager)
    # Before any read: a build may only answer for its own dumps.
    _require_dumps_in_build(consensus, req.dumps)
    key_material_by_path = _per_dump_key_material(req)
    anchor_path, slab_offset = _aligned_window_anchor(req)

    if consensus is not None:
        payload = aligned_window_from_vector(
            consensus,
            anchor_path=anchor_path,
            anchor_view=req.view,
            offset=req.offset,
            slab_offset=slab_offset,
            length=req.length,
            dumps=req.dumps,
            include_bytes=req.include_bytes,
            key_material_by_path=key_material_by_path,
        )
    else:
        payload = aligned_window_result(
            build_tool_session(),
            dump_paths=list(req.dump_paths or []),
            anchor_path=anchor_path,
            anchor_view=req.view,
            offset=req.offset,
            slab_offset=slab_offset,
            length=req.length,
            normalize=req.normalize,
            classify=req.classify,
            include_bytes=req.include_bytes,
            key_material_by_path=key_material_by_path,
        ).payload
    payload["consensus_id"] = consensus_id
    return payload


@router.post("/consensus/regions")
def consensus_regions(
    req: ConsensusRegionsRequest,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
):
    """Every occurrence of a consensus class, paginated AND jumpable.

    The list behind "show me every key candidate": one page of regions, each
    carrying its slab coordinates, its label, its per-class byte mix — and the
    offset a hex viewer can be scrolled to.

    THE OFFSET IS THE POINT. ``regions[].anchor_offset`` is the argument
    ``hex-store.scrollToOffset`` takes, verbatim. Returning only a VA would
    force the client to re-implement the slab -> VA -> offset translation for
    each of the two coordinates it navigates in (the overlay walks ``"vas"``,
    the single viewer ``"va"``) — the client-side coordinate arithmetic
    ``app.tools_consensus`` exists to delete, and the origin of both shipped
    overlay bugs. ``-1`` means "no honest answer" (never a plausible number,
    the convention ``ConsensusVector.slab_to_va`` set), and the envelope's
    ``anchor.jumpable`` states that ONCE for the page so a client can hide the
    jump affordance instead of inferring a refusal from a sea of ``-1``s.

    ``classes`` omitted is the NON-INVARIANT UNION. Real key material is
    class-mixed — a measured 48-byte TLS 1.2 secret is 22 KEY_CANDIDATE + 18
    POINTER + 8 STRUCTURAL bytes — so ``classes=["key_candidate"]`` does not
    return that secret, it shatters it into 3-byte shards.

    Pagination is a slab-offset CURSOR, not a page number: pass the previous
    response's ``next_after`` as ``after``. ``total`` sizes the whole result
    set and ``counts`` carries the whole-build histogram, so the chip counts
    beside the list arrive with the first page.

    POST, not GET, for the same two reasons as ``/consensus/aligned-window``:
    N key triples do not fit a query string, and key material must stay out of
    access logs, history and ``Referer``. The keys are load-bearing here too —
    resolving a ``"vas"`` anchor offset means opening (and decrypting) the
    anchor container.

    A LOCKED anchor is reported (``jumpable: false``), never raised: the
    regions themselves are read from the consensus, not from the container, so
    a missing key costs the jump offsets and nothing else.

    Deliberately NO ``try/except``: a ``CapabilityError`` out of the producer
    goes through the app's single global handler (``api.main``), which is what
    keeps the error contract identical to every other producer-backed route.
    """
    from memdiver.app.composition import build_tool_session
    from memdiver.app.tools_consensus import (
        class_regions_from_vector,
        class_regions_result,
    )

    consensus, consensus_id = _consensus_source(req, manager)
    # Before any read: a build may only answer for its own dumps. The anchor is
    # the only dump this route names, and anchoring on a dump the build never
    # saw would express every offset in a coordinate the classes were not
    # measured in.
    _require_dumps_in_build(
        consensus, [req.anchor_path] if req.anchor_path else None,
    )
    key_material_by_path = _per_dump_key_material(req)

    if consensus is not None:
        payload = class_regions_from_vector(
            consensus,
            classes=req.classes,
            min_length=req.min_length,
            max_length=req.max_length,
            after=req.after,
            limit=req.limit,
            anchor_path=req.anchor_path,
            anchor_view=req.anchor_view,
            include_anchor_offsets=req.include_anchor_offsets,
            key_material_by_path=key_material_by_path,
        )
    else:
        payload = class_regions_result(
            build_tool_session(),
            dump_paths=list(req.dump_paths or []),
            classes=req.classes,
            min_length=req.min_length,
            max_length=req.max_length,
            after=req.after,
            limit=req.limit,
            anchor_path=req.anchor_path,
            anchor_view=req.anchor_view,
            include_anchor_offsets=req.include_anchor_offsets,
            normalize=req.normalize,
            key_material_by_path=key_material_by_path,
        ).payload
    payload["consensus_id"] = consensus_id
    return payload


@router.post("/run-file", response_model=AnalysisRunResponse)
def run_file_analysis(request: AnalyzeFileRequest):
    """Submit single-file analysis as a task and return a task_id.

    Previously this read the dump and ran every requested algorithm
    inline on the request thread. A 2026-04-13 benchmark recorded
    ~102.5 s for ``entropy_scan`` on a 10 MB dump — long enough to trip
    proxy/gateway timeouts. The GIL-bound work now runs on the
    TaskManager's ProcessPool via
    ``app.pipeline.analysis_task_runner.run_file`` (which preserves the exact
    algorithm loop, including optional decryption key material). Progress
    streams over ``/ws/tasks/{task_id}`` — one event per algorithm — and
    the full ``AnalysisResult`` is downloadable as the ``analysis_result``
    artifact.

    The path existence check stays here so callers still get a fast 404
    for a missing file instead of a task that fails asynchronously.
    """
    path = Path(request.dump_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {request.dump_path}")

    manager = _task_manager_or_503()
    worker_params: dict = {
        "task_root": str(manager.artifact_store.root),
        "dump_path": request.dump_path,
        "algorithms": list(request.algorithms),
        "user_regex": request.user_regex,
        "custom_patterns": request.custom_patterns,
        # Forward raw key material; the worker decodes it in-process so the
        # params stay JSON-friendly across the multiprocessing queue.
        "passphrase": request.passphrase,
        "key_hex": request.key_hex,
        "kem_key_hex": request.kem_key_hex,
    }
    record = manager.submit(
        kind="analysis",
        params=worker_params,
        runner_dotted="memdiver.app.pipeline.analysis_task_runner.run_file",
        stage_names=["analyze"],
    )
    return AnalysisRunResponse(
        task_id=record.task_id,
        status=record.status.value,
    )


@router.get("/patterns")
def list_patterns():
    """List available JSON pattern definitions."""
    patterns_dir = Path(__file__).parent.parent.parent / "algorithms" / "patterns"
    patterns = []
    if patterns_dir.is_dir():
        for f in sorted(patterns_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                patterns.append({
                    "filename": f.name,
                    "name": data.get("name", f.stem),
                    "description": data.get("description", ""),
                    "applicable_to": data.get("applicable_to", {}),
                })
            except Exception:
                logger.exception("Failed to load pattern %s", f.name)
                patterns.append({"filename": f.name, "name": f.stem, "description": "Error loading", "applicable_to": {}})
    return {"patterns": patterns}


@router.post("/batch", response_model=BatchRunResponse)
def run_batch(request: BatchRunRequest):
    """Submit a batch analysis task and return a task_id.

    Mirrors :func:`api.routers.pipeline.run_pipeline_endpoint`: the
    request is translated into JSON-friendly worker params, dispatched
    to the TaskManager's ProcessPool via
    ``app.pipeline.batch_task_runner.run_batch``, and a ``task_id`` is
    returned immediately. Progress streams over ``/ws/tasks/{task_id}``
    and the aggregated batch result is downloadable as the
    ``batch_result`` artifact via the same artifact contract the
    pipeline endpoint uses.
    """
    manager = _task_manager_or_503()
    # Same single conversion seam as /run. Kept dict-based so each job's
    # AnalyzeRequest __post_init__ validation stays deferred to the worker's
    # per-job re-hydration (unchanged pool payload).
    worker_params: dict = batch_run_params(
        request, task_root=str(manager.artifact_store.root)
    )
    record = manager.submit(
        kind="batch",
        params=worker_params,
        runner_dotted="memdiver.app.pipeline.batch_task_runner.run_batch",
        stage_names=["batch"],
    )
    return BatchRunResponse(
        task_id=record.task_id,
        status=record.status.value,
    )


@router.post("/convergence")
def run_convergence(req: ConvergenceRequest):
    """Run convergence sweep: build consensus at N=[2..max] and return metrics."""
    from memdiver.engine.convergence import run_convergence_sweep
    from memdiver.engine.serializer import serialize_convergence_result

    paths = [Path(p) for p in req.dump_paths]
    missing = [p for p in paths if not p.exists()]
    if missing:
        raise HTTPException(status_code=404, detail=f"Files not found: {missing[:3]}")
    if len(paths) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 dumps")

    result = run_convergence_sweep(
        paths,
        n_values=req.n_values,
        max_fp=req.max_fp,
    )
    return serialize_convergence_result(result)


@router.post("/verify-key")
def verify_key(req: VerifyKeyRequest):
    """Attempt decryption verification of a candidate key.

    Thin HTTP adapter over ``app.tools_pipeline.verify_key_result`` — the same
    producer the CLI ``verify`` command and the MCP ``verify`` tool use, so the
    candidate-read + decryption check cannot drift across surfaces. The
    producer's transport-agnostic ``CapabilityError`` is translated to an
    ``HTTPException`` here (preserving this route's ``{"detail": ...}`` shape +
    per-category status), rather than through the global handler, because the
    404/400 contract predates that handler.
    """
    from memdiver.app.tools_pipeline import verify_key_result

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex) or {}
    try:
        result = verify_key_result(
            dump_path=req.dump_path,
            offset=req.offset,
            length=req.length,
            ciphertext_hex=req.ciphertext_hex,
            cipher=req.cipher,
            iv_hex=req.iv_hex,
            nonce_hex=req.nonce_hex,
            aad_hex=req.aad_hex,
            tag_hex=req.tag_hex,
            key_material=km,
        )
    except CapabilityError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc

    return {
        "verified": result["verified"],
        "offset": result["offset"],
        "cipher": result["cipher"],
        "key_hex": result["key_hex"],
    }


@router.post("/auto-export")
def auto_export(req: AutoExportRequest):
    """Auto-detect key region and export as YARA/JSON/Volatility3.

    Thin HTTP adapter over the ``app`` producer
    :func:`memdiver.app.tools_pipeline.export_pattern`, which owns the
    consensus → pattern pipeline so the CLI, API and MCP surfaces cannot
    drift again. Prior to PR 4 this route had its own copy of the pipeline
    that called ``cm.build(paths)`` (flat-bytes), producing file-relative
    offsets for native MSL inputs that users could not map back to memory.

    The producer returns the same ``{format, content, pattern, region}``
    payload the pre-relocation service returned, so the response body is
    unchanged.
    """
    from memdiver.app.tools_pipeline import export_pattern

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex)
    try:
        return export_pattern(
            dump_paths=list(req.dump_paths),
            fmt=req.format,
            name=req.name,
            align=req.align,
            context=req.context,
            key_material=km,
        )
    except CapabilityError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


@router.post("/manual-export")
def manual_export(req: ManualExportRequest):
    """Export a pattern from a caller-supplied offset + length.

    The manual counterpart to :func:`auto_export`, and a thin HTTP adapter over
    the ``app`` producer
    :func:`memdiver.app.tools_pipeline.manual_export_pattern` — the same single
    implementation the CLI ``export`` command (without ``--auto``) and the MCP
    ``manual_export_pattern`` tool route through, so the four surfaces cannot
    drift. This route is why ``pipeline.manual_export_pattern`` could be
    registered as a four-surface capability: before it, the only way to reach
    the producer was the terminal.

    ``req.offset`` is memory-relative for ``.msl`` inputs (the producer reads
    through each dump's memory projection), which is the same space every other
    offset in this API is expressed in. Encrypted containers decrypt with the
    ``KeyMaterialFields`` on the body, decoded here exactly as the sibling
    routes do.

    Returns the producer's ``{format, content, pattern, region}`` payload
    verbatim; a user-correctable failure (too few dumps, missing file, unknown
    format, region too volatile) arrives as the producer's ``CapabilityError``
    and is translated to an ``HTTPException`` carrying its own accurate status,
    preserving this router's ``{"detail": ...}`` contract.
    """
    from memdiver.app.tools_pipeline import manual_export_pattern

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex)
    try:
        return manual_export_pattern(
            dump_paths=list(req.dump_paths),
            offset=req.offset,
            length=req.length,
            fmt=req.format,
            name=req.name,
            min_static_ratio=req.min_static_ratio,
            key_material=km,
        )
    except CapabilityError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


@router.post("/export-keylog")
def export_keylog(
    req: ExportKeylogRequest,
    settings: Settings = Depends(get_api_settings),
):
    """Emit a Wireshark-loadable NSS key log from recovered TLS secrets.

    Thin HTTP adapter over the ``app`` producer
    :func:`memdiver.app.tools_pipeline.keylog_result` — the single
    implementation the CLI ``export-keylog`` command and the MCP
    ``export_keylog`` tool also route through, so the headline artifact cannot
    drift across surfaces. Returns ``{keylog, count, output_path}``; a malformed
    hex / missing key surfaces as the producer's ``CapabilityError``, translated
    here to an ``HTTPException`` (preserving this router's ``{"detail": ...}``
    contract).
    """
    from memdiver.app.tools_pipeline import keylog_result

    # ``output_path`` is a WRITE, so it is contained even though this API's
    # localhost path parameters are otherwise an accepted, documented risk.
    # That exemption (see api/main.py) is scoped in writing to READS — the
    # operator deliberately points inspect/analysis at arbitrary local dump
    # files. An unvalidated write is a different class: ``keylog_result`` does
    # ``Path(output_path).write_text(...)``, so an out-of-tree path could land
    # on ~/.ssh/authorized_keys, a shell rc, or a .pth in site-packages.
    # Containment lives here, at the HTTP boundary, and NOT in the producer:
    # the CLI ``export-keylog`` command and the MCP tool legitimately write
    # wherever the operator's own shell can.
    resolved_output: str | None = None
    if req.output_path is not None:
        try:
            # Called here rather than as a Depends so an export WITHOUT an
            # output_path (the frontend's flow) still works on a server with no
            # upload directory chosen yet; only the contained write needs one.
            resolved_output = str(
                ensure_within(upload_dir_or_409(), Path(req.output_path))
            )
        except ValueError as exc:
            # Do not echo the resolved upload_dir — the ValueError message
            # embeds it, which would disclose the server's on-disk layout.
            raise HTTPException(
                status_code=400,
                detail="output_path escapes the upload directory",
            ) from exc

    try:
        return keylog_result(
            secrets=list(req.secrets),
            output_path=resolved_output,
        )
    except CapabilityError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc
