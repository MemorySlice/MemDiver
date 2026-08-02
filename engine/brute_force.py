"""Candidate brute-force loop against a user-supplied decryption oracle.

Drives the ``memdiver brute-force`` CLI. Takes a candidates.json emitted
by ``search-reduce``, iterates every (offset, key_size) slice through the
oracle, and reports hits. On first hit it materializes the neighborhood
variance slice from the stored Welford state so ``emit-plugin`` can
build a vol3 anchor without re-reading the consensus matrix.

Parallelism: when ``jobs > 1`` dispatches via a spawn-based
ProcessPoolExecutor. Workers re-import the user oracle from its absolute
path because importlib spec modules don't survive pickling. Serial mode
(``jobs=1``) keeps the oracle in-process so tracebacks are readable.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from multiprocessing import get_context
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Tuple

import numpy as np

from memdiver.engine.candidate_grid import iter_region_grid
from memdiver.engine.oracle import (
    OracleFn,
    load_oracle,
    load_oracle_config,
    validate_oracle_sandboxed,
)
from memdiver.engine.progress import (
    Cancelled,
    ProgressEvent,
    ProgressFn,
    check_cancel,
    noop_progress,
    safe_emit,
)

logger = logging.getLogger("memdiver.engine.brute_force")

_PROGRESS_EVERY = 256

EXIT_HIT = 0
EXIT_CRASH = 1
EXIT_NO_HIT = 2

NEIGHBORHOOD_PAD = 64


@dataclass
class Hit:
    offset: int
    length: int
    key_hex: str
    region_index: int
    neighborhood_variance: List[float] = field(default_factory=list)
    neighborhood_start: int = 0

    def to_dict(self) -> dict:
        return {
            "offset": int(self.offset),
            "length": int(self.length),
            "key_hex": self.key_hex,
            "region_index": int(self.region_index),
            "neighborhood_start": int(self.neighborhood_start),
            "neighborhood_variance": list(self.neighborhood_variance),
        }


@dataclass
class TopKEntry:
    offset: int
    length: int
    mean_variance: float
    mean_entropy: float

    def to_dict(self) -> dict:
        return {
            "offset": int(self.offset),
            "length": int(self.length),
            "mean_variance": float(self.mean_variance),
            "mean_entropy": float(self.mean_entropy),
        }


@dataclass
class BruteForceResult:
    hits: List[Hit] = field(default_factory=list)
    total_candidates: int = 0
    verified_count: int = 0
    exhaustive: bool = True
    top_k: List[TopKEntry] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return EXIT_HIT if self.hits else EXIT_NO_HIT

    def to_dict(self) -> dict:
        return {
            "hits": [h.to_dict() for h in self.hits],
            "total_candidates": self.total_candidates,
            "verified_count": self.verified_count,
            "exhaustive": self.exhaustive,
            "top_k": [t.to_dict() for t in self.top_k],
        }


def load_candidates(path: Path) -> dict:
    """Load a candidates.json produced by ``memdiver search-reduce``."""
    return json.loads(Path(path).read_text())


def iter_candidate_slices(
    regions: Sequence[dict],
    reference_data: bytes,
    key_sizes: Sequence[int],
    stride: int,
) -> Iterator[Tuple[int, int, int, bytes]]:
    """Yield ``(region_index, offset, size, candidate_bytes)`` tuples.

    The iteration grid is snapped up to the first multiple of ``stride``
    ≥ the region start, so that when stride == alignment the candidate
    offsets align with the same grid the alignment filter used to keep
    the region. Regions whose first kept byte is slightly unaligned
    (common when the aligned filter keeps block-edge bytes) still get
    their aligned interior offsets tested.
    """
    if stride <= 0:
        raise ValueError("stride must be positive")
    dump_len = len(reference_data)
    for ridx, region in enumerate(regions):
        r_start = int(region["offset"])
        r_end = r_start + int(region["length"])
        for offset, size in iter_region_grid(r_start, r_end, key_sizes, stride, dump_len):
            yield ridx, offset, size, reference_data[offset:offset + size]


def count_candidate_slices(
    regions: Sequence[dict],
    reference_data: bytes,
    key_sizes: Sequence[int],
    stride: int,
) -> int:
    """Count candidates without materialising their bytes.

    Equivalent to ``sum(1 for _ in iter_candidate_slices(...))`` but iterates
    the (offset, size) grid directly via :func:`iter_region_grid`, skipping the
    per-candidate ``reference_data`` slice. Used for the progress-total
    precomputation pass so counting never allocates candidate byte-strings.
    """
    if stride <= 0:
        raise ValueError("stride must be positive")
    dump_len = len(reference_data)
    total = 0
    for region in regions:
        r_start = int(region["offset"])
        r_end = r_start + int(region["length"])
        total += sum(
            1 for _ in iter_region_grid(r_start, r_end, key_sizes, stride, dump_len)
        )
    return total


def _load_neighborhood_variance(
    state_path: Path,
    offset: int,
    length: int,
) -> Tuple[int, List[float]]:
    """Slice the hit's neighborhood variance from a mmap'd m2.npy."""
    state = json.loads(Path(state_path).read_text())
    n = int(state.get("num_dumps", 0))
    if n == 0:
        return offset, []
    m2 = np.load(state["m2_path"], mmap_mode="r")
    try:
        start = max(0, offset - NEIGHBORHOOD_PAD)
        end = min(len(m2), offset + length + NEIGHBORHOOD_PAD)
        # ``.astype`` materializes an independent copy, so the mapping can be
        # released immediately below.
        slice_variance = (m2[start:end].astype(np.float32) / float(n))
    finally:
        # Release the mmap fd now — this runs once per hit; leaving it to GC
        # accumulates open mappings across an exhaustive many-hit run.
        mm = getattr(m2, "_mmap", None)
        if mm is not None:
            mm.close()
    return start, slice_variance.tolist()


def _build_top_k(regions: Sequence[dict], k: int) -> List[TopKEntry]:
    ranked = sorted(
        regions,
        key=lambda r: (float(r.get("mean_variance", 0.0)), float(r.get("mean_entropy", 0.0))),
        reverse=True,
    )
    return [
        TopKEntry(
            offset=int(r["offset"]),
            length=int(r["length"]),
            mean_variance=float(r.get("mean_variance", 0.0)),
            mean_entropy=float(r.get("mean_entropy", 0.0)),
        )
        for r in ranked[:k]
    ]


_WORKER_ORACLE: Optional[OracleFn] = None


def _worker_init(oracle_path: str, oracle_config: dict) -> None:
    global _WORKER_ORACLE
    # sandbox=False: run_brute_force() validates the oracle exactly once in the
    # parent (validate_oracle_sandboxed, before the serial/parallel split), so
    # this invariant is genuinely established for BOTH branches. The W pool
    # workers must NOT each re-spawn a redundant validation subprocess on this
    # hot startup path.
    _WORKER_ORACLE = load_oracle(Path(oracle_path), oracle_config, sandbox=False)


def _worker_verify(job: Tuple[int, int, int, bytes]) -> Tuple[int, int, int, bool]:
    ridx, offset, size, candidate = job
    try:
        ok = bool(_WORKER_ORACLE(candidate))  # type: ignore[misc]
    except Exception as exc:  # user oracle must not kill the worker pool
        logger.debug("oracle raised at offset 0x%x: %s", offset, exc)
        ok = False
    return ridx, offset, size, ok


def _run_serial(
    jobs: Iterator[Tuple[int, int, int, bytes]],
    oracle: OracleFn,
    exhaustive: bool,
    *,
    total_estimate: int = 0,
    progress_callback: ProgressFn = noop_progress,
    cancel_event: Optional[object] = None,
) -> Tuple[List[Tuple[int, int, int]], int]:
    hits: List[Tuple[int, int, int]] = []
    total = 0
    for ridx, offset, size, candidate in jobs:
        if total % _PROGRESS_EVERY == 0:
            check_cancel(cancel_event)
        total += 1
        try:
            ok = bool(oracle(candidate))
        except Exception as exc:
            logger.debug("oracle raised at offset 0x%x: %s", offset, exc)
            ok = False
        if ok:
            hits.append((ridx, offset, size))
            safe_emit(
                progress_callback,
                ProgressEvent(
                    stage="brute_force:hit",
                    pct=-1.0,
                    msg=f"hit @ 0x{offset:x} size={size}",
                    extra={"offset": int(offset), "size": int(size),
                           "region_index": int(ridx)},
                ),
            )
            if not exhaustive:
                break
        if total % _PROGRESS_EVERY == 0:
            pct = (total / total_estimate) if total_estimate > 0 else -1.0
            safe_emit(
                progress_callback,
                ProgressEvent(
                    stage="brute_force:progress",
                    pct=pct,
                    msg=f"tried={total} hits={len(hits)}",
                    extra={"tried": total, "hits": len(hits),
                           "total": total_estimate},
                ),
            )
    return hits, total


def _run_parallel(
    jobs_iter: Iterator[Tuple[int, int, int, bytes]],
    oracle_path: Path,
    oracle_config: dict,
    jobs: int,
    exhaustive: bool,
    *,
    total_estimate: int = 0,
    progress_callback: ProgressFn = noop_progress,
    cancel_event: Optional[object] = None,
) -> Tuple[List[Tuple[int, int, int]], int]:
    """Stream candidates through a process pool with bounded back-pressure.

    Rather than eagerly submitting one Future per candidate (which would
    pickle the entire candidate space — each job carries its candidate
    bytes — into the pool at once), this keeps at most ``max_in_flight``
    Futures outstanding: it primes the window, then submits the next
    candidate only as an earlier one completes. Memory therefore stays
    bounded like the serial path. ``total_estimate`` is only used for the
    progress percentage. Hit *ordering* is normalized by the caller (sorted by
    offset), so the non-deterministic completion order no longer leaks into the
    result; on the first non-exhaustive hit this path stops feeding new
    candidates and drains the current in-flight window (rather than cancelling
    immediately), so the caller can pick the lowest-offset hit deterministically.
    """
    hits: List[Tuple[int, int, int]] = []
    completed = 0
    total = total_estimate
    # A small multiple of the worker count keeps every worker fed while
    # capping how many candidate-byte payloads are resident at once.
    max_in_flight = max(1, jobs * 4)
    ctx = get_context("spawn")
    with ProcessPoolExecutor(
        max_workers=jobs,
        mp_context=ctx,
        initializer=_worker_init,
        initargs=(str(oracle_path), oracle_config),
    ) as pool:
        in_flight = set()
        draining = False  # set on the first non-exhaustive hit
        try:
            # Prime the in-flight window.
            for job in jobs_iter:
                in_flight.add(pool.submit(_worker_verify, job))
                if len(in_flight) >= max_in_flight:
                    break

            while in_flight:
                done, in_flight = wait(in_flight, return_when=FIRST_COMPLETED)
                for fut in done:
                    check_cancel(cancel_event)
                    completed += 1
                    ridx, offset, size, ok = fut.result()
                    if ok:
                        hits.append((ridx, offset, size))
                        safe_emit(
                            progress_callback,
                            ProgressEvent(
                                stage="brute_force:hit",
                                pct=-1.0,
                                msg=f"hit @ 0x{offset:x} size={size}",
                                extra={"offset": int(offset), "size": int(size),
                                       "region_index": int(ridx)},
                            ),
                        )
                        # Non-exhaustive: stop feeding new candidates but let the
                        # current in-flight window finish, so the caller can pick
                        # the lowest-offset hit deterministically instead of
                        # whichever future happened to complete first.
                        if not exhaustive:
                            draining = True
                    if completed % _PROGRESS_EVERY == 0:
                        pct = (completed / total) if total > 0 else -1.0
                        safe_emit(
                            progress_callback,
                            ProgressEvent(
                                stage="brute_force:progress",
                                pct=pct,
                                msg=f"tried={completed}/{total} hits={len(hits)}",
                                extra={"tried": completed, "hits": len(hits),
                                       "total": total},
                            ),
                        )
                if not draining:
                    # Refill the window: submit one new candidate per slot freed
                    # by the just-completed Futures.
                    for job in jobs_iter:
                        in_flight.add(pool.submit(_worker_verify, job))
                        if len(in_flight) >= max_in_flight:
                            break
        except Cancelled:
            for pending in in_flight:
                pending.cancel()
            raise
        # best-effort cancel: already-running workers will finish, but
        # queued-but-unstarted futures drop without invoking the oracle.
        for pending in in_flight:
            pending.cancel()
    return hits, completed


def brute_force_with_oracle(
    regions: Sequence[dict],
    reference_data: bytes,
    oracle: OracleFn,
    *,
    key_sizes: Sequence[int] = (32,),
    stride: int = 8,
    exhaustive: bool = True,
    top_k: int = 10,
    progress_callback: ProgressFn = noop_progress,
    cancel_event: Optional[object] = None,
) -> BruteForceResult:
    """Iterate candidates through a pre-loaded oracle callable.

    Used by run_nsweep so the oracle is loaded exactly once across all
    N values. Does NOT attach neighborhood variance — callers that
    need it should invoke ``_load_neighborhood_variance`` themselves.
    """
    # Count candidates without holding the whole list resident: the generator
    # is memory-bounded, so a discard-count pass keeps peak memory O(1) while
    # still reporting the exact total upfront. The oracle (the expensive part)
    # still runs exactly once per candidate, on a fresh generator.
    total_estimate = count_candidate_slices(regions, reference_data, key_sizes, stride)
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="brute_force:start",
            pct=0.0,
            msg=f"candidates={total_estimate}",
            extra={"total": total_estimate},
        ),
    )
    raw_hits, total = _run_serial(
        iter_candidate_slices(regions, reference_data, key_sizes, stride),
        oracle,
        exhaustive,
        total_estimate=total_estimate,
        progress_callback=progress_callback,
        cancel_event=cancel_event,
    )
    # Deterministic ordering: the emitted plugin anchors on hits[0], so sort by
    # (offset, region_index, size) regardless of discovery order — identical
    # inputs must always yield an identical plugin.
    raw_hits.sort(key=lambda h: (h[1], h[0], h[2]))
    hits = [
        Hit(
            offset=offset,
            length=size,
            key_hex=reference_data[offset:offset + size].hex(),
            region_index=ridx,
        )
        for ridx, offset, size in raw_hits
    ]
    result = BruteForceResult(
        hits=hits,
        total_candidates=total,
        verified_count=len(hits),
        exhaustive=exhaustive,
    )
    if not hits:
        result.top_k = _build_top_k(regions, top_k)
    return result


def run_brute_force(
    candidates_path: Path,
    reference_data: bytes,
    oracle_path: Path,
    *,
    oracle_config_path: Optional[Path] = None,
    key_sizes: Sequence[int] = (32,),
    stride: int = 8,
    jobs: int = 1,
    exhaustive: bool = True,
    state_path: Optional[Path] = None,
    top_k: int = 10,
    progress_callback: ProgressFn = noop_progress,
    cancel_event: Optional[object] = None,
) -> BruteForceResult:
    """Iterate candidates through ``--oracle`` and return a BruteForceResult."""
    payload = load_candidates(candidates_path)
    regions: List[dict] = payload.get("regions", [])
    oracle_config = load_oracle_config(oracle_config_path)

    # Validate the oracle ONCE here in the parent, before the serial/parallel
    # split, so every path is covered — including the parallel branch whose
    # workers load with sandbox=False. This is the single parent-side chokepoint
    # that establishes the "validated upstream" invariant _worker_init relies on;
    # without it, ``--jobs N`` would run untrusted oracle code in W workers with
    # the load-time sandbox fully bypassed. Raises OracleLoadError on hang/OOM/
    # crash BEFORE any worker (or serial load) touches the oracle. The ok-cache
    # in engine.oracle dedups this against the serial branch's own load.
    validate_oracle_sandboxed(oracle_path, oracle_config)

    # Count candidates via a slice-free grid pass instead of holding the full
    # materialized list; the dispatch below then streams a fresh generator
    # (serial iterates it directly; the parallel path keeps its bounded
    # in-flight window). Count matches the run exactly because both derive from
    # the same pure iter_region_grid over identical inputs.
    total_estimate = count_candidate_slices(regions, reference_data, key_sizes, stride)
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="brute_force:start",
            pct=0.0,
            msg=f"candidates={total_estimate} jobs={jobs}",
            extra={"total": total_estimate, "jobs": jobs},
        ),
    )

    job_iter = iter_candidate_slices(regions, reference_data, key_sizes, stride)
    if jobs > 1 and total_estimate > 1:
        raw_hits, total = _run_parallel(
            job_iter, oracle_path, oracle_config, jobs, exhaustive,
            total_estimate=total_estimate,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )
    else:
        # Already validated once in the parent above (sandbox=True), so skip the
        # redundant re-spawn here; the ok-cache would dedup it anyway.
        oracle = load_oracle(oracle_path, oracle_config, sandbox=False)
        raw_hits, total = _run_serial(
            job_iter, oracle, exhaustive,
            total_estimate=total_estimate,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )

    # Deterministic ordering: the emitted plugin anchors on hits[0], so sort by
    # (offset, region_index, size) regardless of discovery order (serial
    # iteration vs parallel completion) — identical inputs must always yield an
    # identical plugin.
    raw_hits.sort(key=lambda h: (h[1], h[0], h[2]))
    hits: List[Hit] = []
    for ridx, offset, size in raw_hits:
        neighborhood_start = offset
        neighborhood: List[float] = []
        if state_path is not None:
            try:
                neighborhood_start, neighborhood = _load_neighborhood_variance(
                    state_path, offset, size
                )
            except Exception as exc:
                logger.warning("could not load neighborhood variance: %s", exc)
        hits.append(
            Hit(
                offset=offset,
                length=size,
                key_hex=reference_data[offset:offset + size].hex(),
                region_index=ridx,
                neighborhood_variance=neighborhood,
                neighborhood_start=neighborhood_start,
            )
        )

    result = BruteForceResult(
        hits=hits,
        total_candidates=total,
        verified_count=len(hits),
        exhaustive=exhaustive,
    )
    if not hits:
        result.top_k = _build_top_k(regions, top_k)
    return result


def write_result(result: BruteForceResult, hits_path: Path) -> Path:
    hits_path = Path(hits_path)
    hits_path.parent.mkdir(parents=True, exist_ok=True)
    hits_path.write_text(json.dumps(result.to_dict(), indent=2))
    return hits_path
