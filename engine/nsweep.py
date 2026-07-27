"""User-facing N-scaling harness for the consensus → oracle pipeline.

Drives the ``memdiver n-sweep`` CLI: builds one incremental Welford
accumulator, adds dumps one at a time, runs the
``candidate_pipeline.reduce_search_space`` chain at every N checkpoint,
and invokes a user oracle against the surviving candidates, returning a
pure ``NSweepResult`` describing how the survivor count shrinks per stage
as N grows. The headline-first report artifacts (json + markdown + plotly
HTML) are rendered by the app-layer writer
(``memdiver.app.reports.write_nsweep_artifacts``), keeping this engine
module free of any presentation dependency.

Split from ``engine/convergence.py`` so the legacy ground-truth sweep
stays small and the new harness owns its own dataclasses.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from memdiver.core.variance import WelfordVariance
from memdiver.engine.progress import (
    ProgressEvent,
    ProgressFn,
    check_cancel,
    noop_progress,
    safe_emit,
)

logger = logging.getLogger("memdiver.engine.nsweep")


@dataclass
class StageTiming:
    consensus_ms: float = 0.0
    reduce_ms: float = 0.0
    brute_force_ms: float = 0.0


@dataclass
class NSweepPoint:
    n: int
    stages: dict
    candidates_tried: int
    hits: int
    hit_offset: Optional[int]
    timing: StageTiming
    fallback_entropy_only: bool = False

    def to_dict(self) -> dict:
        return {
            "n": self.n,
            "stages": dict(self.stages),
            "candidates_tried": self.candidates_tried,
            "hits": self.hits,
            "hit_offset": self.hit_offset,
            "timing_ms": {
                "consensus": round(self.timing.consensus_ms, 2),
                "reduce": round(self.timing.reduce_ms, 2),
                "brute_force": round(self.timing.brute_force_ms, 2),
            },
            "fallback_entropy_only": self.fallback_entropy_only,
        }


@dataclass
class NSweepResult:
    points: List[NSweepPoint] = field(default_factory=list)
    first_hit_n: Optional[int] = None
    first_hit_offset: Optional[int] = None
    first_hit_time_ms: Optional[float] = None
    total_dumps: int = 0
    # Opt-in floor-free escalation verdict (auto_floor.to_dict + hit_tier),
    # populated only when escalate=True and no checkpoint found a hit.
    escalation: Optional[dict] = None

    def to_dict(self) -> dict:
        # Pure data only — the presentation ``headline`` is injected by the
        # app-layer writer (memdiver.app.reports.write_nsweep_artifacts) so the
        # engine never imports up into presentation.
        d = {
            "total_dumps": self.total_dumps,
            "first_hit_n": self.first_hit_n,
            "first_hit_offset": self.first_hit_offset,
            "points": [p.to_dict() for p in self.points],
        }
        # Additive: absent when escalation was not requested / not reached, so
        # the default report stays byte-identical.
        if self.escalation is not None:
            d["escalation"] = self.escalation
        return d


def _fold_until(
    welford: WelfordVariance,
    sources: List,
    already_folded: int,
    target_n: int,
) -> int:
    for idx in range(already_folded, target_n):
        data = sources[idx].read_all()
        if len(data) < welford.size:
            raise ValueError(
                f"source {idx} shorter than welford size "
                f"({len(data)} < {welford.size}); pre-compute min size"
            )
        welford.add_dump(data[: welford.size])
    return target_n


def _probe_min_size(sources: List) -> int:
    """Return the minimum ``read_all`` length across all sources.

    n-sweep must pick a Welford width that every source can satisfy,
    otherwise later folds raise. This costs one extra ``read_all`` per
    source up front; on mmap-backed MSL/raw sources the kernel caches
    the pages so the fold-time reads are free.
    """
    min_size = None
    for src in sources:
        length = len(src.read_all())
        if min_size is None or length < min_size:
            min_size = length
    return int(min_size or 0)


def run_nsweep(
    sources: List,
    *,
    n_values: List[int],
    reduce_kwargs: dict,
    oracle: Callable[[bytes], bool],
    key_sizes=(32,),
    stride: int = 8,
    exhaustive: bool = True,
    escalate: bool = False,
    escalate_oracle_budget: Optional[int] = None,
    progress_callback: ProgressFn = noop_progress,
    cancel_event: Optional[object] = None,
) -> NSweepResult:
    """Drive consensus → reduce → oracle across increasing N values.

    One Welford accumulator grows across checkpoints, so total I/O is
    O(N_max) not O(sum(N)). The oracle is loaded once and invoked for
    every candidate at every checkpoint.

    When ``escalate`` is set and NO checkpoint found a hit, a floor-free
    descending-variance sweep runs once at the terminal (max-N) checkpoint,
    reusing that checkpoint's IN-MEMORY variance (no re-fold). The verdict +
    ``hit_tier`` land on ``NSweepResult.escalation``.
    """
    from memdiver.engine.brute_force import brute_force_with_oracle
    from memdiver.engine.candidate_pipeline import reduce_search_space

    if not sources or not n_values:
        return NSweepResult(total_dumps=len(sources))

    max_n = min(max(n_values), len(sources))
    n_values = sorted({n for n in n_values if 1 <= n <= max_n})
    size = _probe_min_size(sources[:max_n])
    welford = WelfordVariance(size)
    first = sources[0].read_all()[:size]
    welford.add_dump(first)
    reference = first
    folded = 1

    result = NSweepResult(total_dumps=len(sources))
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="nsweep:start",
            pct=0.0,
            msg=f"N values: {n_values}",
            extra={"n_values": list(n_values), "total_sources": len(sources)},
        ),
    )
    for idx, n in enumerate(n_values):
        check_cancel(cancel_event)
        safe_emit(
            progress_callback,
            ProgressEvent(
                stage="nsweep:n_start",
                pct=idx / len(n_values),
                msg=f"N={n}",
                extra={"n": n, "n_index": idx, "n_total": len(n_values)},
            ),
        )
        timing = StageTiming()
        t0 = time.monotonic()
        folded = _fold_until(welford, sources, folded, n)
        variance = welford.variance()
        timing.consensus_ms = (time.monotonic() - t0) * 1000

        t1 = time.monotonic()
        reduction = reduce_search_space(
            variance, reference, num_dumps=n,
            progress_callback=progress_callback,
            **reduce_kwargs,
        )
        timing.reduce_ms = (time.monotonic() - t1) * 1000

        regions_as_dicts = [r.to_dict() for r in reduction.regions]
        t2 = time.monotonic()
        bf = brute_force_with_oracle(
            regions_as_dicts, reference, oracle,
            key_sizes=key_sizes, stride=stride, exhaustive=exhaustive,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )
        timing.brute_force_ms = (time.monotonic() - t2) * 1000

        hit_offset = bf.hits[0].offset if bf.hits else None
        point = NSweepPoint(
            n=n,
            stages=reduction.stages.to_dict(),
            candidates_tried=bf.total_candidates,
            hits=bf.verified_count,
            hit_offset=hit_offset,
            timing=timing,
            fallback_entropy_only=reduction.fallback_entropy_only,
        )
        result.points.append(point)
        safe_emit(
            progress_callback,
            ProgressEvent(
                stage="nsweep:point",
                pct=(idx + 1) / len(n_values),
                msg=f"N={n} tried={bf.total_candidates} hits={bf.verified_count}",
                extra={
                    "n": n,
                    "stages": reduction.stages.to_dict(),
                    "candidates_tried": bf.total_candidates,
                    "hits": bf.verified_count,
                    "hit_offset": hit_offset,
                    "timing_ms": {
                        "consensus": round(timing.consensus_ms, 2),
                        "reduce": round(timing.reduce_ms, 2),
                        "brute_force": round(timing.brute_force_ms, 2),
                    },
                },
            ),
        )
        if result.first_hit_n is None and bf.hits:
            result.first_hit_n = n
            result.first_hit_offset = hit_offset
            result.first_hit_time_ms = timing.brute_force_ms

    # Opt-in floor-free fall-through: only when no checkpoint found a hit. The
    # terminal checkpoint's ``variance`` is still in memory here, so the Welford
    # fold never re-runs. Delegates to the same run_auto_floor as the CLI
    # auto-floor / pipeline escalation (single source of truth).
    if escalate and result.first_hit_n is None and result.points:
        from memdiver.engine.auto_floor import escalation_verdict, run_auto_floor

        safe_emit(
            progress_callback,
            ProgressEvent(
                stage="nsweep:escalate",
                pct=1.0,
                msg=f"floor-free descending-variance sweep at terminal N={n}",
                extra={"n": n},
            ),
        )
        af = run_auto_floor(
            variance, reference, n, oracle,
            reduce_kwargs=dict(reduce_kwargs),
            key_sizes=key_sizes,
            stride=stride,
            oracle_budget=escalate_oracle_budget,
            progress_callback=progress_callback,
        )
        result.escalation = escalation_verdict(af)
    return result
