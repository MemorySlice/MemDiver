"""User-facing N-scaling harness for the consensus → oracle pipeline.

Drives the ``memdiver n-sweep`` CLI: builds one incremental Welford
accumulator, adds dumps one at a time, runs the
``candidate_pipeline.reduce_search_space`` chain at every N checkpoint,
and invokes a user oracle against the surviving candidates. Emits a
headline-first report (json + markdown + plotly HTML) describing how
the survivor count shrinks per stage as N grows.

Split from ``engine/convergence.py`` so the legacy ground-truth sweep
stays small and the new harness owns its own dataclasses and plot code.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from core.variance import WelfordVariance
from engine.progress import (
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

    def headline(self) -> str:
        if self.first_hit_n is None:
            last = self.points[-1] if self.points else None
            if last:
                return (
                    f"Exhausted {self.total_dumps} dumps without a hit; "
                    f"smallest survivor set at N={last.n}: "
                    f"{last.stages.get('high_entropy', 0)} candidates."
                )
            return "n-sweep ran on zero dumps."
        point = next(p for p in self.points if p.n == self.first_hit_n)
        return (
            f"At N={self.first_hit_n}, {point.stages.get('high_entropy', 0)} "
            f"candidates survived, {point.hits} decrypted in "
            f"{point.timing.brute_force_ms / 1000:.2f}s at offset "
            f"0x{self.first_hit_offset:x}."
        )

    def to_dict(self) -> dict:
        return {
            "total_dumps": self.total_dumps,
            "first_hit_n": self.first_hit_n,
            "first_hit_offset": self.first_hit_offset,
            "headline": self.headline(),
            "points": [p.to_dict() for p in self.points],
        }


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
    progress_callback: ProgressFn = noop_progress,
    cancel_event: Optional[object] = None,
) -> NSweepResult:
    """Drive consensus → reduce → oracle across increasing N values.

    One Welford accumulator grows across checkpoints, so total I/O is
    O(N_max) not O(sum(N)). The oracle is loaded once and invoked for
    every candidate at every checkpoint.
    """
    from engine.brute_force import brute_force_with_oracle
    from engine.candidate_pipeline import reduce_search_space

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
    return result


def _nsweep_markdown(result: NSweepResult, plot_href: Optional[str] = None) -> str:
    lines: List[str] = ["# N-sweep report", "", f"**{result.headline()}**", ""]
    if plot_href:
        lines.append(f"![reduction curve]({plot_href})")
        lines.append("")
    lines.append(
        "| N | variance | aligned | high_entropy | tried | hits | t_cons ms | t_red ms | t_bf ms |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for p in result.points:
        s = p.stages
        lines.append(
            f"| {p.n} | {s.get('variance', 0)} | {s.get('aligned', 0)} | "
            f"{s.get('high_entropy', 0)} | {p.candidates_tried} | {p.hits} | "
            f"{p.timing.consensus_ms:.0f} | {p.timing.reduce_ms:.0f} | "
            f"{p.timing.brute_force_ms:.0f} |"
        )
    return "\n".join(lines) + "\n"


def _nsweep_plotly_html(result: NSweepResult) -> str:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    ns = [p.n for p in result.points]
    fig = make_subplots(
        rows=2, cols=1, shared_xaxes=True,
        subplot_titles=("Survivors vs N", "Wall-clock per stage (ms)"),
    )
    for stage in ("variance", "aligned", "high_entropy"):
        fig.add_trace(
            go.Scatter(
                x=ns, y=[max(1, p.stages.get(stage, 0)) for p in result.points],
                mode="lines+markers", name=stage,
            ),
            row=1, col=1,
        )
    fig.add_trace(
        go.Scatter(
            x=ns, y=[max(1, p.hits) for p in result.points],
            mode="lines+markers", name="hits",
        ),
        row=1, col=1,
    )
    fig.update_yaxes(type="log", row=1, col=1)
    for name, attr in (("consensus", "consensus_ms"), ("reduce", "reduce_ms"),
                       ("brute_force", "brute_force_ms")):
        fig.add_trace(
            go.Bar(
                x=ns, y=[getattr(p.timing, attr) for p in result.points],
                name=name,
            ),
            row=2, col=1,
        )
    fig.update_layout(
        title=f"N-sweep: {result.headline()}",
        height=700, showlegend=True,
    )
    return fig.to_html(full_html=True, include_plotlyjs="cdn")


def write_nsweep_artifacts(result: NSweepResult, output_dir: Path) -> dict:
    """Write report.json, report.md, report.html under output_dir."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    html_path = output_dir / "report.html"
    md_path = output_dir / "report.md"
    json_path.write_text(json.dumps(result.to_dict(), indent=2))
    html_path.write_text(_nsweep_plotly_html(result))
    md_path.write_text(_nsweep_markdown(result, plot_href="report.html"))
    return {"json": json_path, "html": html_path, "md": md_path}
