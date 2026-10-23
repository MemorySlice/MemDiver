"""Which allocator produced this dump? Ranked candidates with evidence.

:func:`detect_allocator` runs every registered detector (:mod:`.registry`)
over one shared :class:`~memdiver.heap.registry.DetectContext` and ranks the
results. The built-in detectors (:mod:`.builtin`) score the cheap name /
module / OS signals defined here — each one an :class:`Evidence` with a
weight — and later combine them with a content probe of the heap bytes.

Signals (weights add up, capped at 1.0):

* ptmalloc2 — glibc mapped (``libc.so.6``, ``libc-2.*.so``), ``[heap]``;
* scudo — ``[anon:scudo:*]`` regions, ``libscudo*``, Android OS prior;
* jemalloc — ``libjemalloc*``, ``jemalloc`` region names, and Android's
  ``[anon:libc_malloc]`` (pre-11 bionic) when no scudo names are present;
* mallocng — the musl loader / libc (``ld-musl-*.so.1``, ``libc.musl-*``);
* generic — a weak fallback whenever a memory map exists at all.

No signal at all (a flat raw dump) yields :attr:`AllocatorKind.UNKNOWN`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, NamedTuple, Optional

from memdiver.heap.model import AllocatorKind, Evidence
from memdiver.heap.platform import TargetPlatform
from memdiver.heap.registry import (DetectContext, registered_allocators,
                                    run_detector)

AUTO_HINT = "auto"

_GLIBC_MODULES = ("libc.so.6", "libc-2.*.so")
_MUSL_MODULES = ("ld-musl-*.so.1", "libc.musl-*")
_SCUDO_REGIONS = "[anon:scudo:*"
_BIONIC_MALLOC_REGION = "[anon:libc_malloc]"


class Candidate(NamedTuple):
    """One ranked allocator guess."""

    kind: AllocatorKind
    score: float
    evidence: List[Evidence]


@dataclass(frozen=True)
class DetectionResult:
    """Ranked candidates (best first) and the verdict."""

    candidates: List[Candidate]
    best: AllocatorKind
    confidence: float
    platform: Optional[TargetPlatform] = None
    hinted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "best": self.best.value,
            "confidence": round(self.confidence, 4),
            "hinted": self.hinted,
            "platform": _platform_dict(self.platform),
            "candidates": [_candidate_dict(c) for c in self.candidates],
        }


def _candidate_dict(candidate: Candidate) -> Dict[str, Any]:
    return {
        "kind": candidate.kind.value,
        "score": round(candidate.score, 4),
        "evidence": [{"source": e.source, "detail": e.detail,
                      "weight": e.weight} for e in candidate.evidence],
    }


def _platform_dict(platform: Optional[TargetPlatform]) -> Optional[Dict[str, Any]]:
    if platform is None:
        return None
    return {"os": platform.os, "arch": platform.arch,
            "pointer_size": platform.pointer_size,
            "endianness": platform.endianness, "source": platform.source}


# -- detection ------------------------------------------------------------------


def detect_allocator(source: Any, hint: str = AUTO_HINT, *,
                     base_va: Optional[int] = None) -> DetectionResult:
    """Rank the registered allocators for *source*.

    *hint* is ``"auto"`` or an :class:`AllocatorKind` value; a concrete kind
    is returned as-is with confidence 1.0 (``ValueError`` if unknown).
    """
    return detect_in_context(DetectContext(source, base_va=base_va), hint)


def detect_in_context(ctx: DetectContext,
                      hint: str = AUTO_HINT) -> DetectionResult:
    """:func:`detect_allocator` over an existing context (shares its probes)."""
    if hint != AUTO_HINT:
        return _hinted_result(AllocatorKind(hint), ctx)
    candidates = rank_candidates(ctx)
    return _verdict(candidates, ctx.platform)


def rank_candidates(ctx: DetectContext) -> List[Candidate]:
    """Every registered detector's score on *ctx*, best first."""
    candidates = []
    for desc in registered_allocators():
        result = run_detector(desc, ctx)
        candidates.append(Candidate(desc.kind, result.score, result.evidence))
    # sorted() is stable, so equal scores keep registry priority order.
    return sorted(candidates, key=lambda c: -c.score)


def _verdict(candidates: List[Candidate],
             platform: TargetPlatform) -> DetectionResult:
    top = candidates[0] if candidates else None
    if top is None or top.score <= 0.0:
        return DetectionResult(candidates, AllocatorKind.UNKNOWN, 0.0, platform)
    return DetectionResult(candidates, top.kind, top.score, platform)


def _hinted_result(kind: AllocatorKind, ctx: DetectContext) -> DetectionResult:
    hinted = Candidate(kind, 1.0, [Evidence("hint", "user hint", 1.0)])
    return DetectionResult([hinted], kind, 1.0, ctx.platform, hinted=True)


# -- name / module / OS signals -------------------------------------------------


def _ptmalloc2_signals(ctx: DetectContext) -> List[Evidence]:
    evidence = [Evidence("module", f"glibc mapped: {name}", 0.6)
                for name in ctx.matching_modules(*_GLIBC_MODULES)[:1]]
    if ctx.has_region("[heap]") and not ctx.platform.is_android:
        evidence.append(Evidence("region", "[heap] brk region present", 0.25))
    return evidence


def _scudo_signals(ctx: DetectContext) -> List[Evidence]:
    evidence = []
    if ctx.has_region(_SCUDO_REGIONS):
        evidence.append(Evidence("region", "[anon:scudo:*] regions present", 0.8))
    evidence += [Evidence("module", f"scudo library mapped: {name}", 0.6)
                 for name in ctx.matching_modules("libscudo*")[:1]]
    if ctx.platform.is_android:
        evidence.append(Evidence("os", "Android >= 11 defaults to scudo", 0.15))
    return evidence


def _jemalloc_signals(ctx: DetectContext) -> List[Evidence]:
    evidence = [Evidence("module", f"jemalloc library mapped: {name}", 0.7)
                for name in ctx.matching_modules("libjemalloc*")[:1]]
    if any("jemalloc" in name for name in ctx.region_names):
        evidence.append(Evidence("region", "jemalloc-named regions present", 0.6))
    if _is_pre11_bionic_heap(ctx):
        evidence.append(Evidence(
            "region", "[anon:libc_malloc] without scudo (pre-11 bionic)", 0.5))
    return evidence


def _is_pre11_bionic_heap(ctx: DetectContext) -> bool:
    return (ctx.platform.is_android and ctx.has_region(_BIONIC_MALLOC_REGION)
            and not ctx.has_region(_SCUDO_REGIONS))


def _mallocng_signals(ctx: DetectContext) -> List[Evidence]:
    return [Evidence("module", f"musl mapped: {name}", 0.8)
            for name in ctx.matching_modules(*_MUSL_MODULES)[:1]]


def _dlmalloc_signals(ctx: DetectContext) -> List[Evidence]:
    # No naming convention: dlmalloc is embedded, found by content only.
    return []


def _generic_signals(ctx: DetectContext) -> List[Evidence]:
    if not ctx.regions:
        return []
    return [Evidence("fallback", "memory map present, no allocator-specific "
                     "signal required", 0.05)]


NAME_SIGNALS: Dict[AllocatorKind, Callable[[DetectContext], List[Evidence]]] = {
    AllocatorKind.PTMALLOC2: _ptmalloc2_signals,
    AllocatorKind.DLMALLOC: _dlmalloc_signals,
    AllocatorKind.SCUDO: _scudo_signals,
    AllocatorKind.MALLOCNG: _mallocng_signals,
    AllocatorKind.JEMALLOC: _jemalloc_signals,
    AllocatorKind.GENERIC: _generic_signals,
}


def name_signals(kind: AllocatorKind, ctx: DetectContext) -> List[Evidence]:
    """The name / module / OS evidence for *kind* on *ctx* (may be empty)."""
    signals = NAME_SIGNALS.get(kind)
    return signals(ctx) if signals is not None else []


def evidence_score(evidence: List[Evidence]) -> float:
    """Sum of evidence weights, capped at 1.0."""
    return min(1.0, sum(e.weight for e in evidence))
