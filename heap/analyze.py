"""The one heap facade: detect the allocator, parse its heap, never raise.

:func:`analyze_heap` is what every caller (the ``heap.*`` producers,
consensus annotation, ``locate-key``) uses instead of driving the registry
by hand. It

1. detects the allocator (or honours an explicit hint);
2. runs that allocator's parser;
3. when the parser raises or finds no chunks, falls back down the ranked
   candidates and finally to the heuristic ``generic`` walker;
4. records every attempt in ``layout.coverage["analysis"]`` and a line per
   failed attempt in ``layout.diagnostics``.

Parse failures never raise: the worst case is an empty layout whose
diagnostics say why. Only an unknown allocator name raises ``ValueError``.

CACHE. Results are kept in a small process-wide LRU keyed by the dump file
(path, mtime, size, region view filter) and every analysis option, in the
spirit of :mod:`memdiver.app.reader_cache`. Encrypted sources (keyed or
locked) bypass the cache, so a layout derived from decrypted bytes is never
served to a caller without the key. Cached
layouts are shared: treat them as read-only. :func:`clear_heap_cache` drops
every entry.
"""

from __future__ import annotations

import logging
import os
import threading
from collections import OrderedDict
from dataclasses import replace
from pathlib import Path
from typing import (Any, Callable, Dict, Hashable, List, Optional, Sequence,
                    Tuple)

from memdiver.heap.detect import (AUTO_HINT, Candidate, DetectionResult,
                                  detect_in_context)
from memdiver.heap.model import AllocatorKind, Evidence, HeapLayout
from memdiver.heap.registry import DetectContext, ParseOptions, get_allocator

logger = logging.getLogger("memdiver.heap.analyze")

CACHE_SIZE = 8
DEFAULT_MAX_CHUNKS = 200_000

_CacheKey = Tuple[Hashable, ...]
_Attempt = Dict[str, Any]

_cache: "OrderedDict[_CacheKey, HeapLayout]" = OrderedDict()
_cache_lock = threading.Lock()


# -- public API -------------------------------------------------------------------


def parse_allocator_hint(allocator: Any) -> Optional[AllocatorKind]:
    """``None`` for ``"auto"``, else the :class:`AllocatorKind` it names.

    Raises ``ValueError`` (listing the valid names) for anything else.
    """
    if isinstance(allocator, AllocatorKind):
        return allocator
    name = str(allocator or AUTO_HINT).strip().lower()
    if name == AUTO_HINT:
        return None
    try:
        return AllocatorKind(name)
    except ValueError:
        valid = ", ".join([AUTO_HINT] + [k.value for k in AllocatorKind])
        raise ValueError(
            f"unknown allocator {allocator!r}; expected one of: {valid}") from None


def analyze_heap(source: Any, allocator: Any = AUTO_HINT, *,
                 base_va: Optional[int] = None,
                 max_chunks: int = DEFAULT_MAX_CHUNKS,
                 regions: Optional[Sequence[str]] = None) -> HeapLayout:
    """Detect and parse the heap of *source* (a path or an opened DumpSource).

    *allocator* is ``"auto"`` or an :class:`AllocatorKind` (value);
    *base_va* maps a flat dump linearly; *max_chunks* / *regions* are the
    :class:`ParseOptions`. See the module docstring for fallback and caching.
    """
    hint = parse_allocator_hint(allocator)
    options = ParseOptions(max_chunks=max_chunks,
                           regions=tuple(regions) if regions is not None else None)
    if isinstance(source, (str, os.PathLike)):
        return _analyze_path(Path(source), hint, base_va, options)
    key = _source_cache_key(source, hint, base_va, options)
    return _cached(key, lambda: _analyze_source(source, hint, base_va, options))


def clear_heap_cache() -> None:
    """Forget every cached :class:`HeapLayout`."""
    with _cache_lock:
        _cache.clear()


def heap_cache_size() -> int:
    """Number of cached layouts (for tests and diagnostics)."""
    with _cache_lock:
        return len(_cache)


# -- cache ------------------------------------------------------------------------


def _cached(key: Optional[_CacheKey],
            compute: Callable[[], HeapLayout]) -> HeapLayout:
    if key is None:
        return compute()
    with _cache_lock:
        hit = _cache.get(key)
        if hit is not None:
            _cache.move_to_end(key)
            return hit
    layout = compute()
    with _cache_lock:
        _cache[key] = layout
        _cache.move_to_end(key)
        while len(_cache) > CACHE_SIZE:
            _cache.popitem(last=False)
    return layout


def _cache_key(path: Path, region_filter: Optional[str],
               hint: Optional[AllocatorKind], base_va: Optional[int],
               options: ParseOptions) -> Optional[_CacheKey]:
    """``None`` (do not cache) when the file cannot be stat'ed."""
    try:
        resolved = path.resolve()
        stat = resolved.stat()
    except OSError:
        return None
    return (str(resolved), stat.st_mtime_ns, stat.st_size, region_filter,
            hint.value if hint else AUTO_HINT, base_va, options.max_chunks,
            options.regions)


def _source_cache_key(source: Any, hint: Optional[AllocatorKind],
                      base_va: Optional[int],
                      options: ParseOptions) -> Optional[_CacheKey]:
    """``None`` for a pathless source and for ANY encrypted container."""
    path = getattr(source, "path", None)
    if not isinstance(path, (str, os.PathLike)) or _is_encrypted(source):
        return None
    return _cache_key(Path(path), _region_filter_note(source), hint, base_va,
                      options)


def _is_encrypted(source: Any) -> bool:
    """Keyed (decrypted) or locked: either way, never share it via the cache."""
    from memdiver.msl.enums import TagStatus

    return getattr(source, "tag_status", TagStatus.NOT_ENCRYPTED) \
        != TagStatus.NOT_ENCRYPTED


def _region_filter_note(source: Any) -> Optional[str]:
    selection = getattr(source, "region_filter", None)
    to_note = getattr(selection, "to_note", None)
    return str(to_note()) if callable(to_note) else None


# -- analysis ---------------------------------------------------------------------


def _analyze_path(path: Path, hint: Optional[AllocatorKind],
                  base_va: Optional[int], options: ParseOptions) -> HeapLayout:
    from memdiver.core.dump_source import open_dump

    source = open_dump(path)
    source.open()
    try:
        key = _source_cache_key(source, hint, base_va, options)
        return _cached(
            key, lambda: _analyze_source(source, hint, base_va, options))
    finally:
        source.close()


def _analyze_source(source: Any, hint: Optional[AllocatorKind],
                    base_va: Optional[int], options: ParseOptions) -> HeapLayout:
    ctx = DetectContext(source, base_va=base_va)
    detection, notes = _detect(ctx, hint)
    attempts = _attempt_order(detection, hint)
    layout, records = _parse_first_usable(ctx, attempts, options)
    return _annotate(layout, detection, hint, records, notes)


def _detect(ctx: DetectContext, hint: Optional[AllocatorKind]
            ) -> Tuple[DetectionResult, List[str]]:
    try:
        return detect_in_context(ctx, hint.value if hint else AUTO_HINT), []
    except Exception as exc:  # noqa: BLE001 — detection failure is a diagnostic
        logger.warning("Allocator detection failed", exc_info=True)
        empty = DetectionResult([], AllocatorKind.UNKNOWN, 0.0)
        return empty, [f"allocator detection raised {exc!r}"]


def _attempt_order(detection: DetectionResult,
                   hint: Optional[AllocatorKind]) -> List[AllocatorKind]:
    """Parsers to try, best first; ``generic`` is always the last resort."""
    if hint is not None:
        order = [hint]
    else:
        order = [c.kind for c in detection.candidates if c.score > 0.0]
    return list(dict.fromkeys(order + [AllocatorKind.GENERIC]))


def _parse_first_usable(ctx: DetectContext, attempts: List[AllocatorKind],
                        options: ParseOptions
                        ) -> Tuple[Optional[HeapLayout], List[_Attempt]]:
    """The first layout with chunks; else the first that parsed at all."""
    records: List[_Attempt] = []
    first_parsed: Optional[HeapLayout] = None
    for kind in attempts:
        layout, record = _try_parse(kind, ctx, options)
        records.append(record)
        if layout is not None and layout.chunks:
            return layout, records
        if first_parsed is None:
            first_parsed = layout
    return first_parsed, records


def _try_parse(kind: AllocatorKind, ctx: DetectContext,
               options: ParseOptions) -> Tuple[Optional[HeapLayout], _Attempt]:
    record: _Attempt = {"allocator": kind.value, "chunks": 0, "error": None}
    desc = get_allocator(kind)
    if desc is None or desc.parse is None:
        record["error"] = "no parser registered"
        return None, record
    try:
        layout = desc.parse(ctx.memory, ctx, options)
    except Exception as exc:  # noqa: BLE001 — one parser must not sink the analysis
        logger.debug("Heap parser %s failed", kind.value, exc_info=True)
        record["error"] = f"parser raised {exc!r}"
        return None, record
    record["chunks"] = len(layout.chunks)
    return layout, record


def _annotate(layout: Optional[HeapLayout], detection: DetectionResult,
              hint: Optional[AllocatorKind], records: List[_Attempt],
              notes: List[str]) -> HeapLayout:
    """Attach detection evidence and the attempt log to the chosen layout."""
    base = layout or HeapLayout(AllocatorKind.UNKNOWN, platform=detection.platform)
    analysis = _analysis_record(base, detection, hint, records)
    coverage = dict(base.coverage)
    coverage["analysis"] = analysis
    return replace(
        base,
        platform=base.platform or detection.platform,
        evidence=_chosen_evidence(detection, base.allocator) + base.evidence,
        diagnostics=tuple(notes + _attempt_diagnostics(analysis))
        + base.diagnostics,
        coverage=coverage,
    )


def _analysis_record(layout: HeapLayout, detection: DetectionResult,
                     hint: Optional[AllocatorKind],
                     records: List[_Attempt]) -> Dict[str, Any]:
    first = records[0]["allocator"] if records else None
    return {
        "requested": hint.value if hint else AUTO_HINT,
        "detected": detection.best.value,
        "detection_confidence": round(detection.confidence, 4),
        "chosen": layout.allocator.value,
        "fell_back": first is not None and layout.allocator.value != first,
        "attempts": records,
    }


def _attempt_diagnostics(analysis: Dict[str, Any]) -> List[str]:
    lines = [f"{r['allocator']}: {r['error'] or 'parser found no chunks'}"
             for r in analysis["attempts"]
             if r["error"] or r["chunks"] == 0]
    if analysis["fell_back"]:
        lines.append(f"fell back from {analysis['attempts'][0]['allocator']} "
                     f"to {analysis['chosen']}")
    return lines


def _chosen_evidence(detection: DetectionResult,
                     kind: AllocatorKind) -> Tuple[Evidence, ...]:
    match: Optional[Candidate] = next(
        (c for c in detection.candidates if c.kind is kind), None)
    return tuple(match.evidence) if match is not None else ()


__all__ = ["analyze_heap", "clear_heap_cache", "heap_cache_size",
           "parse_allocator_hint", "CACHE_SIZE", "DEFAULT_MAX_CHUNKS"]
