"""jemalloc 5.x — PARTIAL parser: region attribution + slot-stride inference.

jemalloc keeps every piece of metadata out of band (``edata_t`` extents,
the radix tree ``rtree``, slab bitmaps in the arena's base allocations), so
a small-size-class slab is nothing but ``reg_size``-strided regions with no
inline header. This parser does NOT walk the rtree or the extent metadata;
it:

* attributes mappings to jemalloc from their names (``jemalloc``,
  pre-11 bionic ``[anon:libc_malloc]``) — or, when ``libjemalloc*`` is
  mapped but no region is named, every anonymous writable mapping;
* infers one slot stride per mapping from the jemalloc 5.x small size-class
  table, by scoring how well each candidate stride's slot boundaries line
  up with the content's change points (byte-value changes and
  zero/non-zero word transitions);
* emits the inferred slots as headerless :class:`HeapChunk` s in state
  ``UNKNOWN`` with confidence <= 0.6.

A mapping whose stride cannot be inferred is reported as a region only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np

from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (AllocatorKind, ChunkState, Evidence,
                                 HeapChunk, HeapLayout, HeapRegion)
from memdiver.heap.platform import MappedRegion
from memdiver.heap.registry import (DetectContext, DetectScore, ParseOptions,
                                    name_matches)

#: jemalloc 5.x small size classes (LG_QUANTUM=4, 4 KiB pages: SC_NBINS=36,
#: largest small class 14336 = 3.5 pages).
SMALL_SIZE_CLASSES: Tuple[int, ...] = (
    8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448,
    512, 640, 768, 896, 1024, 1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096,
    5120, 6144, 7168, 8192, 10240, 12288, 14336,
)

PARTIAL_DIAGNOSTIC = "partial: no rtree/extent metadata walk"
MAX_SLOT_CONFIDENCE = 0.6
MIN_STRIDE = 16          # 8-byte strides are indistinguishable from pointers
MIN_SLOTS = 4            # a stride must repeat at least this often
MIN_STRIDE_SCORE = 0.5
MAX_SCAN_BYTES = 1 << 20  # stride inference looks at a mapping's first MiB

_BIONIC_MALLOC_REGION = "[anon:libc_malloc]"
_ARENA_NAME_HINTS = ("arena", "base", "rtree")


@dataclass(frozen=True)
class StrideGuess:
    """The best size class for one mapping and how well it fits (0..1)."""

    stride: int
    score: float


# -- region attribution ---------------------------------------------------------


def _is_named_jemalloc(region: MappedRegion) -> bool:
    if region.module_path:
        return False  # the libjemalloc image itself, not its heap
    return ("jemalloc" in region.name
            or name_matches(region.name, _BIONIC_MALLOC_REGION))


def _is_anonymous_writable(region: MappedRegion) -> bool:
    return (not region.module_path and "w" in region.perms
            and (not region.name or region.name.startswith("[anon")))


def owned_regions(ctx: DetectContext,
                  options: Optional[ParseOptions] = None) -> List[MappedRegion]:
    """Mappings attributed to jemalloc (an explicit region filter wins)."""
    captured = [r for r in ctx.regions if r.captured and r.size > 0]
    if options is not None and options.regions is not None:
        return [r for r in captured if options.selects(r)]
    named = [r for r in captured if _is_named_jemalloc(r)]
    if named or not ctx.matching_modules("libjemalloc*"):
        return named
    return [r for r in captured if _is_anonymous_writable(r)]


def region_kind(region: MappedRegion) -> str:
    """``jemalloc_arena`` for metadata-looking names, else ``jemalloc_extent``."""
    lowered = region.name.lower()
    if any(hint in lowered for hint in _ARENA_NAME_HINTS):
        return "jemalloc_arena"
    return "jemalloc_extent"


# -- stride inference -----------------------------------------------------------


def _byte_changes(data: np.ndarray) -> np.ndarray:
    """``changes[i]`` is True when byte ``i`` differs from byte ``i - 1``."""
    changes = np.zeros(len(data), dtype=bool)
    changes[1:] = data[1:] != data[:-1]
    return changes


def _zero_word_changes(data: np.ndarray, word: int) -> np.ndarray:
    """Byte-indexed zero/non-zero word transitions (True at word starts)."""
    usable = len(data) - len(data) % word
    words = data[:usable].reshape(-1, word)
    is_zero: np.ndarray = np.logical_not(words.any(axis=1))
    changes = np.zeros(len(data), dtype=bool)
    flips = np.flatnonzero(is_zero[1:] != is_zero[:-1]) + 1
    changes[flips * word] = True
    return changes


def boundary_score(changes: np.ndarray, stride: int) -> float:
    """How well slot boundaries every *stride* bytes explain *changes*.

    ``(p_on - p_off) * recall``: boundary change rate minus the change rate
    elsewhere (zero for content with no stride structure), weighted by the
    share of all change points that fall on a boundary (which penalises
    multiples of the true stride).
    """
    nslots = len(changes) // stride
    if nslots < MIN_SLOTS:
        return 0.0
    span = changes[:nslots * stride]
    on = span[stride::stride]
    total = int(span.sum())
    if total == 0 or len(on) == 0:
        return 0.0
    hits = int(on.sum())
    off_count = len(span) - len(on) - 1   # byte 0 is never a change point
    p_off = (total - hits) / off_count if off_count > 0 else 1.0
    return max(0.0, hits / len(on) - p_off) * (hits / total)


def infer_stride(data: bytes, word: int = 8) -> Optional[StrideGuess]:
    """The jemalloc size class whose slot grid best fits *data*, or ``None``."""
    arr = np.frombuffer(data[:MAX_SCAN_BYTES], dtype=np.uint8)
    features = (_byte_changes(arr), _zero_word_changes(arr, word))
    best: Optional[StrideGuess] = None
    for stride in SMALL_SIZE_CLASSES:
        if stride < MIN_STRIDE:
            continue
        score = max(boundary_score(f, stride) for f in features)
        if best is None or score > best.score:
            best = StrideGuess(stride, score)
    if best is None or best.score < MIN_STRIDE_SCORE:
        return None
    return best


# -- parse ----------------------------------------------------------------------


def _slots(region: MappedRegion, guess: StrideGuess,
           budget: int) -> List[HeapChunk]:
    confidence = round(MAX_SLOT_CONFIDENCE * min(1.0, guess.score), 3)
    count = min(region.size // guess.stride, max(budget, 0))
    extra = {"partial": True, "stride_score": round(guess.score, 3)}
    return [HeapChunk(va=va, size=guess.stride, state=ChunkState.UNKNOWN,
                      header_len=0, user_va=va, user_len=guess.stride,
                      bin=f"size_class_{guess.stride}", extra=extra,
                      confidence=confidence)
            for va in range(region.va, region.va + count * guess.stride,
                            guess.stride)]


def _region_guess(mem: VaMemory, region: MappedRegion) -> Optional[StrideGuess]:
    data = mem.read(region.va, min(region.size, MAX_SCAN_BYTES))
    if data is None:
        return None
    return infer_stride(data, mem.platform.pointer_size)


def parse_jemalloc(mem: VaMemory, ctx: DetectContext,
                   options: ParseOptions) -> HeapLayout:
    """Partial jemalloc layout: attributed regions + inferred slab slots."""
    regions = owned_regions(ctx, options)
    chunks: List[HeapChunk] = []
    strides: Dict[str, int] = {}
    diagnostics = [PARTIAL_DIAGNOSTIC]
    for region in regions:
        guess = _region_guess(mem, region)
        if guess is None:
            diagnostics.append(f"{region.va:#x}: no slot stride inferred; "
                               "region only")
            continue
        strides[f"{region.va:#x}"] = guess.stride
        chunks.extend(_slots(region, guess, options.max_chunks - len(chunks)))
    if not regions:
        diagnostics.append("no jemalloc-attributed regions")
    return HeapLayout(
        allocator=AllocatorKind.JEMALLOC, platform=mem.platform,
        regions=tuple(HeapRegion(r.va, r.size, r.name, region_kind(r))
                      for r in regions),
        chunks=tuple(chunks),
        confidence=max((c.confidence for c in chunks), default=0.0),
        diagnostics=tuple(diagnostics),
        coverage={"partial": True, "regions": len(regions),
                  "regions_with_stride": len(strides), "strides": strides},
    )


# -- probe ----------------------------------------------------------------------


def probe_jemalloc(ctx: DetectContext) -> DetectScore:
    """Content probe: a size-class slot grid in a jemalloc-attributed region."""
    for region in owned_regions(ctx):
        guess = _region_guess(ctx.memory, region)
        if guess is not None:
            weight = round(0.3 * guess.score, 3)
            return DetectScore(weight, [Evidence(
                "content", f"{guess.stride}-byte slot grid at {region.va:#x} "
                "(jemalloc size class)", weight)])
    return DetectScore(0.0, [])


#: ``kind -> (parse, probe)``, the order of :class:`heap.builtin.BuiltinSpec`.
DESCRIPTOR_OVERRIDES = {AllocatorKind.JEMALLOC: (probe_jemalloc, parse_jemalloc)}

__all__ = ["SMALL_SIZE_CLASSES", "PARTIAL_DIAGNOSTIC", "StrideGuess",
           "owned_regions", "region_kind", "boundary_score", "infer_stride",
           "parse_jemalloc", "probe_jemalloc", "DESCRIPTOR_OVERRIDES"]
