"""Heuristic fallback for unknown allocators: boundary-tag size chains.

Most in-band allocators (dlmalloc descendants, many embedded heaps) put a
size word in front of every chunk, so ``chunk + size`` lands on the next
chunk's header. This module looks for exactly that, without knowing the
allocator: from a few aligned start offsets of a mapping it reads a size
word at a candidate header offset, masks the low flag bits, and follows
the chain as long as every size is aligned, plausible and stays inside the
mapping. A chain of at least :data:`MIN_CHAIN_STEPS` links is reported as
chunks — state ``UNKNOWN``, confidence capped at :data:`MAX_CONFIDENCE` —
and the layout is marked ``heuristic``. Nothing about allocation state,
free lists or metadata is inferred.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (AllocatorKind, ChunkState, Evidence,
                                 HeapChunk, HeapLayout, HeapRegion)
from memdiver.heap.platform import MappedRegion
from memdiver.heap.registry import DetectContext, DetectScore, ParseOptions

HEURISTIC_DIAGNOSTIC = ("heuristic: boundary-tag size chain; allocator, "
                        "chunk state and free lists unknown")
MAX_CONFIDENCE = 0.3
MIN_CHAIN_STEPS = 4
FLAG_BITS = 0x7          # low size bits used as flags (ptmalloc/dlmalloc style)
START_PROBES = 4         # aligned start offsets tried per region


@dataclass(frozen=True)
class SizeChain:
    """A self-consistent run of boundary-tagged chunks in one mapping."""

    sizes: Tuple[int, ...]
    start_va: int
    size_word_offset: int   # bytes from chunk start to its size word
    tiles_region: bool      # the last chunk ends exactly at the region end

    @property
    def end_va(self) -> int:
        return self.start_va + sum(self.sizes)


def _plausible(size: int, remaining: int, align: int) -> bool:
    return size >= 2 * align and size % align == 0 and size <= remaining


def walk_chain(mem: VaMemory, region: MappedRegion, start_va: int,
               size_word_offset: int, max_steps: int) -> SizeChain:
    """Follow ``va += size_at(va + size_word_offset)`` from *start_va*."""
    align = 2 * mem.platform.pointer_size
    sizes: List[int] = []
    va = start_va
    while va < region.end and len(sizes) < max_steps:
        word = mem.ptr(va + size_word_offset)
        if word is None:
            break
        size = word & ~FLAG_BITS
        if not _plausible(size, region.end - va, align):
            break
        sizes.append(size)
        va += size
    return SizeChain(tuple(sizes), start_va, size_word_offset,
                     va == region.end and bool(sizes))


def _chain_rank(chain: SizeChain) -> Tuple[bool, int]:
    return (chain.tiles_region, len(chain.sizes))


def find_chain(mem: VaMemory, region: MappedRegion,
               max_steps: int) -> Optional[SizeChain]:
    """The best size chain of at least :data:`MIN_CHAIN_STEPS` links."""
    ptr = mem.platform.pointer_size
    align = 2 * ptr
    candidates = [walk_chain(mem, region, region.va + k * align, offset,
                             max_steps)
                  for k in range(START_PROBES) for offset in (0, ptr)]
    valid = [c for c in candidates if len(c.sizes) >= MIN_CHAIN_STEPS]
    return max(valid, key=_chain_rank, default=None)


def chain_confidence(chain: SizeChain) -> float:
    """Grows with chain length; full tiling of the region adds a bonus."""
    length_part = min(1.0, len(chain.sizes) / (4 * MIN_CHAIN_STEPS))
    score = 0.5 * length_part + (0.5 if chain.tiles_region else 0.0)
    return round(MAX_CONFIDENCE * score, 3)


def chain_chunks(chain: SizeChain, pointer_size: int) -> List[HeapChunk]:
    """One ``UNKNOWN`` chunk per link; the header ends after the size word."""
    header = chain.size_word_offset + pointer_size
    confidence = chain_confidence(chain)
    chunks, va = [], chain.start_va
    for size in chain.sizes:
        chunks.append(HeapChunk(
            va=va, size=size, state=ChunkState.UNKNOWN, header_len=header,
            user_va=va + header, user_len=size - header,
            extra={"heuristic": True}, confidence=confidence))
        va += size
    return chunks


def candidate_regions(ctx: DetectContext,
                      options: Optional[ParseOptions] = None) -> List[MappedRegion]:
    """Captured, writable, non-module mappings (honours a region filter)."""
    regions = [r for r in ctx.regions
               if r.captured and r.size > 0 and "w" in r.perms
               and not r.module_path]
    if options is not None:
        regions = [r for r in regions if options.selects(r)]
    return regions


def parse_generic(mem: VaMemory, ctx: DetectContext,
                  options: ParseOptions) -> HeapLayout:
    """Heuristic layout: boundary-tag chains found in candidate mappings."""
    chunks: List[HeapChunk] = []
    regions: List[HeapRegion] = []
    for region in candidate_regions(ctx, options):
        budget = options.max_chunks - len(chunks)
        chain = find_chain(mem, region, budget) if budget > 0 else None
        if chain is None:
            continue
        regions.append(HeapRegion(region.va, region.size, region.name,
                                  "generic_heap"))
        chunks.extend(chain_chunks(chain, mem.platform.pointer_size))
    return HeapLayout(
        allocator=AllocatorKind.GENERIC, platform=mem.platform,
        regions=tuple(regions), chunks=tuple(chunks),
        confidence=max((c.confidence for c in chunks), default=0.0),
        diagnostics=(HEURISTIC_DIAGNOSTIC,),
        coverage={"heuristic": True, "regions_with_chain": len(regions)},
    )


def probe_generic(ctx: DetectContext) -> DetectScore:
    """Content probe: any mapping holding a boundary-tag size chain."""
    for region in candidate_regions(ctx):
        chain = find_chain(ctx.memory, region, 4 * MIN_CHAIN_STEPS)
        if chain is not None:
            weight = chain_confidence(chain)
            return DetectScore(weight, [Evidence(
                "content", f"{len(chain.sizes)}-link boundary-tag size chain "
                f"at {chain.start_va:#x} (heuristic)", weight)])
    return DetectScore(0.0, [])


#: ``kind -> (parse, probe)``, the order of :class:`heap.builtin.BuiltinSpec`.
DESCRIPTOR_OVERRIDES = {AllocatorKind.GENERIC: (probe_generic, parse_generic)}

__all__ = ["HEURISTIC_DIAGNOSTIC", "MAX_CONFIDENCE", "MIN_CHAIN_STEPS",
           "SizeChain", "walk_chain", "find_chain", "chain_confidence",
           "chain_chunks", "candidate_regions", "parse_generic",
           "probe_generic", "DESCRIPTOR_OVERRIDES"]
