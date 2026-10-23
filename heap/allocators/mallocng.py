"""musl mallocng parser (musl >= 1.2.1).

Layouts follow ``src/malloc/mallocng/meta.h``::

    struct group { struct meta *meta; unsigned char active_idx:5;
                   char pad[UNIT - sizeof(struct meta *) - 1];
                   unsigned char storage[]; };
    struct meta  { struct meta *prev, *next; struct group *mem;
                   volatile int avail_mask, freed_mask;
                   uintptr_t last_idx:5, freeable:1, sizeclass:6,
                             maplen:8*sizeof(uintptr_t)-12; };
    struct meta_area { uint64_t check; struct meta_area *next; int nslots;
                       struct meta slots[]; };   /* one page each */

DISCOVERY. Every writable mapping is scanned at 16-byte alignment for a
group header whose ``meta`` pointer lands in writable memory holding a
``struct meta`` with ``meta->mem == group`` — the back-pointer check
``get_meta()`` asserts, which needs no knowledge of ``ctx.secret``. The meta
must also be internally sane (masks inside ``last_idx``, a known sizeclass,
``maplen`` covering the slots) and sit on a slot boundary of its page-aligned
``meta_area``.

SLOTS. The stride is ``UNIT * size_classes[sizeclass]`` (``get_stride()``;
single-slot mmapped groups use ``maplen*4096 - UNIT``). ``avail_mask`` slots
were never handed out (FREE, bin ``"avail"``), ``freed_mask`` slots were
freed (FREE, bin ``"freed"``), the rest are IN_USE. An IN_USE slot's in-band
header (``enframe()``: ``p[-3]&31`` = index, ``*(u16*)(p-2)`` = offset from
storage in UNITs, ``p[-3]>>5`` = reserved) is decoded to confirm it and to
recover the requested size; a slot enframed at a cycled offset (``p[-3] ==
7<<5`` at the slot start) is followed to its real user pointer.

ROLES. ``struct meta``, the ``meta_area`` header and each group header are
``ALLOCATOR_META``. The last IB bytes of a slot hold the NEXT slot's in-band
header and are painted ``CHUNK_HEADER``.

LIMITATIONS: there are no free lists in mallocng (state lives in the masks),
so no :class:`FreeList` is produced; ``ctx.active[]`` / the malloc_context
are not located; a group nested inside another group's slot replaces that
outer slot in the chunk list (chunks never overlap).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import numpy as np

from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (AllocatorKind, ChunkState, Evidence,
                                 HeapChunk, HeapLayout, HeapRegion, HeapRole)
from memdiver.heap.platform import MappedRegion
from memdiver.heap.registry import (DetectContext, DetectFn, DetectScore,
                                    ParseFn, ParseOptions)

UNIT = 16
IB = 4
_PAGE = 0x1000
_OFFSET_MARK = 7                  # p[-3] >> 5 at a slot enframed at an offset
_FREED_MARK = 0xFF                # free(): p[-3] = 255
_MMAP_SIZECLASS = 63
_MAX_MAPLEN = 1 << 20             # pages; sanity bound, not a musl limit
_BLOCK = 0x10000
_PROBE_BYTES = 0x40_0000
_PROBE_MAX_GROUPS = 8
_SKIPPED_NAMES = ("[stack", "[vvar", "[vsyscall", "[vdso")

#: ``size_classes[]`` in UNITs, from musl ``src/malloc/mallocng/malloc.c``.
SIZE_CLASSES = (
    1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 12, 15,
    18, 20, 25, 31,
    36, 42, 50, 63,
    72, 84, 102, 127,
    146, 170, 204, 255,
    292, 340, 409, 511,
    584, 682, 818, 1023,
    1169, 1364, 1637, 2047,
    2340, 2730, 3276, 4095,
    4680, 5460, 6552, 8191,
)


# -- struct decoding --------------------------------------------------------------


@dataclass(frozen=True)
class MallocngMeta:
    """One decoded ``struct meta``."""

    va: int
    prev: int
    next: int
    mem: int
    avail_mask: int
    freed_mask: int
    last_idx: int
    freeable: int
    sizeclass: int
    maplen: int

    @property
    def nslots(self) -> int:
        return self.last_idx + 1

    @property
    def stride(self) -> int:
        """``get_stride()``."""
        if self.last_idx == 0 and self.maplen:
            return self.maplen * _PAGE - UNIT
        return UNIT * SIZE_CLASSES[self.sizeclass]


def meta_size(pointer_size: int) -> int:
    """``sizeof(struct meta)``: 40 on 64-bit, 24 on 32-bit."""
    return 4 * pointer_size + 8


def meta_area_header_size(pointer_size: int) -> int:
    """``offsetof(struct meta_area, slots)``: 24 on 64-bit, 16 on 32-bit."""
    raw = 8 + pointer_size + 4
    return (raw + pointer_size - 1) & ~(pointer_size - 1)


def read_meta(memory: VaMemory, va: int) -> Optional[MallocngMeta]:
    """Decode the ``struct meta`` at *va* (``None`` if not captured)."""
    ps = memory.platform.pointer_size
    words = [memory.ptr(va + i * ps) for i in range(3)]
    masks = [memory.u32(va + 3 * ps + i * 4) for i in range(2)]
    bits = memory.ptr(va + 3 * ps + 8)
    if None in words or None in masks or bits is None:
        return None
    prev, nxt, mem = (int(w or 0) for w in words)
    return MallocngMeta(va, prev, nxt, mem, int(masks[0] or 0),
                        int(masks[1] or 0), bits & 31, (bits >> 5) & 1,
                        (bits >> 6) & 63, bits >> 12)


def _meta_is_sane(meta: MallocngMeta, pointer_size: int) -> bool:
    used = (1 << meta.nslots) - 1
    if meta.avail_mask & meta.freed_mask:
        return False
    if (meta.avail_mask | meta.freed_mask) & ~used & 0xFFFF_FFFF:
        return False
    if any(p % pointer_size for p in (meta.prev, meta.next)):
        return False
    if meta.maplen > _MAX_MAPLEN:
        return False
    if meta.sizeclass == _MMAP_SIZECLASS:
        return meta.last_idx == 0 and meta.maplen > 0
    return meta.sizeclass < len(SIZE_CLASSES)


def _maplen_covers(meta: MallocngMeta) -> bool:
    if not meta.maplen:
        return True
    return UNIT + meta.nslots * meta.stride <= meta.maplen * _PAGE


def _in_meta_area(memory: VaMemory, meta: MallocngMeta) -> bool:
    """*meta* sits on a slot boundary of its page's ``meta_area``."""
    ps = memory.platform.pointer_size
    area = meta.va & ~(_PAGE - 1)
    rel = meta.va - area - meta_area_header_size(ps)
    if rel < 0 or rel % meta_size(ps):
        return False
    nslots = memory.u32(area + 8 + ps)
    return nslots is not None and rel // meta_size(ps) < nslots


# -- groups -----------------------------------------------------------------------


@dataclass(frozen=True)
class SlotHeader:
    """A decoded in-band slot header (``enframe()``)."""

    user_va: int
    user_len: int
    offset_units: int


@dataclass(frozen=True)
class MallocngGroup:
    """A validated group and its meta."""

    va: int
    meta: MallocngMeta
    active_idx: int

    @property
    def storage(self) -> int:
        return self.va + UNIT

    @property
    def end(self) -> int:
        return self.storage + self.meta.nslots * self.meta.stride

    def slot_va(self, idx: int) -> int:
        return self.storage + idx * self.meta.stride


def validate_group(memory: VaMemory, group_va: int,
                   meta_va: int) -> Optional[MallocngGroup]:
    """A :class:`MallocngGroup` when *group_va* -> *meta_va* checks out."""
    ps = memory.platform.pointer_size
    if group_va % UNIT or meta_va % ps or not meta_va:
        return None
    meta = read_meta(memory, meta_va)
    if meta is None or meta.mem != group_va:
        return None
    if not (_meta_is_sane(meta, ps) and _maplen_covers(meta)):
        return None
    active = memory.read(group_va + ps, 1)
    if active is None or active[0] & 31 > meta.last_idx:
        return None
    if not _in_meta_area(memory, meta):
        return None
    return MallocngGroup(group_va, meta, active[0] & 31)


def _byte(memory: VaMemory, va: int) -> Optional[int]:
    data = memory.read(va, 1)
    return None if data is None else data[0]


def _user_pointer(memory: VaMemory, group: MallocngGroup, idx: int) -> Optional[int]:
    """Follow a cycled-offset slot start to its user pointer."""
    start = group.slot_va(idx)
    mark = _byte(memory, start - 3)
    if mark is None:
        return None
    if mark >> 5 != _OFFSET_MARK:
        return start
    off = memory.u16(start - 2)
    if off is None or not 0 < off * UNIT < group.meta.stride - IB:
        return None
    return start + off * UNIT


def _stored_offset(memory: VaMemory, p: int) -> Optional[int]:
    """``get_meta()``'s offset: u16 at p-2, or u32 at p-8 when p[-4] != 0."""
    big = _byte(memory, p - 4)
    if big is None:
        return None
    return memory.u32(p - 8) if big else memory.u16(p - 2)


def _reserved(memory: VaMemory, hdr: int, end: int) -> Optional[int]:
    reserved = hdr >> 5
    return memory.u32(end - 4) if reserved >= 5 else reserved


def decode_slot_header(memory: VaMemory, group: MallocngGroup,
                       idx: int) -> Optional[SlotHeader]:
    """The confirmed in-band header of IN_USE slot *idx*, else ``None``."""
    p = _user_pointer(memory, group, idx)
    if p is None:
        return None
    hdr = _byte(memory, p - 3)
    offset = _stored_offset(memory, p)
    if hdr is None or hdr & 31 != idx or offset != (p - group.storage) // UNIT:
        return None
    end = group.slot_va(idx) + group.meta.stride - IB
    reserved = _reserved(memory, hdr, end)
    if reserved is None or not 0 <= reserved <= end - p:
        return None
    return SlotHeader(p, end - reserved - p, offset)


# -- chunks -----------------------------------------------------------------------


def _slot_state(meta: MallocngMeta, idx: int) -> Tuple[ChunkState, Optional[str]]:
    if meta.avail_mask >> idx & 1:
        return ChunkState.FREE, "avail"
    if meta.freed_mask >> idx & 1:
        return ChunkState.FREE, "freed"
    return ChunkState.IN_USE, None


def _slot_extra(group: MallocngGroup, idx: int) -> Dict[str, Any]:
    return {"sizeclass": group.meta.sizeclass, "slot_idx": idx,
            "meta_va": group.meta.va, "group_va": group.va}


def _trailing_header_role(group: MallocngGroup, idx: int
                          ) -> Optional[Tuple[Tuple[int, int, HeapRole], ...]]:
    if idx >= group.meta.last_idx:
        return None
    return ((group.meta.stride - IB, IB, HeapRole.CHUNK_HEADER),)


def slot_chunk(memory: VaMemory, group: MallocngGroup, idx: int) -> HeapChunk:
    """One slot of *group* as a :class:`HeapChunk`."""
    start, stride = group.slot_va(idx), group.meta.stride
    state, label = _slot_state(group.meta, idx)
    extra = _slot_extra(group, idx)
    user_va, user_len, confidence = start, stride - IB, 1.0
    if state is ChunkState.IN_USE:
        header = decode_slot_header(memory, group, idx)
        extra["header_ok"] = header is not None
        if header is None:
            confidence = 0.5
        else:
            user_va, user_len = header.user_va, header.user_len
    return HeapChunk(va=start, size=stride, state=state,
                     header_len=user_va - start, user_va=user_va,
                     user_len=user_len, bin=label, extra=extra,
                     confidence=confidence,
                     roles=_trailing_header_role(group, idx))


def _meta_chunk(va: int, size: int, label: str, **extra: Any) -> HeapChunk:
    return HeapChunk(va=va, size=size, state=ChunkState.IN_USE, header_len=0,
                     user_va=va, user_len=size, bin=label,
                     extra={"meta": True, **extra})


def group_header_chunk(group: MallocngGroup) -> HeapChunk:
    return _meta_chunk(group.va, UNIT, "group", meta_va=group.meta.va,
                       sizeclass=group.meta.sizeclass,
                       active_idx=group.active_idx)


def meta_chunk(group: MallocngGroup, pointer_size: int) -> HeapChunk:
    return _meta_chunk(group.meta.va, meta_size(pointer_size), "meta",
                       group_va=group.va, sizeclass=group.meta.sizeclass,
                       last_idx=group.meta.last_idx,
                       freeable=group.meta.freeable,
                       maplen=group.meta.maplen)


def meta_area_chunk(memory: VaMemory, area_va: int) -> HeapChunk:
    ps = memory.platform.pointer_size
    return _meta_chunk(area_va, meta_area_header_size(ps), "meta_area",
                       check=memory.u64(area_va), next=memory.ptr(area_va + 8),
                       nslots=memory.u32(area_va + 8 + ps))


def group_confidence(chunks: List[HeapChunk]) -> float:
    """Share of IN_USE slots whose in-band header confirmed (1.0 if none)."""
    checked = [c for c in chunks if "header_ok" in c.extra]
    if not checked:
        return 1.0
    return sum(1 for c in checked if c.extra["header_ok"]) / len(checked)


# -- scanning ---------------------------------------------------------------------


def _scannable(region: MappedRegion) -> bool:
    return (region.captured and "w" in region.perms
            and not region.name.startswith(_SKIPPED_NAMES))


class _TargetIndex:
    """Vectorised "does this word point into a writable mapping?"."""

    def __init__(self, regions: List[MappedRegion]):
        spans = sorted((r.va, r.end) for r in regions)
        self._starts = np.array([s for s, _e in spans], dtype=np.uint64)
        self._ends = np.array([e for _s, e in spans], dtype=np.uint64)

    def contains(self, words: np.ndarray) -> np.ndarray:
        if not len(self._starts):
            return np.zeros(len(words), dtype=bool)
        idx = np.searchsorted(self._starts, words, side="right") - 1
        safe = np.clip(idx, 0, None)
        return (idx >= 0) & (words < self._ends[safe])


def _iter_blocks(memory: VaMemory, region: MappedRegion
                 ) -> Iterator[Tuple[int, bytes]]:
    """``(va, bytes)`` of captured blocks of *region*, skipping holes."""
    for va in range(region.va, region.end, _BLOCK):
        size = min(_BLOCK, region.end - va)
        data = memory.read(va, size)
        if data is not None:
            yield va, data
            continue
        for page in range(va, va + size, _PAGE):
            chunk = memory.read(page, min(_PAGE, va + size - page))
            if chunk is not None:
                yield page, chunk


def _candidate_pairs(memory: VaMemory, block_va: int, data: bytes,
                     targets: _TargetIndex) -> Iterator[Tuple[int, int]]:
    """``(group_va, meta_va)`` where a UNIT-aligned word hits *targets*."""
    ps = memory.platform.pointer_size
    order = "<" if memory.platform.endianness == "little" else ">"
    usable = len(data) - len(data) % UNIT
    if block_va % UNIT or usable == 0:
        return
    words = np.frombuffer(data[:usable], dtype=f"{order}u{ps}")[::UNIT // ps]
    words = words.astype(np.uint64)
    mask = (words != 0) & (words % ps == 0) & targets.contains(words)
    for slot in np.flatnonzero(mask):
        yield block_va + int(slot) * UNIT, int(words[slot])


def find_groups(memory: VaMemory, regions: List[MappedRegion],
                targets: List[MappedRegion], *, byte_budget: Optional[int] = None,
                max_groups: Optional[int] = None) -> Tuple[List[MallocngGroup], int]:
    """Validated groups in *regions* (meta pointers into *targets*)."""
    index = _TargetIndex(targets)
    groups: List[MallocngGroup] = []
    scanned = 0
    for region in regions:
        for block_va, data in _iter_blocks(memory, region):
            if byte_budget is not None and scanned >= byte_budget:
                return groups, scanned
            scanned += len(data)
            for group_va, meta_va in _candidate_pairs(memory, block_va, data, index):
                group = validate_group(memory, group_va, meta_va)
                if group is not None:
                    groups.append(group)
                if max_groups is not None and len(groups) >= max_groups:
                    return groups, scanned
    return groups, scanned


def _writable_regions(ctx: DetectContext) -> List[MappedRegion]:
    return [r for r in ctx.regions if _scannable(r)]


# -- probe ------------------------------------------------------------------------


def probe_mallocng(ctx: DetectContext) -> DetectScore:
    """Content probe: validated groups within a bounded scan."""
    writable = _writable_regions(ctx)
    groups, _scanned = find_groups(ctx.memory, writable, writable,
                                   byte_budget=_PROBE_BYTES,
                                   max_groups=_PROBE_MAX_GROUPS)
    return _probe_score(ctx.memory, groups)


def _probe_score(memory: VaMemory, groups: List[MallocngGroup]) -> DetectScore:
    confirmed = [g for g in groups if _group_confirmed(memory, g)]
    if not confirmed:
        return DetectScore(0.0, [])
    score = min(0.95, 0.6 + 0.1 * (len(confirmed) - 1))
    detail = (f"{len(confirmed)} mallocng group(s) with meta->mem back-pointer "
              "and confirmed in-band slot headers")
    return DetectScore(score, [Evidence("content", detail, score)])


def _group_confirmed(memory: VaMemory, group: MallocngGroup) -> bool:
    """At least one IN_USE slot decodes, or the group has none in use."""
    meta = group.meta
    busy = [i for i in range(meta.nslots)
            if not (meta.avail_mask | meta.freed_mask) >> i & 1]
    if not busy:
        return True
    return any(decode_slot_header(memory, group, i) for i in busy)


# -- parse ------------------------------------------------------------------------


class _Builder:
    """Accumulates chunks/regions under the ``max_chunks`` cap."""

    def __init__(self, memory: VaMemory, ctx: DetectContext, opts: ParseOptions):
        self.memory, self.ctx, self.opts = memory, ctx, opts
        self.chunks: List[HeapChunk] = []
        self.regions: List[HeapRegion] = []
        self.areas: Set[int] = set()
        self.confidences: List[float] = []
        self.truncated = False

    def _room(self, count: int = 1) -> bool:
        if len(self.chunks) + count > self.opts.max_chunks:
            self.truncated = True
        return not self.truncated

    def _push(self, chunk: HeapChunk) -> None:
        if self._room():
            self.chunks.append(chunk)

    def add_group(self, group: MallocngGroup) -> None:
        ps = self.memory.platform.pointer_size
        self._add_area(group.meta.va & ~(_PAGE - 1))
        self._push(meta_chunk(group, ps))
        self._push(group_header_chunk(group))
        slots = [slot_chunk(self.memory, group, i) for i in range(group.meta.nslots)]
        for chunk in slots:
            self._push(chunk)
        self.confidences.append(group_confidence(slots))
        self.regions.append(HeapRegion(group.va, group.end - group.va,
                                       self._name(group.va), "mallocng_group"))

    def _add_area(self, area_va: int) -> None:
        if area_va in self.areas:
            return
        self.areas.add(area_va)
        self._push(meta_area_chunk(self.memory, area_va))
        self.regions.append(HeapRegion(area_va, _PAGE, self._name(area_va),
                                       "mallocng_meta_area"))

    def _name(self, va: int) -> str:
        for region in self.ctx.regions:
            if region.va <= va < region.end:
                return region.name
        return ""


def drop_containers(chunks: List[HeapChunk]) -> List[HeapChunk]:
    """Remove chunks that overlap a later-starting one (nested groups)."""
    ordered = sorted(chunks, key=lambda c: (c.va, -c.size))
    kept = [c for c, nxt in zip(ordered, ordered[1:]) if nxt.va >= c.end]
    return kept + ordered[-1:]


def parse_mallocng(memory: VaMemory, ctx: DetectContext,
                   opts: ParseOptions) -> HeapLayout:
    """Find every validated group and report its slots, meta and headers."""
    writable = _writable_regions(ctx)
    scan = [r for r in writable if opts.selects(r)]
    groups, scanned = find_groups(memory, scan, writable)
    builder = _Builder(memory, ctx, opts)
    for group in sorted(groups, key=lambda g: g.va):
        builder.add_group(group)
    return _layout(memory, builder, groups, scanned, len(scan))


def _layout(memory: VaMemory, builder: _Builder, groups: List[MallocngGroup],
            scanned: int, region_count: int) -> HeapLayout:
    chunks = drop_containers(builder.chunks)
    diagnostics = []
    if builder.truncated:
        diagnostics.append(f"max_chunks={builder.opts.max_chunks} reached; "
                           "chunk list truncated")
    if len(chunks) < len(builder.chunks):
        diagnostics.append(f"{len(builder.chunks) - len(chunks)} outer slot(s) "
                           "replaced by nested groups")
    confidence = (sum(builder.confidences) / len(builder.confidences)
                  if builder.confidences else 0.0)
    return HeapLayout(
        allocator=AllocatorKind.MALLOCNG, platform=memory.platform,
        regions=tuple(builder.regions), chunks=tuple(chunks),
        evidence=tuple(_probe_score(memory, groups[:_PROBE_MAX_GROUPS]).evidence),
        confidence=confidence, diagnostics=tuple(diagnostics),
        coverage={"groups": len(groups), "meta_areas": len(builder.areas),
                  "regions_scanned": region_count, "bytes_scanned": scanned,
                  "truncated": builder.truncated})


DESCRIPTOR_OVERRIDES: Dict[AllocatorKind, Tuple[DetectFn, ParseFn]] = {
    AllocatorKind.MALLOCNG: (probe_mallocng, parse_mallocng),
}

__all__ = ["SIZE_CLASSES", "MallocngMeta", "MallocngGroup", "SlotHeader",
           "read_meta", "validate_group", "decode_slot_header", "slot_chunk",
           "find_groups", "probe_mallocng", "parse_mallocng",
           "DESCRIPTOR_OVERRIDES"]
