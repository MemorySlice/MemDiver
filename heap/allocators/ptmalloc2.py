"""glibc ptmalloc2 and Doug Lea dlmalloc boundary-tag heap parsers.

Both allocators lay chunks out back to back, each behind a two-word header
``{prev_size, size}`` whose low three bits are flags. The walker reads the
size word, masks the flags (``size & ~7``) and steps to the next chunk; the
alignment is ``2 * SIZE_SZ`` (16 on 64-bit, 8 on 32-bit — an i386 glibc
built with ``MALLOC_ALIGNMENT == 16`` is not handled).

ptmalloc2 (levels L0-L3):

* flags are PREV_INUSE (1), IS_MMAPPED (2, never set inside a heap) and
  NON_MAIN_ARENA (4); a chunk is free when its successor's PREV_INUSE is
  clear, the last chunk of the heap is ``top``;
* the first chunk is ``tcache_perthread_struct`` (ALLOCATOR_META); its size
  gives the version hint (0x290: ``uint16_t counts`` glibc >= 2.30, 0x250:
  ``char counts`` 2.26-2.29). Its bins are walked with plain and with
  safe-linked (``(pos >> 12) ^ ptr``, glibc >= 2.32) ``next`` pointers and
  the decoding that forms in-heap chains wins. Tcache'd chunks are CACHED
  with ``next``/``key`` marked FREE_LINK;
* ``main_arena`` is located by scanning glibc's writable mapping for a
  word equal to the walked top chunk whose surrounding ``bins[]`` are all
  self-linked or point into the heap. When found, fastbins (CACHED, ``fd``
  FREE_LINK) and the unsorted / small / large bins are walked.

dlmalloc (levels L0-L2): the same walker; bit 2 is CINUSE so a chunk's own
head says whether it is in use. Free chunks are labelled ``smallbin`` /
``treebin`` by size; ``malloc_state`` is not decoded.

Corrupt headers are skipped by resyncing to the next aligned header whose
successor is also plausible (a diagnostic names the address); pages the
dump never captured are skipped the same way and counted in ``coverage``.

Limitations: only the regions named like the main heap (``[heap]``; for
dlmalloc also ``[anon:libc_malloc]``) are walked unless
:attr:`ParseOptions.regions` selects others. Non-main arenas (``heap_info``
at 64 MiB-aligned anonymous maps) and their ``malloc_state`` are not
decoded, mmapped chunks are not enumerated, and ``main_arena`` is not found
in statically linked binaries (no glibc module mapping). Each of these
produces a diagnostic instead of a guess.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (AllocatorKind, ChunkState, Evidence, FreeList,
                                 HeapChunk, HeapLayout, HeapRegion, HeapRole)
from memdiver.heap.platform import MappedRegion, TargetPlatform
from memdiver.heap.registry import (DetectContext, DetectScore, ParseOptions,
                                    name_matches)

_PREV_INUSE = 0x1
_IS_MMAPPED = 0x2        # dlmalloc: CINUSE_BIT
_NON_MAIN_ARENA = 0x4
_FLAG_BITS = 0x7
_TCACHE_BINS = 64
_NBINS = 128
_FIRST_LARGE_BIN = 64
_DL_MIN_LARGE_SIZE = 0x100
_PAGE = 0x1000
_PROBE_HEADERS = 32
_PROBE_REGIONS = 4
_MAX_LIST_LEN = 4096
_MAX_ARENA_SCAN = 8 << 20
_CACHE_PAGES = 256
_GLIBC_MODULES = ("libc.so.6", "libc-2.*.so", "libc.so")

_Roles = Tuple[Tuple[int, int, HeapRole], ...]


# -- geometry & flavours ----------------------------------------------------------


@dataclass(frozen=True)
class _Geometry:
    """Word size, endianness and the alignment derived from them."""

    ptr: int
    endian: str

    @property
    def align(self) -> int:
        return 2 * self.ptr

    @property
    def header(self) -> int:
        return 2 * self.ptr

    @property
    def min_chunk(self) -> int:
        return 4 * self.ptr

    def align_up(self, va: int) -> int:
        return (va + self.align - 1) & ~(self.align - 1)

    def pack(self, value: int) -> bytes:
        return value.to_bytes(self.ptr, "big" if self.endian == "big" else "little")


def _geometry(platform: TargetPlatform) -> _Geometry:
    return _Geometry(platform.pointer_size, platform.endianness)


@dataclass(frozen=True)
class _Flavor:
    kind: AllocatorKind
    region_patterns: Tuple[str, ...]
    dlmalloc: bool


_PTMALLOC2 = _Flavor(AllocatorKind.PTMALLOC2, ("[heap]",), False)
_DLMALLOC = _Flavor(AllocatorKind.DLMALLOC,
                    ("[heap]", "[anon:libc_malloc]", "*dlmalloc*"), True)


# -- paged reads --------------------------------------------------------------------


class _PagedReader:
    """Word reads by VA through a small LRU cache of page-sized reads."""

    def __init__(self, memory: VaMemory, geo: _Geometry):
        self._memory = memory
        self._geo = geo
        self._pages: "OrderedDict[int, Optional[bytes]]" = OrderedDict()

    def read(self, va: int, n: int) -> Optional[bytes]:
        page_va = va & ~(_PAGE - 1)
        page = self._page(page_va) if va + n <= page_va + _PAGE else None
        if page is None:
            return self._memory.read(va, n)
        return page[va - page_va:va - page_va + n]

    def _page(self, page_va: int) -> Optional[bytes]:
        if page_va in self._pages:
            self._pages.move_to_end(page_va)
            return self._pages[page_va]
        data = self._memory.read(page_va, _PAGE)
        self._pages[page_va] = data
        if len(self._pages) > _CACHE_PAGES:
            self._pages.popitem(last=False)
        return data

    def uint(self, va: int, width: int) -> Optional[int]:
        data = self.read(va, width)
        if data is None:
            return None
        return int.from_bytes(data, "big" if self._geo.endian == "big" else "little")

    def word(self, va: int) -> Optional[int]:
        return self.uint(va, self._geo.ptr)


# -- boundary-tag walk --------------------------------------------------------------


@dataclass(frozen=True)
class _Raw:
    """One walked chunk header. ``after_gap``: a resync/hole precedes it."""

    va: int
    size: int
    flags: int
    after_gap: bool
    region_end: int

    @property
    def end(self) -> int:
        return self.va + self.size


@dataclass
class _Walk:
    raws: List[_Raw] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    skipped: int = 0
    uncaptured: int = 0
    truncated: bool = False


def _plausible(word: int, va: int, end: int, geo: _Geometry, flavor: _Flavor) -> bool:
    size = word & ~_FLAG_BITS
    if size < geo.min_chunk or size % geo.align or va + size > end:
        return False
    return flavor.dlmalloc or not word & _IS_MMAPPED


def _header_word(reader: _PagedReader, va: int, end: int, geo: _Geometry,
                 flavor: _Flavor) -> Optional[int]:
    """The size word at *va* when it forms a plausible header, else ``None``."""
    word = reader.word(va + geo.ptr)
    if word is None or not _plausible(word, va, end, geo, flavor):
        return None
    return word


def _resync(reader: _PagedReader, start: int, end: int, geo: _Geometry,
            flavor: _Flavor) -> int:
    """First aligned VA >= *start* whose header and successor are plausible."""
    va = geo.align_up(start)
    while va + geo.header <= end:
        word = _header_word(reader, va, end, geo, flavor)
        if word is not None:
            nxt = va + (word & ~_FLAG_BITS)
            if nxt == end or _header_word(reader, nxt, end, geo, flavor) is not None:
                return va
        va += geo.align
    return end


def _walk_region(reader: _PagedReader, region: MappedRegion, geo: _Geometry,
                 flavor: _Flavor, budget: int, walk: _Walk) -> None:
    va, end, gap = geo.align_up(region.va), region.end, False
    while va + geo.header <= end:
        if len(walk.raws) >= budget:
            walk.truncated = True
            return
        word = reader.word(va + geo.ptr)
        if word is not None and _plausible(word, va, end, geo, flavor):
            walk.raws.append(_Raw(va, word & ~_FLAG_BITS, word & _FLAG_BITS, gap, end))
            va, gap = va + (word & ~_FLAG_BITS), False
            continue
        va, gap = _skip_bad_header(reader, va, word, end, geo, flavor, walk), True


def _skip_bad_header(reader: _PagedReader, va: int, word: Optional[int], end: int,
                     geo: _Geometry, flavor: _Flavor, walk: _Walk) -> int:
    """Record why *va* is unusable and return where the walk resumes."""
    if word is None:
        hole_end = min((va & ~(_PAGE - 1)) + _PAGE, end)
        walk.uncaptured += hole_end - va
        resume = _resync(reader, hole_end, end, geo, flavor)
        walk.skipped += resume - hole_end
        return resume
    walk.diagnostics.append(
        f"implausible chunk header at {va:#x} (size word {word:#x}); resyncing")
    resume = _resync(reader, va + geo.align, end, geo, flavor)
    walk.skipped += resume - va
    if resume < end:
        walk.diagnostics.append(f"resynced at {resume:#x}")
    return resume


# -- chunk classification -------------------------------------------------------------


@dataclass
class _Slot:
    """A walked chunk plus the state/bin/roles the overlays assign to it."""

    raw: _Raw
    state: ChunkState
    bin: Optional[str] = None
    roles: Optional[_Roles] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def reserved(self) -> bool:
        """Top chunk or allocator metadata: never a free-list member."""
        return self.bin == "top" or bool(self.extra.get("meta"))


def _link_roles(geo: _Geometry, words: int) -> _Roles:
    return tuple((geo.header + i * geo.ptr, geo.ptr, HeapRole.FREE_LINK)
                 for i in range(words))


def _successor(raws: Sequence[_Raw], idx: int) -> Optional[_Raw]:
    if idx + 1 >= len(raws):
        return None
    nxt = raws[idx + 1]
    return nxt if nxt.va == raws[idx].end and not nxt.after_gap else None


def _base_state(raw: _Raw, nxt: Optional[_Raw], flavor: _Flavor) -> ChunkState:
    if flavor.dlmalloc:
        return ChunkState.IN_USE if raw.flags & _IS_MMAPPED else ChunkState.FREE
    if nxt is None:
        return ChunkState.UNKNOWN
    return ChunkState.IN_USE if nxt.flags & _PREV_INUSE else ChunkState.FREE


def _is_top(raw: _Raw, flavor: _Flavor) -> bool:
    if raw.end != raw.region_end:
        return False
    return not (flavor.dlmalloc and raw.flags & _IS_MMAPPED)


def _initial_slot(raws: Sequence[_Raw], idx: int, geo: _Geometry,
                  flavor: _Flavor) -> _Slot:
    raw = raws[idx]
    if _is_top(raw, flavor):
        return _Slot(raw, ChunkState.FREE, "top")
    slot = _Slot(raw, _base_state(raw, _successor(raws, idx), flavor))
    if slot.state is ChunkState.FREE:
        slot.roles = _link_roles(geo, 2)
        if flavor.dlmalloc:
            slot.bin = "smallbin" if raw.size < _DL_MIN_LARGE_SIZE else "treebin"
    return slot


class _Heap:
    """Walked slots indexed by chunk VA, plus the heap regions' extents."""

    def __init__(self, slots: List[_Slot], regions: Sequence[MappedRegion]):
        self.slots = slots
        self.by_va = {slot.raw.va: slot for slot in slots}
        self._extents = [(r.va, r.end) for r in regions]

    def free_candidate(self, chunk_va: int) -> Optional[int]:
        slot = self.by_va.get(chunk_va)
        return chunk_va if slot is not None and not slot.reserved else None

    def contains(self, va: int) -> bool:
        return any(lo <= va < hi for lo, hi in self._extents)

    def top(self) -> Optional[_Slot]:
        return next((s for s in self.slots if s.bin == "top"), None)


# -- free-list walks ------------------------------------------------------------------


@dataclass(frozen=True)
class _Chain:
    nodes: Tuple[int, ...]
    cycle: bool = False
    broken: bool = False


def _reveal(pos: int, stored: int) -> int:
    """glibc >= 2.32 ``REVEAL_PTR``: ``(pos >> 12) ^ stored``."""
    return (pos >> 12) ^ stored


def _walk_singly(reader: _PagedReader, first: int, link_offset: int, safe: bool,
                 to_chunk: Callable[[int], Optional[int]]) -> _Chain:
    """Follow a NULL-terminated list whose link sits at ``node + link_offset``."""
    nodes: List[int] = []
    node = first
    while node:
        chunk_va = to_chunk(node)
        if chunk_va is None or len(nodes) >= _MAX_LIST_LEN:
            return _Chain(tuple(nodes), broken=True)
        if chunk_va in nodes:
            return _Chain(tuple(nodes), cycle=True)
        nodes.append(chunk_va)
        stored = reader.word(node + link_offset)
        if stored is None:
            return _Chain(tuple(nodes), broken=True)
        node = _reveal(node + link_offset, stored) if safe else stored
    return _Chain(tuple(nodes))


def _walk_double(reader: _PagedReader, header_va: int, geo: _Geometry,
                 to_chunk: Callable[[int], Optional[int]]) -> _Chain:
    """Follow ``fd`` from a circular bin header back to itself."""
    nodes: List[int] = []
    node = reader.word(header_va + geo.header)
    while node is not None and node != header_va:
        if to_chunk(node) is None or len(nodes) >= _MAX_LIST_LEN:
            return _Chain(tuple(nodes), broken=True)
        if node in nodes:
            return _Chain(tuple(nodes), cycle=True)
        nodes.append(node)
        node = reader.word(node + geo.header)
    return _Chain(tuple(nodes), broken=node is None)


def _chains_badness(chains: Sequence[_Chain]) -> Tuple[int, int]:
    return (sum(c.broken or c.cycle for c in chains), -sum(len(c.nodes) for c in chains))


def _pick_decoding(walk: Callable[[bool], List[_Chain]],
                   hint: Optional[bool]) -> Tuple[Optional[bool], List[_Chain]]:
    """Decode plain and safe-linked; keep whichever forms in-heap chains.

    Returns ``(safe, chains)``; ``safe`` is ``None`` when neither wins.
    """
    if hint is not None:
        return hint, walk(hint)
    plain, safe = walk(False), walk(True)
    if _chains_badness(safe) < _chains_badness(plain):
        return True, safe
    if _chains_badness(plain) < _chains_badness(safe):
        return False, plain
    return None, plain


@dataclass
class _Lists:
    """Free lists found so far, their diagnostics and the safe-linking verdict."""

    free_lists: List[FreeList] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    safe: Optional[bool] = None


def _record(lists: _Lists, kind: str, index: int, head_va: int, chain: _Chain,
            decoded: bool) -> None:
    lists.free_lists.append(FreeList(kind, index, head_va, chain.nodes, decoded,
                                     chain.cycle))
    if chain.cycle:
        lists.diagnostics.append(f"{kind}[{index}] contains a cycle")
    elif chain.broken:
        lists.diagnostics.append(
            f"{kind}[{index}] ends at an invalid or uncaptured pointer "
            f"after {len(chain.nodes)} chunk(s)")


def _mark(heap: _Heap, chain: _Chain, state: ChunkState, label: str,
          roles: _Roles) -> None:
    for chunk_va in chain.nodes:
        slot = heap.by_va[chunk_va]
        slot.state, slot.bin, slot.roles = state, label, roles


# -- tcache ---------------------------------------------------------------------------


def _tcache_struct_sizes(geo: _Geometry) -> Dict[int, int]:
    """Chunk size of ``tcache_perthread_struct`` -> width of ``counts[]``."""
    sizes: Dict[int, int] = {}
    for width in (2, 1):
        request = width * _TCACHE_BINS + geo.ptr * _TCACHE_BINS
        sizes[(request + geo.ptr + geo.align - 1) & ~(geo.align - 1)] = width
    return sizes


_VERSION_BY_WIDTH = {2: "glibc>=2.30", 1: "glibc 2.26-2.29"}


def _mark_tcache_struct(heap: _Heap, geo: _Geometry) -> Optional[_Slot]:
    """Flag the heap's first chunk as ``tcache_perthread_struct`` when it fits."""
    if not heap.slots:
        return None
    first = heap.slots[0]
    width = _tcache_struct_sizes(geo).get(first.raw.size)
    if width is None or first.bin == "top":
        return None
    first.state, first.bin, first.roles = (ChunkState.IN_USE,
                                           "tcache_perthread_struct", None)
    first.extra = {"meta": True, "struct": "tcache_perthread_struct",
                   "counts_width": width}
    return first


def _tcache_heads(reader: _PagedReader, struct_slot: _Slot,
                  geo: _Geometry) -> Iterator[Tuple[int, int, int, int]]:
    """``(index, count, entry_slot_va, head)`` for every non-empty bin."""
    width = struct_slot.extra["counts_width"]
    counts_va = struct_slot.raw.va + geo.header
    entries_va = counts_va + width * _TCACHE_BINS
    for idx in range(_TCACHE_BINS):
        head = reader.word(entries_va + idx * geo.ptr)
        if head:
            count = reader.uint(counts_va + idx * width, width) or 0
            yield idx, count, entries_va + idx * geo.ptr, head


def _decode_tcache(reader: _PagedReader, heap: _Heap, struct_slot: _Slot,
                   geo: _Geometry, lists: _Lists) -> None:
    heads = list(_tcache_heads(reader, struct_slot, geo))

    def user_to_chunk(mem: int) -> Optional[int]:
        return heap.free_candidate(mem - geo.header) if mem % geo.align == 0 else None

    def walk(safe: bool) -> List[_Chain]:
        return [_walk_singly(reader, head, 0, safe, user_to_chunk)
                for _i, _c, _s, head in heads]

    lists.safe, chains = _pick_decoding(walk, None)
    for (idx, count, slot_va, _head), chain in zip(heads, chains):
        _record(lists, "tcache", idx, slot_va, chain, bool(lists.safe))
        _mark(heap, chain, ChunkState.CACHED, f"tcache[{idx}]", _link_roles(geo, 2))
        if count != len(chain.nodes):
            lists.diagnostics.append(
                f"tcache[{idx}] count {count} != walked length {len(chain.nodes)}")


def _version_hint(struct_slot: Optional[_Slot], safe: Optional[bool]) -> str:
    if struct_slot is None:
        return "glibc<2.26 or tcache disabled"
    width = struct_slot.extra["counts_width"]
    if width == 2 and safe is True:
        return "glibc>=2.32"
    if width == 2 and safe is False:
        return "glibc 2.30-2.31"
    return _VERSION_BY_WIDTH[width]


# -- main_arena -----------------------------------------------------------------------


def _libc_data_regions(regions: Sequence[MappedRegion]) -> List[MappedRegion]:
    return [r for r in regions
            if "w" in r.perms and r.captured and r.size <= _MAX_ARENA_SCAN
            and r.module_path
            and any(fnmatch(os.path.basename(r.module_path), p) for p in _GLIBC_MODULES)]


def _aligned_hits(data: bytes, needle: bytes, step: int) -> Iterator[int]:
    pos = data.find(needle)
    while pos >= 0:
        if pos % step == 0:
            yield pos
        pos = data.find(needle, pos + 1)


def _bins_consistent(reader: _PagedReader, top_slot_va: int, geo: _Geometry,
                     heap: _Heap) -> bool:
    """Every ``bins[]`` pair is self-linked (empty) or points into the heap."""
    words = [reader.word(top_slot_va + (2 + i) * geo.ptr) for i in range(2 * _NBINS - 2)]
    empty = 0
    for pair in range(_NBINS - 1):
        header_va = top_slot_va + 2 * pair * geo.ptr
        fd, bk = words[2 * pair], words[2 * pair + 1]
        if fd is None or bk is None:
            return False
        if fd == bk == header_va:
            empty += 1
        elif not (heap.contains(fd) and heap.contains(bk)):
            return False
    return empty > 0


def _find_main_arena(memory: VaMemory, reader: _PagedReader, regions: Sequence[MappedRegion],
                     geo: _Geometry, heap: _Heap, top_va: int) -> Optional[int]:
    """VA of ``main_arena.top`` inside glibc's writable data, or ``None``."""
    needle = geo.pack(top_va)
    for region in _libc_data_regions(regions):
        data = memory.read(region.va, region.size)
        if data is None:
            continue
        for offset in _aligned_hits(data, needle, geo.ptr):
            if _bins_consistent(reader, region.va + offset, geo, heap):
                return region.va + offset
    return None


def _nfastbins(geo: _Geometry) -> int:
    """``NFASTBINS = fastbin_index(request2size(MAX_FAST_SIZE)) + 1``."""
    max_fast = 80 * geo.ptr // 4
    request = max(geo.min_chunk, (max_fast + geo.ptr + geo.align - 1) & ~(geo.align - 1))
    return (request >> (4 if geo.ptr == 8 else 3)) - 2 + 1


def _decode_fastbins(reader: _PagedReader, heap: _Heap, top_slot_va: int,
                     geo: _Geometry, lists: _Lists) -> None:
    base = top_slot_va - _nfastbins(geo) * geo.ptr
    heads = [(i, base + i * geo.ptr, reader.word(base + i * geo.ptr))
             for i in range(_nfastbins(geo))]
    present = [(i, slot_va, head) for i, slot_va, head in heads if head]

    def walk(safe: bool) -> List[_Chain]:
        return [_walk_singly(reader, head, geo.header, safe, heap.free_candidate)
                for _i, _s, head in present]

    safe, chains = _pick_decoding(walk, lists.safe)
    for (idx, slot_va, _head), chain in zip(present, chains):
        _record(lists, "fastbin", idx, slot_va, chain, bool(safe))
        _mark(heap, chain, ChunkState.CACHED, f"fastbin[{idx}]", _link_roles(geo, 1))


def _bin_label(index: int) -> Tuple[str, str, int]:
    """``(kind, label, link words)`` of ``bin_at(index)``."""
    if index == 1:
        return "unsorted", "unsorted", 2
    if index < _FIRST_LARGE_BIN:
        return "smallbin", f"smallbin[{index}]", 2
    return "largebin", f"largebin[{index}]", 4


def _decode_bins(reader: _PagedReader, heap: _Heap, top_slot_va: int,
                 geo: _Geometry, lists: _Lists) -> None:
    for index in range(1, _NBINS - 1):
        header_va = top_slot_va + 2 * (index - 1) * geo.ptr
        chain = _walk_double(reader, header_va, geo, heap.free_candidate)
        if not chain.nodes and not chain.broken:
            continue
        kind, label, words = _bin_label(index)
        _record(lists, kind, index, header_va, chain, False)
        _mark(heap, chain, ChunkState.FREE, label, _link_roles(geo, words))


def _decode_arena(memory: VaMemory, reader: _PagedReader, ctx: DetectContext,
                  heap: _Heap, geo: _Geometry, lists: _Lists) -> Optional[int]:
    top = heap.top()
    arena_top = (None if top is None else
                 _find_main_arena(memory, reader, ctx.regions, geo, heap, top.raw.va))
    if arena_top is None:
        lists.diagnostics.append(
            "main_arena not found (no captured glibc data mapping referencing the "
            "top chunk): fastbin/unsorted/small/large bins not decoded, fastbin "
            "chunks appear in use")
        return None
    _decode_fastbins(reader, heap, arena_top, geo, lists)
    _decode_bins(reader, heap, arena_top, geo, lists)
    return arena_top


# -- region selection ----------------------------------------------------------------


def _target_regions(ctx: DetectContext, flavor: _Flavor,
                    opts: Optional[ParseOptions]) -> List[MappedRegion]:
    regions = [r for r in ctx.regions if r.captured and r.size > 0]
    if opts is not None and opts.regions is not None:
        return [r for r in regions if opts.selects(r)]
    named = [r for r in regions
             if any(name_matches(r.name, p) for p in flavor.region_patterns)]
    if named or flavor.dlmalloc:
        return named
    return _nameless_main_heap(ctx, regions, flavor)


#: A candidate heap must score at least this on the boundary-tag probe.
_NAMELESS_MIN_PROBE_SCORE = 0.5


def _nameless_main_heap(ctx: DetectContext, regions: Sequence[MappedRegion],
                        flavor: _Flavor) -> List[MappedRegion]:
    """The brk heap of a dump whose map lost the ``[heap]`` label.

    An imported ``.msl`` keeps the executable's and libraries' paths but not
    the pseudo-names, so ``[heap]`` is an anonymous ``rw-`` region. On Linux
    the brk heap lies above the main executable's image, but the lowest such
    region is often the executable's own ``.bss`` continuation; so the
    candidates are tried in address order (``ctx.regions`` is not assumed
    sorted) and the first whose content passes the boundary-tag probe wins.
    Only offered when glibc is mapped; the walk's own header checks still
    have to agree before anything is reported.
    """
    if not ctx.matching_modules(*_GLIBC_MODULES):
        return []
    image_end = _first_module_end(ctx.regions)
    if image_end is None:
        return []
    candidates = sorted((r for r in regions if r.va >= image_end and "w" in r.perms
                         and not r.name and not r.module_path), key=lambda r: r.va)
    geo = _geometry(ctx.platform)
    reader = _PagedReader(ctx.memory, geo)
    for region in candidates:
        if _probe_score(*_probe_region(reader, region, geo, flavor)) >= _NAMELESS_MIN_PROBE_SCORE:
            return [region]
    return []


def _first_module_end(regions: Sequence[MappedRegion]) -> Optional[int]:
    """End of the last mapping of the lowest-VA file-backed module."""
    mapped = [r for r in regions if r.module_path]
    if not mapped:
        return None
    first_path = min(mapped, key=lambda r: r.va).module_path
    return max(r.end for r in mapped if r.module_path == first_path)


# -- probe ----------------------------------------------------------------------------


def _dl_consistent(prev_word: Optional[int], word: int) -> bool:
    """dlmalloc: a free chunk (CINUSE clear) has a successor with PINUSE clear."""
    return prev_word is None or bool(prev_word & _IS_MMAPPED) or not word & _PREV_INUSE


def _probe_region(reader: _PagedReader, region: MappedRegion, geo: _Geometry,
                  flavor: _Flavor) -> Tuple[int, bool]:
    """``(plausible consecutive headers, reached the region end)``."""
    va, good, prev = geo.align_up(region.va), 0, None
    while good < _PROBE_HEADERS and va + geo.header <= region.end:
        word = _header_word(reader, va, region.end, geo, flavor)
        if word is None or (flavor.dlmalloc and not _dl_consistent(prev, word)):
            return good, False
        good, prev, va = good + 1, word, va + (word & ~_FLAG_BITS)
    return good, va == region.end


def _probe_score(good: int, complete: bool) -> float:
    if good == 0:
        return 0.0
    fraction = 1.0 if complete or good >= _PROBE_HEADERS else good / (good + 1)
    return fraction * min(1.0, good / 4)


def _probe(ctx: DetectContext, flavor: _Flavor) -> DetectScore:
    regions = _target_regions(ctx, flavor, None)[:_PROBE_REGIONS]
    if not regions:
        return DetectScore(0.0, [])
    geo = _geometry(ctx.platform)
    reader = _PagedReader(ctx.memory, geo)
    results = [(_probe_score(*_probe_region(reader, r, geo, flavor)), r) for r in regions]
    score, region = max(results, key=lambda item: item[0])
    detail = (f"{flavor.kind.value} boundary-tag walk of {region.name or hex(region.va)}"
              f" scored {score:.2f}")
    return DetectScore(score, [Evidence("content", detail, score)])


def probe_ptmalloc2(ctx: DetectContext) -> DetectScore:
    """Content probe: plausible consecutive ptmalloc2 headers in ``[heap]``."""
    return _probe(ctx, _PTMALLOC2)


def probe_dlmalloc(ctx: DetectContext) -> DetectScore:
    """Content probe: plausible, CINUSE-consistent dlmalloc headers."""
    return _probe(ctx, _DLMALLOC)


# -- parse ----------------------------------------------------------------------------


def _walk_all(reader: _PagedReader, regions: Sequence[MappedRegion], geo: _Geometry,
              flavor: _Flavor, max_chunks: int) -> _Walk:
    walk = _Walk()
    for region in regions:
        _walk_region(reader, region, geo, flavor, max_chunks, walk)
        if walk.truncated:
            walk.diagnostics.append(f"stopped after max_chunks={max_chunks} chunks")
            break
    return walk


_LINKED_STATES = (ChunkState.FREE, ChunkState.CACHED)


def _header_fields(reader: _PagedReader, slot: _Slot, geo: _Geometry) -> Dict[str, Any]:
    """Raw header words, plus the first two user words of a linked free chunk.

    ``fd``/``bk`` are stored as read (still safe-linked for tcache/fastbins);
    the decoded chain lives in the layout's free lists.
    """
    raw = slot.raw
    fields = {"prev_size": reader.word(raw.va), "size_word": reader.word(raw.va + geo.ptr)}
    if slot.state in _LINKED_STATES and slot.bin != "top":
        user_va = raw.va + geo.header
        fields["fd"] = reader.word(user_va)
        fields["bk"] = reader.word(user_va + geo.ptr)
    return {name: word for name, word in fields.items() if word is not None}


def _to_chunk(reader: _PagedReader, slot: _Slot, geo: _Geometry) -> HeapChunk:
    raw = slot.raw
    extra = {**_header_fields(reader, slot, geo), **slot.extra}
    return HeapChunk(va=raw.va, size=raw.size, state=slot.state, header_len=geo.header,
                     user_va=raw.va + geo.header, user_len=raw.size - geo.header,
                     flags=raw.flags, bin=slot.bin, extra=extra,
                     confidence=0.7 if raw.after_gap else 1.0, roles=slot.roles)


def _coverage(regions: Sequence[MappedRegion], walk: _Walk,
              arena_top: Optional[int], safe: Optional[bool]) -> Dict[str, Any]:
    return {
        "regions": [r.name or hex(r.va) for r in regions],
        "bytes_total": sum(r.size for r in regions),
        "bytes_walked": sum(raw.size for raw in walk.raws),
        "bytes_skipped": walk.skipped,
        "bytes_uncaptured": walk.uncaptured,
        "chunk_count": len(walk.raws),
        "truncated": walk.truncated,
        "main_arena_top_va": arena_top,
        "safe_linking": safe,
    }


def _ptmalloc2_overlays(memory: VaMemory, reader: _PagedReader, ctx: DetectContext,
                        heap: _Heap, geo: _Geometry,
                        lists: _Lists) -> Tuple[str, Optional[int]]:
    """Tcache + arena decoding; returns ``(version_hint, main_arena top VA)``."""
    struct_slot = _mark_tcache_struct(heap, geo)
    if struct_slot is not None:
        _decode_tcache(reader, heap, struct_slot, geo, lists)
    arena_top = _decode_arena(memory, reader, ctx, heap, geo, lists)
    if any(s.raw.flags & _NON_MAIN_ARENA for s in heap.slots):
        lists.diagnostics.append(
            "NON_MAIN_ARENA chunks present; non-main arenas are not decoded")
    return _version_hint(struct_slot, lists.safe), arena_top


def _empty_layout(flavor: _Flavor, platform: TargetPlatform) -> HeapLayout:
    patterns = ", ".join(flavor.region_patterns)
    return HeapLayout(flavor.kind, platform=platform, diagnostics=(
        f"no captured {flavor.kind.value} heap region (looked for {patterns})",),
        coverage={"regions": [], "bytes_total": 0, "chunk_count": 0})


def _parse(memory: VaMemory, ctx: DetectContext, opts: ParseOptions,
           flavor: _Flavor) -> HeapLayout:
    regions = _target_regions(ctx, flavor, opts)
    if not regions:
        return _empty_layout(flavor, memory.platform)
    geo = _geometry(memory.platform)
    reader = _PagedReader(memory, geo)
    walk = _walk_all(reader, regions, geo, flavor, opts.max_chunks)
    heap = _Heap([_initial_slot(walk.raws, i, geo, flavor) for i in range(len(walk.raws))],
                 regions)
    lists = _Lists()
    version, arena_top = "dlmalloc 2.8.x", None
    if not flavor.dlmalloc:
        version, arena_top = _ptmalloc2_overlays(memory, reader, ctx, heap, geo, lists)
    coverage = _coverage(regions, walk, arena_top, lists.safe)
    confidence = coverage["bytes_walked"] / max(1, coverage["bytes_total"])
    return HeapLayout(
        flavor.kind, version_hint=version, platform=memory.platform,
        regions=tuple(HeapRegion(r.va, r.size, r.name, "heap") for r in regions),
        chunks=tuple(_to_chunk(reader, slot, geo) for slot in heap.slots),
        free_lists=tuple(lists.free_lists),
        evidence=(Evidence("walk", f"{len(walk.raws)} chunks walked in "
                           f"{len(regions)} region(s)", confidence),),
        confidence=confidence,
        diagnostics=tuple(walk.diagnostics + lists.diagnostics), coverage=coverage)


def parse_ptmalloc2(memory: VaMemory, ctx: DetectContext,
                    opts: ParseOptions) -> HeapLayout:
    """Walk glibc ptmalloc2 heap regions (chunks, tcache, main_arena bins)."""
    return _parse(memory, ctx, opts, _PTMALLOC2)


def parse_dlmalloc(memory: VaMemory, ctx: DetectContext,
                   opts: ParseOptions) -> HeapLayout:
    """Walk dlmalloc 2.8.x segments (chunks only; no malloc_state)."""
    return _parse(memory, ctx, opts, _DLMALLOC)


DESCRIPTOR_OVERRIDES = {
    AllocatorKind.PTMALLOC2: (probe_ptmalloc2, parse_ptmalloc2),
    AllocatorKind.DLMALLOC: (probe_dlmalloc, parse_dlmalloc),
}

__all__ = ["probe_ptmalloc2", "parse_ptmalloc2", "probe_dlmalloc",
           "parse_dlmalloc", "DESCRIPTOR_OVERRIDES"]
