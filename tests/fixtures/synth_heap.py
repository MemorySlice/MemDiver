"""Hand-built heap byte layouts: the expected-result oracle for heap parsers.

Every builder returns a :class:`SynthHeap`: the raw bytes of one or more
mapped regions plus the list of :class:`ExpectedChunk` a correct parser must
recover from them. Layouts are written field by field from the upstream
struct definitions cited in each builder's docstring; there is no allocation
simulation. All builders are deterministic.

Conventions shared by every :class:`ExpectedChunk`:

* ``va`` / ``size`` -- the chunk (or slot / block) as the allocator sizes it;
  chunks never overlap and, within ``SynthHeap.tiled_span``, tile exactly.
* ``header_len`` -- bytes from ``va`` to the user pointer.
* ``user_len`` -- user-visible bytes: the requested size where the allocator
  records it (scudo, mallocng in-use), otherwise ``size - header_len``.
* ``bin`` -- free-list / class label, or ``None``.

Load a fixture as a DumpSource with :func:`as_regioned_raw` +
:func:`open_regioned`.
"""
from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from memdiver.heap.model import AllocatorKind, ChunkState

Region = Tuple[int, int, str]          # (va, size, name)
Module = Tuple[int, int, str]          # (va, size, path)

PAGE = 0x1000


@dataclass(frozen=True)
class ExpectedChunk:
    """One chunk a parser must report."""

    va: int
    size: int
    state: ChunkState
    header_len: int
    user_len: int
    bin: Optional[str] = None


@dataclass
class SynthHeap:
    """Synthetic heap mapping(s) and the chunks they contain.

    ``data`` is the concatenation of every region's bytes in ``regions``
    order (the same layout as a regioned raw ``.bin``); ``base_va`` is the
    first region's VA. ``tiled_span`` is the half-open VA range the expected
    chunks must tile exactly (empty for the negative control).
    """

    data: bytes
    base_va: int
    allocator: str
    pointer_size: int
    regions: List[Region]
    chunks: List[ExpectedChunk]
    tiled_span: Tuple[int, int] = (0, 0)
    perms: List[str] = field(default_factory=list)

    def region_bytes(self, idx: int) -> bytes:
        start = sum(size for _va, size, _n in self.regions[:idx])
        return self.data[start:start + self.regions[idx][1]]

    def read(self, va: int, length: int) -> bytes:
        """Bytes at *va* (must lie inside one region)."""
        offset = 0
        for region_va, size, _name in self.regions:
            if region_va <= va and va + length <= region_va + size:
                start = offset + va - region_va
                return self.data[start:start + length]
            offset += size
        raise ValueError(f"{va:#x}+{length} is not inside one region")


# -- low-level writers ------------------------------------------------------------


def _ptr_fmt(pointer_size: int) -> str:
    if pointer_size not in (4, 8):
        raise ValueError(f"pointer_size must be 4 or 8, got {pointer_size}")
    return "<Q" if pointer_size == 8 else "<I"


def _put_word(buf: bytearray, offset: int, value: int, pointer_size: int) -> None:
    struct.pack_into(_ptr_fmt(pointer_size), buf, offset, value)


def _fill(buf: bytearray, offset: int, length: int, byte: int) -> None:
    buf[offset:offset + length] = bytes([byte]) * length


# -- glibc ptmalloc2 / dlmalloc boundary tags -------------------------------------

PREV_INUSE = 0x1
DL_CINUSE = 0x2                       # dlmalloc 2.8.x CINUSE_BIT
TCACHE_BINS = 64


def _malloc_alignment(pointer_size: int) -> int:
    """2 * SIZE_SZ: 16 on 64-bit; 8 on 32-bit (ARM-style MALLOC_ALIGNMENT)."""
    return 2 * pointer_size


def _min_chunk(pointer_size: int) -> int:
    return 4 * pointer_size           # MINSIZE


def _tcache_struct_size(pointer_size: int) -> int:
    """request2size(sizeof(tcache_perthread_struct)) for glibc >= 2.30.

    ``uint16_t counts[64]; tcache_entry *entries[64];`` -> 0x290 on 64-bit.
    """
    request = 2 * TCACHE_BINS + pointer_size * TCACHE_BINS
    align = _malloc_alignment(pointer_size)
    return (request + pointer_size + align - 1) & ~(align - 1)


def _tcache_index(chunk_size: int, pointer_size: int) -> int:
    """csize2tidx(): (size - MINSIZE + MALLOC_ALIGN_MASK) / MALLOC_ALIGNMENT."""
    align = _malloc_alignment(pointer_size)
    return (chunk_size - _min_chunk(pointer_size) + align - 1) // align


def _scaled(sizes: Sequence[int], pointer_size: int) -> List[int]:
    """64-bit chunk sizes scaled to *pointer_size* (keeps the same layout)."""
    return [size * pointer_size // 8 for size in sizes]


def _write_boundary_chunk(buf: bytearray, offset: int, size_field: int,
                          pointer_size: int, prev_size: int = 0) -> None:
    _put_word(buf, offset, prev_size, pointer_size)
    _put_word(buf, offset + pointer_size, size_field, pointer_size)


def glibc_heap(base_va: Optional[int] = None, *, pointer_size: int = 8,
               safe_linking: bool = True, region_size: int = PAGE) -> SynthHeap:
    """glibc ptmalloc2 ``[heap]`` (main arena, sbrk heap), glibc >= 2.30.

    Follows ``malloc/malloc.c``: ``struct malloc_chunk { INTERNAL_SIZE_T
    mchunk_prev_size; INTERNAL_SIZE_T mchunk_size; ... }`` with the low size
    bits as flags (PREV_INUSE=1, IS_MMAPPED=2, NON_MAIN_ARENA=4). The first
    chunk is ``tcache_perthread_struct { uint16_t counts[TCACHE_MAX_BINS];
    tcache_entry *entries[TCACHE_MAX_BINS]; }`` (chunk size 0x290 on 64-bit).
    Freed chunks are ``tcache_entry { tcache_entry *next; uintptr_t key; }``
    at the user pointer; ``next`` is ``PROTECT_PTR`` (``(pos >> 12) ^ ptr``,
    glibc >= 2.32) when *safe_linking*. Tcache'd chunks keep PREV_INUSE set
    in their successor, so every size field carries PREV_INUSE. Ends with the
    top chunk.
    """
    if base_va is None:
        base_va = 0x5555_5555_9000 if pointer_size == 8 else 0x0804_C000
    header = 2 * pointer_size
    tcache_size = _tcache_struct_size(pointer_size)
    tcache_mem = base_va + header
    # (size_64bit, state, fill byte) after the tcache struct.
    layout = [(0x30, ChunkState.IN_USE, 0x41), (0x30, ChunkState.CACHED, 0x42),
              (0x50, ChunkState.IN_USE, 0x43), (0x30, ChunkState.CACHED, 0x44),
              (0x40, ChunkState.CACHED, 0x45), (0x100, ChunkState.IN_USE, 0x46)]
    sizes = _scaled([s for s, _st, _f in layout], pointer_size)
    buf = bytearray(region_size)
    chunks = [ExpectedChunk(base_va, tcache_size, ChunkState.IN_USE, header,
                            tcache_size - header, "tcache_perthread_struct")]
    _write_boundary_chunk(buf, 0, tcache_size | PREV_INUSE, pointer_size)
    offset = tcache_size
    bins: dict = {}
    for size, (_s, state, fill) in zip(sizes, layout):
        _write_boundary_chunk(buf, offset, size | PREV_INUSE, pointer_size)
        _fill(buf, offset + header, size - header, fill)
        label = None
        if state is ChunkState.CACHED:
            idx = _tcache_index(size, pointer_size)
            label = f"tcache[{idx}]"
            bins.setdefault(idx, []).append(base_va + offset + header)
        chunks.append(ExpectedChunk(base_va + offset, size, state, header,
                                    size - header, label))
        offset += size
    _write_tcache(buf, bins, tcache_mem, base_va, pointer_size, safe_linking)
    top_size = region_size - offset
    _write_boundary_chunk(buf, offset, top_size | PREV_INUSE, pointer_size)
    chunks.append(ExpectedChunk(base_va + offset, top_size, ChunkState.FREE,
                                header, top_size - header, "top"))
    return SynthHeap(bytes(buf), base_va, AllocatorKind.PTMALLOC2.value,
                     pointer_size, [(base_va, region_size, "[heap]")], chunks,
                     (base_va, base_va + region_size), ["rw-p"])


def _write_tcache(buf: bytearray, bins: dict, tcache_mem: int, base_va: int,
                  pointer_size: int, safe_linking: bool) -> None:
    """Fill counts[]/entries[] and each entry's next/key (LIFO order)."""
    counts_off = tcache_mem - base_va
    entries_off = counts_off + 2 * TCACHE_BINS
    for idx, mems in bins.items():
        chain = list(reversed(mems))          # most recently freed first
        struct.pack_into("<H", buf, counts_off + 2 * idx, len(chain))
        _put_word(buf, entries_off + pointer_size * idx, chain[0], pointer_size)
        for pos, mem in enumerate(chain):
            nxt = chain[pos + 1] if pos + 1 < len(chain) else 0
            stored = ((mem >> 12) ^ nxt) if safe_linking else nxt
            _put_word(buf, mem - base_va, stored, pointer_size)
            _put_word(buf, mem - base_va + pointer_size, tcache_mem, pointer_size)


def dlmalloc_heap(base_va: Optional[int] = None, *, pointer_size: int = 8,
                  region_name: str = "[anon:libc_malloc]",
                  region_size: int = PAGE) -> SynthHeap:
    """Doug Lea dlmalloc 2.8.x segment (as in old bionic ``libc_malloc``).

    Follows ``malloc.c``: ``struct malloc_chunk { size_t prev_foot; size_t
    head; struct malloc_chunk *fd, *bk; }``; ``head`` = size | PINUSE_BIT(1)
    | CINUSE_BIT(2). A free chunk has CINUSE clear, ``fd``/``bk`` into the
    smallbin header inside ``malloc_state`` (a VA outside this region), its
    size repeated as the successor's ``prev_foot`` and the successor's
    PINUSE clear. The top chunk's head is ``tsize | PINUSE_BIT``.
    """
    if base_va is None:
        base_va = 0x7F00_0010_0000 if pointer_size == 8 else 0x4010_0000
    header = 2 * pointer_size
    smallbin_va = base_va - 0x10_0000 + 0x80     # fake &mstate->smallbins[i]
    layout = [(0x40, True, 0x51), (0x60, False, 0x52), (0x30, True, 0x53),
              (0x80, True, 0x54), (0x50, True, 0x55)]
    sizes = _scaled([s for s, _u, _f in layout], pointer_size)
    buf = bytearray(region_size)
    chunks: List[ExpectedChunk] = []
    offset = 0
    prev_in_use, prev_size = True, 0
    for size, (_s, in_use, fill) in zip(sizes, layout):
        head = size | (PREV_INUSE if prev_in_use else 0)
        head |= DL_CINUSE if in_use else 0
        _write_boundary_chunk(buf, offset, head, pointer_size,
                              0 if prev_in_use else prev_size)
        _fill(buf, offset + header, size - header, fill)
        if not in_use:
            _put_word(buf, offset + header, smallbin_va, pointer_size)
            _put_word(buf, offset + header + pointer_size, smallbin_va,
                      pointer_size)
        state = ChunkState.IN_USE if in_use else ChunkState.FREE
        chunks.append(ExpectedChunk(base_va + offset, size, state, header,
                                    size - header,
                                    None if in_use else "smallbin"))
        prev_in_use, prev_size = in_use, size
        offset += size
    top_size = region_size - offset
    _write_boundary_chunk(buf, offset, top_size | PREV_INUSE, pointer_size)
    chunks.append(ExpectedChunk(base_va + offset, top_size, ChunkState.FREE,
                                header, top_size - header, "top"))
    return SynthHeap(bytes(buf), base_va, AllocatorKind.DLMALLOC.value,
                     pointer_size, [(base_va, region_size, region_name)],
                     chunks, (base_va, base_va + region_size), ["rw-p"])


# -- scudo ------------------------------------------------------------------------

SCUDO_HEADER_LEN = 16                 # roundUp(sizeof(PackedHeader), 16)
SCUDO_AVAILABLE, SCUDO_ALLOCATED, SCUDO_QUARANTINED = 0, 1, 2
_SCUDO_STATES = {SCUDO_AVAILABLE: ChunkState.FREE,
                 SCUDO_ALLOCATED: ChunkState.IN_USE,
                 SCUDO_QUARANTINED: ChunkState.QUARANTINED}


def scudo_pack_header(class_id: int, state: int, size: int, *, origin: int = 0,
                      offset: int = 0, checksum: int = 0) -> int:
    """Pack a ``scudo::Chunk::UnpackedHeader`` (LSB-first bitfields)."""
    return ((class_id & 0xFF) | (state & 0x3) << 8 | (origin & 0x3) << 10
            | (size & 0xFFFFF) << 12 | (offset & 0xFFFF) << 32
            | (checksum & 0xFFFF) << 48)


def scudo_unpack_header(word: int) -> dict:
    return {"class_id": word & 0xFF, "state": (word >> 8) & 0x3,
            "origin": (word >> 10) & 0x3, "size": (word >> 12) & 0xFFFFF,
            "offset": (word >> 32) & 0xFFFF, "checksum": (word >> 48) & 0xFFFF}


def scudo_primary(base_va: int = 0x7A00_0000_0000, *, class_id: int = 10,
                  block_size: int = 0x200, region_size: int = PAGE) -> SynthHeap:
    """Scudo standalone primary region for one size class (64-bit).

    Follows ``compiler-rt/lib/scudo/standalone/chunk.h``: ``struct
    UnpackedHeader { uptr ClassId : 8; u8 State : 2; u8 OriginOrWasZeroed : 2;
    uptr SizeOrUnusedBytes : 20; uptr Offset : 16; uptr Checksum : 16; }``
    packed into one u64 at the start of a 16-byte header area that precedes
    the user pointer. Blocks are ``block_size`` apart. Checksums are
    arbitrary (the per-process cookie is unknown to a dump reader).
    """
    states = [SCUDO_ALLOCATED, SCUDO_ALLOCATED, SCUDO_AVAILABLE,
              SCUDO_ALLOCATED, SCUDO_QUARANTINED, SCUDO_AVAILABLE,
              SCUDO_ALLOCATED, SCUDO_AVAILABLE]
    count = region_size // block_size
    buf = bytearray(region_size)
    chunks: List[ExpectedChunk] = []
    for idx in range(count):
        state = states[idx % len(states)]
        requested = block_size - SCUDO_HEADER_LEN - 8 * (idx % 3)
        word = scudo_pack_header(class_id, state, requested,
                                 checksum=0xBEEF ^ (idx * 0x111))
        offset = idx * block_size
        struct.pack_into("<Q", buf, offset, word)
        _fill(buf, offset + SCUDO_HEADER_LEN, requested, 0x60 + idx)
        chunks.append(ExpectedChunk(base_va + offset, block_size,
                                    _SCUDO_STATES[state], SCUDO_HEADER_LEN,
                                    requested, f"class{class_id}"))
    return SynthHeap(bytes(buf), base_va, AllocatorKind.SCUDO.value, 8,
                     [(base_va, region_size, "[anon:scudo:primary]")], chunks,
                     (base_va, base_va + count * block_size), ["rw-p"])


# -- musl mallocng ----------------------------------------------------------------

MALLOCNG_UNIT = 16
MALLOCNG_IB = 4
#: ``size_classes[]`` from musl ``src/malloc/mallocng/malloc.c`` (first 16).
MALLOCNG_SIZE_CLASSES = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 18, 20, 25, 31)
MALLOCNG_META_SIZE = 40               # 64-bit sizeof(struct meta)
MALLOCNG_META_AREA_HDR = 24           # check, next, nslots (+pad)


def mallocng_group(meta_va: int = 0x7F00_0020_0000,
                   group_va: int = 0x7F00_0021_0000, *, sizeclass: int = 3,
                   nslots: int = 8, secret: int = 0x1122_3344_5566_7788
                   ) -> SynthHeap:
    """musl mallocng: one meta area + one mmapped group (64-bit).

    Follows ``src/malloc/mallocng/meta.h``: ``struct meta { struct meta
    *prev, *next; struct group *mem; volatile int avail_mask, freed_mask;
    uintptr_t last_idx:5; uintptr_t freeable:1; uintptr_t sizeclass:6;
    uintptr_t maplen:8*sizeof(uintptr_t)-12; }`` inside ``struct meta_area
    { uint64_t check; struct meta_area *next; int nslots; struct meta
    slots[]; }``, and ``struct group { struct meta *meta; unsigned char
    active_idx:5; char pad[UNIT - sizeof(struct meta *) - 1]; unsigned char
    storage[]; }``. Slot *i* starts at ``storage + i*stride``; ``enframe()``
    writes the 4-byte in-band header just before it: ``p[-3] = idx |
    reserved<<5``, ``*(uint16_t*)(p-2) = (p - storage)/UNIT`` (reserved >= 5
    is stored as a u32 at ``end-4``). ``free()`` sets ``p[-3] = 255`` and
    zeroes the offset. Region 0 is the meta area, region 1 the group.
    """
    stride = MALLOCNG_SIZE_CLASSES[sizeclass] * MALLOCNG_UNIT
    if nslots == 1:   # get_stride(): !last_idx && maplen -> maplen*4096 - UNIT
        stride = PAGE - MALLOCNG_UNIT
    storage_va = group_va + MALLOCNG_UNIT
    in_use = {i for i in (0, 1, 3, 6) if i < nslots}
    freed = {i for i in (2, 5) if i < nslots}
    avail = set(range(nslots)) - in_use - freed
    group = bytearray(PAGE)
    meta_slot_va = meta_va + MALLOCNG_META_AREA_HDR
    struct.pack_into("<QB", group, 0, meta_slot_va, nslots - 1)
    chunks: List[ExpectedChunk] = []
    for idx in range(nslots):
        slot_off = MALLOCNG_UNIT + idx * stride
        chunks.append(_mallocng_slot(group, slot_off, storage_va, idx, stride,
                                     in_use, freed))
    meta = bytearray(PAGE)
    nmeta = (PAGE - MALLOCNG_META_AREA_HDR) // MALLOCNG_META_SIZE
    struct.pack_into("<QQi", meta, 0, secret, 0, nmeta)
    bits = (nslots - 1) | 1 << 5 | sizeclass << 6 | 1 << 12   # maplen = 1 page
    struct.pack_into("<QQQIIQ", meta, MALLOCNG_META_AREA_HDR, meta_slot_va,
                     meta_slot_va, group_va, _mask(avail), _mask(freed), bits)
    regions = [(meta_va, PAGE, ""), (group_va, PAGE, "")]
    return SynthHeap(bytes(meta) + bytes(group), meta_va,
                     AllocatorKind.MALLOCNG.value, 8, regions, chunks,
                     (storage_va, storage_va + nslots * stride),
                     ["rw-p", "rw-p"])


def _mask(indices: set) -> int:
    return sum(1 << i for i in indices)


def _mallocng_slot(group: bytearray, slot_off: int, storage_va: int, idx: int,
                   stride: int, in_use: set, freed: set) -> ExpectedChunk:
    slot_va = storage_va - MALLOCNG_UNIT + slot_off
    usable = stride - MALLOCNG_IB
    if idx in in_use:
        requested = max(0, usable - 9 - 4 * idx)  # reserved >= 5: u32 form
        reserved = usable - requested
        _fill(group, slot_off, requested, 0x70 + idx)
        struct.pack_into("<BH", group, slot_off - 3, idx | 5 << 5,
                         (slot_off - MALLOCNG_UNIT) // MALLOCNG_UNIT)
        end = slot_off + usable
        group[end - 5] = 0
        struct.pack_into("<I", group, end - 4, reserved)
        return ExpectedChunk(slot_va, stride, ChunkState.IN_USE, 0, requested,
                             None)
    if idx in freed:
        _fill(group, slot_off, usable, 0x30 + idx)     # stale payload
        struct.pack_into("<BH", group, slot_off - 3, 0xFF, 0)
        return ExpectedChunk(slot_va, stride, ChunkState.FREE, 0, usable,
                             "freed")
    return ExpectedChunk(slot_va, stride, ChunkState.FREE, 0, usable, "avail")


# -- jemalloc ---------------------------------------------------------------------


def jemalloc_slab(base_va: int = 0x7F00_0030_0000, *, reg_size: int = 0x200,
                  region_size: int = PAGE) -> SynthHeap:
    """jemalloc small-size-class slab: equal regions, no inline headers.

    jemalloc keeps all metadata out of band (``edata_t`` + slab bitmap in the
    arena's base allocations), so a slab is just ``reg_size``-strided
    regions; allocation state is unknowable from the slab bytes alone.
    """
    count = region_size // reg_size
    buf = bytearray(region_size)
    chunks = []
    for idx in range(count):
        if idx % 3 != 2:
            _fill(buf, idx * reg_size, reg_size, 0x80 + idx)
        chunks.append(ExpectedChunk(base_va + idx * reg_size, reg_size,
                                    ChunkState.UNKNOWN, 0, reg_size,
                                    f"size_class_{reg_size}"))
    return SynthHeap(bytes(buf), base_va, AllocatorKind.JEMALLOC.value, 8,
                     [(base_va, region_size, "[anon:jemalloc]")], chunks,
                     (base_va, base_va + count * reg_size), ["rw-p"])


def random_region(seed: int = 0, base_va: int = 0x7F00_0040_0000, *,
                  region_size: int = PAGE) -> SynthHeap:
    """Negative control: anonymous mapping of seeded random bytes, no chunks."""
    data = random.Random(seed).randbytes(region_size)
    return SynthHeap(data, base_va, AllocatorKind.UNKNOWN.value, 8,
                     [(base_va, region_size, "")], [], (base_va, base_va),
                     ["rw-p"])


# -- DumpSource wrappers ----------------------------------------------------------


def as_regioned_raw(tmp_path: Path, heaps: Sequence[SynthHeap],
                    modules: Sequence[Module] = (), *,
                    flavour: str = "gdb_raw", stem: str = "synth") -> Path:
    """Write ``<stem>.<flavour>.bin`` + ``.maps``; return the ``.bin`` path.

    Regions are sorted by VA; the ``.bin`` is their byte concatenation (the
    layout of :mod:`core.dump_sources._regioned_base`). Module mappings are
    zero-filled ``r-xp`` regions named by their path.
    """
    entries = []
    for heap in heaps:
        perms = heap.perms or ["rw-p"] * len(heap.regions)
        for idx, (va, size, name) in enumerate(heap.regions):
            entries.append((va, size, perms[idx], name, heap.region_bytes(idx)))
    for va, size, path in modules:
        entries.append((va, size, "r-xp", path, bytes(size)))
    entries.sort(key=lambda e: e[0])
    for prev, cur in zip(entries, entries[1:]):
        if prev[0] + prev[1] > cur[0]:
            raise ValueError(f"regions overlap at {cur[0]:#x}")
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    bin_path = tmp_path / f"{stem}.{flavour}.bin"
    bin_path.write_bytes(b"".join(e[4] for e in entries))
    lines = [f"{va:x}-{va + size:x} {perms} 00000000 00:00 0"
             + (f" {name}" if name else "")
             for va, size, perms, name, _data in entries]
    bin_path.with_suffix(".maps").write_text("\n".join(lines) + "\n")
    return bin_path


def open_regioned(path: Path):
    """Open *path* via ``core.dump_source.open_dump`` (opened, ready to read)."""
    from memdiver.core.dump_source import open_dump

    source = open_dump(Path(path))
    source.open()
    return source
