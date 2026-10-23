"""Scudo (LLVM standalone, Android >= 11) primary-region parser.

Every scudo chunk starts with a 16-byte header area (``getHeaderSize()`` =
``roundUp(sizeof(PackedHeader), 16)``) that precedes the user pointer. Its
first u64 is the packed ``Chunk::UnpackedHeader`` (``chunk.h``), LSB-first::

    ClassId:8 | State:2 | OriginOrWasZeroed:2 | SizeOrUnusedBytes:20
              | Offset:16 | Checksum:16

State 0 = Available (freed), 1 = Allocated, 2 = Quarantined. The checksum is
keyed by a per-process cookie a dump reader never has, so headers are judged
on STRUCTURE instead:

* a valid state, a non-zero ClassId (0 is the internal BatchClass), Offset 0
  (no realignment in the primary) and a non-zero size;
* the block stride of a ClassId is inferred from where its headers repeat in
  the region (the most common gap between them), and the slot phase from the
  most common position modulo that stride;
* the recorded size must fit the stride, and neighbouring slots must agree.

Each walked slot gets a structural confidence; slots below
:data:`_UNKNOWN_BELOW` (garbage or never-allocated zero headers) are reported
as ``UNKNOWN``. The stride is inferred purely from the bytes: the Android
size-class map changes between releases, so it is not used to override them.

LIMITATIONS (by design, this release):

* ``[anon:scudo:secondary]`` mappings are listed as regions but their
  ``LargeBlock::Header`` is not decoded (a diagnostic says so);
* BatchClass (ClassId 0) blocks and the per-class free lists
  (``TransferBatch``) are not walked — no :class:`FreeList` is produced;
* a ClassId needs at least two headers on its stride to be walked, and only
  slots between its first and last header are reported;
* realigned chunks (``memalign``, Offset != 0) score lower and may surface as
  ``UNKNOWN``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (AllocatorKind, ChunkState, Evidence,
                                 HeapChunk, HeapLayout, HeapRegion)
from memdiver.heap.platform import MappedRegion
from memdiver.heap.registry import (DetectContext, DetectFn, DetectScore,
                                    ParseFn, ParseOptions, name_matches)

HEADER_LEN = 16
_ALIGN = 16
_PAGE = 0x1000
_MIN_STRIDE = 2 * HEADER_LEN
_MAX_STRIDE = 1 << 20
_MIN_ANCHORS = 2
_MIN_HIT_RATE = 0.5
_UNKNOWN_BELOW = 0.6
_GARBAGE_SCORE = 0.1
_PROBE_BYTES = 0x10000
_PROBE_MAX_REGIONS = 32
_PROBE_MIN_ANCHORS = 4
_PROBE_FULL_ANCHORS = 8
_PROBE_CEILING = 0.9

_PRIMARY = "[anon:scudo:primary*"
_SECONDARY = "[anon:scudo:secondary*"

_STATES = {0: ChunkState.FREE, 1: ChunkState.IN_USE,
           2: ChunkState.QUARANTINED}


# -- header ---------------------------------------------------------------------


@dataclass(frozen=True)
class ScudoHeader:
    """One decoded ``Chunk::UnpackedHeader``."""

    class_id: int
    state: int
    origin: int
    size_or_unused: int
    offset: int
    checksum: int

    @classmethod
    def decode(cls, word: int) -> "ScudoHeader":
        return cls(class_id=word & 0xFF, state=(word >> 8) & 0x3,
                   origin=(word >> 10) & 0x3,
                   size_or_unused=(word >> 12) & 0xFFFFF,
                   offset=(word >> 32) & 0xFFFF,
                   checksum=(word >> 48) & 0xFFFF)

    @property
    def plausible(self) -> bool:
        """A primary-region header candidate (before any stride check)."""
        return (self.state in _STATES and self.class_id != 0
                and self.offset == 0 and self.size_or_unused > 0)

    def extra(self) -> Dict[str, int]:
        return {"class_id": self.class_id, "origin": self.origin,
                "size_or_unused": self.size_or_unused, "offset": self.offset,
                "checksum": self.checksum}


# -- region bytes -----------------------------------------------------------------


@dataclass
class _RegionImage:
    """A region's bytes plus which pages the dump actually captured."""

    region: MappedRegion
    data: bytes
    captured_pages: np.ndarray
    little_endian: bool = True

    @property
    def va(self) -> int:
        return self.region.va

    @property
    def captured_bytes(self) -> int:
        full = int(self.captured_pages.sum()) * _PAGE
        return min(full, len(self.data))

    def captured(self, offset: int, length: int) -> bool:
        first, last = offset // _PAGE, (offset + length - 1) // _PAGE
        if offset < 0 or offset + length > len(self.data):
            return False
        return bool(self.captured_pages[first:last + 1].all())

    def header(self, offset: int) -> Optional[ScudoHeader]:
        if not self.captured(offset, 8):
            return None
        raw = self.data[offset:offset + 8]
        word = (int.from_bytes(raw, "little") if self.little_endian
                else int.from_bytes(raw, "big"))
        return ScudoHeader.decode(word)

    def slot_words(self) -> np.ndarray:
        """The u64 at every 16-aligned offset (uncaptured slots are 0)."""
        usable = len(self.data) // _ALIGN * _ALIGN
        dtype = np.dtype("<u8" if self.little_endian else ">u8")
        words = np.frombuffer(self.data[:usable], dtype=dtype)
        return words.reshape(-1, 2)[:, 0].astype(np.uint64)

    def slot_captured(self, count: int) -> np.ndarray:
        pages = (np.arange(count) * _ALIGN) // _PAGE
        return self.captured_pages[pages]


def _read_image(memory: VaMemory, region: MappedRegion,
                limit: Optional[int] = None) -> _RegionImage:
    """Read *region* (its first *limit* bytes), page by page on a gap."""
    size = region.size if limit is None else min(region.size, limit)
    little = memory.platform.endianness == "little"
    pages = (size + _PAGE - 1) // _PAGE
    whole = memory.read(region.va, size)
    if whole is not None:
        return _RegionImage(region, whole, np.ones(pages, dtype=bool), little)
    buf, captured = bytearray(size), np.zeros(pages, dtype=bool)
    for idx in range(pages):
        start = idx * _PAGE
        chunk = memory.read(region.va + start, min(_PAGE, size - start))
        if chunk is not None:
            buf[start:start + len(chunk)] = chunk
            captured[idx] = True
    return _RegionImage(region, bytes(buf), captured, little)


# -- stride inference -------------------------------------------------------------


@dataclass(frozen=True)
class _ClassRun:
    """The blocks of one ClassId: ``[first, last]`` offsets on ``stride``."""

    class_id: int
    stride: int
    first: int
    last: int
    anchors: int

    @property
    def slots(self) -> int:
        return (self.last - self.first) // self.stride + 1

    @property
    def end(self) -> int:
        return self.last + self.stride

    @property
    def hit_rate(self) -> float:
        return self.anchors / self.slots

    def owns(self, offset: int) -> bool:
        return (self.first <= offset <= self.last
                and (offset - self.first) % self.stride == 0)


def _candidates_by_class(image: _RegionImage) -> Dict[int, np.ndarray]:
    """Offsets of plausible headers, grouped by ClassId."""
    words = image.slot_words()
    if not len(words):
        return {}
    class_ids = words & np.uint64(0xFF)
    mask = ((((words >> np.uint64(8)) & np.uint64(0x3)) <= 2)
            & (class_ids != 0)
            & (((words >> np.uint64(32)) & np.uint64(0xFFFF)) == 0)
            & (((words >> np.uint64(12)) & np.uint64(0xFFFFF)) > 0)
            & image.slot_captured(len(words)))
    offsets = np.nonzero(mask)[0] * _ALIGN
    return {int(cid): offsets[class_ids[mask] == cid]
            for cid in np.unique(class_ids[mask])}


def _mode(values: np.ndarray) -> int:
    """Most common value; ties go to the smallest."""
    uniq, counts = np.unique(values, return_counts=True)
    return int(uniq[int(np.argmax(counts))])


def _infer_run(class_id: int, offsets: np.ndarray) -> Optional[_ClassRun]:
    """Stride and phase of *class_id*'s headers, if they repeat convincingly."""
    if len(offsets) < _MIN_ANCHORS:
        return None
    stride = _mode(np.diff(offsets))
    if not _MIN_STRIDE <= stride <= _MAX_STRIDE or stride % _ALIGN:
        return None
    phase = _mode(offsets % stride)
    anchors = offsets[offsets % stride == phase]
    if len(anchors) < _MIN_ANCHORS:
        return None
    run = _ClassRun(class_id, stride, int(anchors[0]), int(anchors[-1]),
                    len(anchors))
    return run if run.hit_rate >= _MIN_HIT_RATE else None


def _class_runs(image: _RegionImage) -> List[_ClassRun]:
    """Non-overlapping class runs, strongest first then sorted by offset."""
    runs = [run for cid, offs in _candidates_by_class(image).items()
            if (run := _infer_run(cid, offs)) is not None]
    accepted: List[_ClassRun] = []
    for run in sorted(runs, key=lambda r: (-r.anchors, r.first)):
        if all(run.end <= other.first or other.end <= run.first
               for other in accepted):
            accepted.append(run)
    return sorted(accepted, key=lambda r: r.first)


# -- chunk construction -----------------------------------------------------------


def _neighbour_agrees(image: _RegionImage, run: _ClassRun, offset: int) -> bool:
    for neighbour in (offset - run.stride, offset + run.stride):
        if not run.owns(neighbour):
            continue
        header = image.header(neighbour)
        if header is not None and header.plausible \
                and header.class_id == run.class_id:
            return True
    return False


def _size_fits(header: ScudoHeader, stride: int) -> bool:
    return 0 < header.size_or_unused <= stride - HEADER_LEN


def structural_score(header: ScudoHeader, class_id: int, stride: int,
                     neighbour_agrees: bool) -> float:
    """How much a header at a stride slot looks like a real scudo header."""
    if header.state not in _STATES or header.class_id != class_id:
        return _GARBAGE_SCORE
    score = 0.4
    score += 0.2 if header.offset == 0 else 0.0
    score += 0.2 if _size_fits(header, stride) else 0.0
    score += 0.2 if neighbour_agrees else 0.0
    return round(score, 3)


def _make_chunk(va: int, header: ScudoHeader, run: _ClassRun,
                confidence: float) -> HeapChunk:
    trusted = confidence >= _UNKNOWN_BELOW
    state = _STATES[header.state] if trusted else ChunkState.UNKNOWN
    user_len = (header.size_or_unused if trusted and _size_fits(header, run.stride)
                else run.stride - HEADER_LEN)
    return HeapChunk(va=va, size=run.stride, state=state,
                     header_len=HEADER_LEN, user_va=va + HEADER_LEN,
                     user_len=user_len, bin=f"class{run.class_id}",
                     extra=header.extra(), confidence=confidence)


def _slot_chunk(image: _RegionImage, run: _ClassRun,
                offset: int) -> Optional[HeapChunk]:
    if offset + run.stride > len(image.data):
        return None
    header = image.header(offset)
    if header is None:
        return None
    score = structural_score(header, run.class_id, run.stride,
                             _neighbour_agrees(image, run, offset))
    return _make_chunk(image.va + offset, header, run, score)


# -- layout assembly --------------------------------------------------------------


@dataclass
class _LayoutBuilder:
    """Accumulates chunks, regions and bookkeeping across walked regions."""

    max_chunks: int
    chunks: List[HeapChunk] = field(default_factory=list)
    regions: List[HeapRegion] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    bytes_total: int = 0
    bytes_captured: int = 0
    uncaptured_pages: int = 0
    truncated: bool = False

    def walk(self, image: _RegionImage) -> None:
        region = image.region
        self.regions.append(HeapRegion(region.va, region.size, region.name,
                                       "primary"))
        self._count_coverage(image)
        runs = _class_runs(image)
        if not runs:
            self.diagnostics.append(
                f"{region.name or hex(region.va)}: no repeating scudo headers")
        for run in runs:
            self._record_run(image, run)
            self._walk_run(image, run)

    def _count_coverage(self, image: _RegionImage) -> None:
        self.bytes_total += len(image.data)
        self.bytes_captured += image.captured_bytes
        missing = int((~image.captured_pages).sum())
        self.uncaptured_pages += missing
        if missing:
            self.diagnostics.append(
                f"{image.region.name or hex(image.va)}: {missing} uncaptured "
                "page(s) skipped")

    def _record_run(self, image: _RegionImage, run: _ClassRun) -> None:
        self.evidence.append(Evidence(
            "structure",
            f"class {run.class_id}: {run.anchors}/{run.slots} headers on "
            f"stride {run.stride:#x} at {image.va + run.first:#x}",
            round(run.hit_rate, 3)))

    def _walk_run(self, image: _RegionImage, run: _ClassRun) -> None:
        for offset in range(run.first, run.last + 1, run.stride):
            if len(self.chunks) >= self.max_chunks:
                self._truncate()
                return
            chunk = _slot_chunk(image, run, offset)
            if chunk is not None:
                self.chunks.append(chunk)

    def _truncate(self) -> None:
        if not self.truncated:
            self.truncated = True
            self.diagnostics.append(
                f"max_chunks={self.max_chunks} reached; walk truncated")

    def add_secondary(self, region: MappedRegion) -> None:
        self.regions.append(HeapRegion(region.va, region.size, region.name,
                                       "secondary"))
        self.diagnostics.append(
            f"{region.name} at {region.va:#x}: secondary LargeBlock headers "
            "are not decoded")

    def layout(self, memory: VaMemory) -> HeapLayout:
        return HeapLayout(
            allocator=AllocatorKind.SCUDO, platform=memory.platform,
            regions=tuple(self.regions), chunks=tuple(self.chunks),
            evidence=tuple(self.evidence), confidence=self._confidence(),
            diagnostics=tuple(self.diagnostics), coverage=self._coverage())

    def _confidence(self) -> float:
        if not self.chunks:
            return 0.0
        return round(sum(c.confidence for c in self.chunks) / len(self.chunks), 3)

    def _coverage(self) -> Dict[str, Any]:
        return {"regions_walked": sum(r.kind == "primary" for r in self.regions),
                "bytes_total": self.bytes_total,
                "bytes_captured": self.bytes_captured,
                "uncaptured_pages": self.uncaptured_pages,
                "chunks": len(self.chunks), "truncated": self.truncated}


# -- region selection -------------------------------------------------------------


def _is_anonymous_rw(region: MappedRegion) -> bool:
    anonymous = not region.name or region.name.startswith("[anon:")
    return "w" in region.perms and anonymous and not region.module_path


def _named(ctx: DetectContext, pattern: str,
           opts: Optional[ParseOptions] = None) -> List[MappedRegion]:
    return [r for r in ctx.regions if name_matches(r.name, pattern)
            and (opts is None or opts.selects(r))]


def _fallback_regions(ctx: DetectContext,
                      opts: Optional[ParseOptions] = None) -> List[MappedRegion]:
    """Anonymous writable regions: where scudo hides without region names."""
    return [r for r in ctx.regions if _is_anonymous_rw(r)
            and not name_matches(r.name, _SECONDARY)
            and (opts is None or opts.selects(r))]


def _plausible(image: _RegionImage) -> bool:
    return sum(r.anchors for r in _class_runs(image)) >= _PROBE_MIN_ANCHORS


def _primary_images(memory: VaMemory, ctx: DetectContext,
                    opts: ParseOptions) -> Tuple[List[_RegionImage], List[str]]:
    named = _named(ctx, _PRIMARY, opts)
    if named:
        return [_read_image(memory, r) for r in named], []
    images = [image for r in _fallback_regions(ctx, opts)
              if _plausible(image := _read_image(memory, r))]
    note = (f"no [anon:scudo:primary] regions; walked {len(images)} "
            "structurally plausible anonymous region(s)")
    return images, [note]


# -- public API -------------------------------------------------------------------


def probe_scudo(ctx: DetectContext) -> DetectScore:
    """Content probe: do scudo headers repeat on a stride in the heap regions?

    Looks at the first :data:`_PROBE_BYTES` of each ``[anon:scudo:primary]``
    region (or, without such names, each anonymous writable region).
    """
    regions = (_named(ctx, _PRIMARY) or _fallback_regions(ctx))
    anchors = slots = 0
    for region in regions[:_PROBE_MAX_REGIONS]:
        for run in _class_runs(_read_image(ctx.memory, region, _PROBE_BYTES)):
            anchors, slots = anchors + run.anchors, slots + run.slots
    return _probe_score(anchors, slots)


def _probe_score(anchors: int, slots: int) -> DetectScore:
    if anchors < _PROBE_MIN_ANCHORS:
        return DetectScore(0.0, [])
    support = min(1.0, anchors / _PROBE_FULL_ANCHORS)
    score = round(_PROBE_CEILING * (anchors / slots) * support, 3)
    detail = f"{anchors}/{slots} stride slots carry plausible scudo headers"
    return DetectScore(score, [Evidence("content", detail, score)])


def parse_scudo(memory: VaMemory, ctx: DetectContext,
                opts: ParseOptions) -> HeapLayout:
    """Walk every scudo primary region (and list the secondary ones)."""
    builder = _LayoutBuilder(max_chunks=opts.max_chunks)
    images, notes = _primary_images(memory, ctx, opts)
    builder.diagnostics.extend(notes)
    for image in images:
        builder.walk(image)
    for region in _named(ctx, _SECONDARY, opts):
        builder.add_secondary(region)
    return builder.layout(memory)


DESCRIPTOR_OVERRIDES: Dict[AllocatorKind, Tuple[DetectFn, ParseFn]] = {
    AllocatorKind.SCUDO: (probe_scudo, parse_scudo),
}

__all__ = ["HEADER_LEN", "ScudoHeader", "structural_score", "probe_scudo",
           "parse_scudo", "DESCRIPTOR_OVERRIDES"]
