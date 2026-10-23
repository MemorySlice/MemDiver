"""Plain data types for the heap allocator layer.

Every allocator parser (``heap/allocators/``) produces the same shapes, so
callers — consensus annotation, ``locate-key`` chunk context, the web "heap"
mode — never need to know which allocator a dump used:

* :class:`HeapChunk` — one allocator chunk / slot, with its byte layout;
* :class:`HeapRegion` — a mapping the allocator owns;
* :class:`FreeList` — one walked free list (tcache bin, fastbin, freelist);
* :class:`Evidence` — why the detector believes in an allocator;
* :class:`HeapLayout` — the whole result, with VA lookups
  (:meth:`HeapLayout.chunk_at`) and a per-byte role projection
  (:meth:`HeapLayout.role_runs`).

ROLES. A byte of a chunk has exactly one :class:`HeapRole`. The default is
derived from the chunk's shape (header bytes, user bytes, slack after the
user bytes) and state (a free chunk's user bytes are stale ``FREE_DATA``);
a parser that knows better — the tcache ``next``/``key`` words at user+0
and user+8 are ``FREE_LINK``, not ``FREE_DATA`` — sets
:attr:`HeapChunk.roles` and those sub-ranges are painted on top.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from itertools import pairwise
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

import numpy as np

from memdiver.heap.platform import TargetPlatform

#: ``(start_va, end_va, role)`` — an absolute, half-open role segment.
_Segment = Tuple[int, int, "HeapRole"]


class AllocatorKind(str, Enum):
    """Which allocator produced a heap layout."""

    PTMALLOC2 = "ptmalloc2"
    DLMALLOC = "dlmalloc"
    SCUDO = "scudo"
    MALLOCNG = "mallocng"
    JEMALLOC = "jemalloc"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class ChunkState(str, Enum):
    """Allocation state of a chunk.

    ``CACHED`` is a chunk parked in a fast cache (tcache, fastbin): its
    in-use bit still says "allocated" although the program freed it.
    """

    IN_USE = "in_use"
    FREE = "free"
    CACHED = "cached"
    QUARANTINED = "quarantined"
    UNKNOWN = "unknown"


class HeapRole(IntEnum):
    """What a heap byte is for. Values are stable (they go into role maps)."""

    NONE = 0
    CHUNK_HEADER = 1
    USER_DATA = 2
    FREE_LINK = 3       # fd/bk, tcache next/key, scudo batch pointers
    FREE_DATA = 4       # stale payload left in a freed chunk
    ALLOCATOR_META = 5  # tcache_perthread_struct, malloc_state, mallocng meta
    TOP = 6
    SLACK = 7
    MIXED = 254         # dumps disagree
    UNCOVERED = 255


_FREED_STATES = frozenset({ChunkState.FREE, ChunkState.CACHED,
                           ChunkState.QUARANTINED})


@dataclass(frozen=True)
class HeapChunk:
    """One allocator chunk.

    ``va``/``size`` span the whole chunk including its header;
    ``user_va``/``user_len`` are the bytes handed to the program.
    ``roles`` optionally overrides the default role derivation with
    ``(offset_from_va, length, role)`` sub-ranges, applied in order.
    """

    va: int
    size: int
    state: ChunkState
    header_len: int
    user_va: int
    user_len: int
    flags: int = 0
    bin: Optional[str] = None
    extra: Mapping[str, Any] = field(default_factory=dict, hash=False)
    confidence: float = 1.0
    roles: Optional[Tuple[Tuple[int, int, HeapRole], ...]] = None

    @property
    def end(self) -> int:
        return self.va + self.size

    def contains(self, va: int) -> bool:
        return self.va <= va < self.end

    def role_segments(self) -> List[_Segment]:
        """Absolute ``(start, end, role)`` segments covering the chunk."""
        layers = self._default_layers() + self._override_layers()
        edges = sorted({max(self.va, min(self.end, edge))
                        for start, end, _ in layers for edge in (start, end)})
        return [(lo, hi, _topmost_role(layers, lo))
                for lo, hi in pairwise(edges) if hi > lo]

    def _default_layers(self) -> List[_Segment]:
        if self.bin == "top":
            return [(self.va, self.end, HeapRole.TOP)]
        if self.extra.get("meta"):
            return [(self.va, self.end, HeapRole.ALLOCATOR_META)]
        user_role = (HeapRole.FREE_DATA if self.state in _FREED_STATES
                     else HeapRole.USER_DATA)
        return [
            (self.va, self.end, HeapRole.SLACK),
            (self.va, self.va + self.header_len, HeapRole.CHUNK_HEADER),
            (self.user_va, self.user_va + self.user_len, user_role),
        ]

    def _override_layers(self) -> List[_Segment]:
        return [(self.va + off, self.va + off + length, HeapRole(role))
                for off, length, role in (self.roles or ())]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "va": self.va, "size": self.size, "state": self.state.value,
            "header_len": self.header_len, "user_va": self.user_va,
            "user_len": self.user_len, "flags": self.flags, "bin": self.bin,
            "extra": _json_safe(dict(self.extra)),
            "confidence": self.confidence,
            "roles": ([[off, length, int(role)] for off, length, role in self.roles]
                      if self.roles is not None else None),
        }


def _topmost_role(layers: Sequence[_Segment], va: int) -> HeapRole:
    """Role of the last-painted layer covering *va* (later layers win)."""
    for start, end, role in reversed(layers):
        if start <= va < end:
            return role
    return HeapRole.NONE


@dataclass(frozen=True)
class HeapRegion:
    """A mapping owned by the allocator (arena, scudo region, mallocng group)."""

    va: int
    size: int
    name: str
    kind: str


@dataclass(frozen=True)
class FreeList:
    """One walked free list. ``decoded`` = safe-linking was undone."""

    kind: str
    index: int
    head_va: int
    chunk_vas: Tuple[int, ...] = ()
    decoded: bool = False
    cycle: bool = False


@dataclass(frozen=True)
class Evidence:
    """One detection signal and how much it counts."""

    source: str
    detail: str
    weight: float


@dataclass
class HeapLayout:
    """A parsed heap: chunks sorted by VA plus the allocator context."""

    allocator: AllocatorKind
    version_hint: Optional[str] = None
    platform: Optional[TargetPlatform] = None
    regions: Tuple[HeapRegion, ...] = ()
    chunks: Tuple[HeapChunk, ...] = ()
    free_lists: Tuple[FreeList, ...] = ()
    evidence: Tuple[Evidence, ...] = ()
    confidence: float = 0.0
    diagnostics: Tuple[str, ...] = ()
    coverage: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.chunks = tuple(sorted(self.chunks, key=lambda c: c.va))
        # uint64 so kernel-half VAs (>= 2**63) still sort and search.
        self._starts = np.fromiter((c.va for c in self.chunks),
                                   dtype=np.uint64, count=len(self.chunks))

    def chunk_at(self, va: int) -> Optional[HeapChunk]:
        """The chunk whose ``[va, va + size)`` contains *va*, else ``None``."""
        if va < 0 or not self.chunks:
            return None
        idx = int(np.searchsorted(self._starts, np.uint64(va), side="right")) - 1
        if idx >= 0 and self.chunks[idx].contains(va):
            return self.chunks[idx]
        return None

    def role_runs(self, lo: int, hi: int) -> Iterator[Tuple[int, int, HeapRole]]:
        """Yield coalesced, non-overlapping ``(va, length, role)`` in [lo, hi).

        Bytes outside every chunk (``NONE``) are omitted, so consecutive runs
        may have gaps between them.
        """
        pending: Optional[List[Any]] = None
        for start, end, role in self._clipped_segments(lo, hi):
            if pending and pending[1] == start and pending[2] == role:
                pending[1] = end
                continue
            if pending:
                yield (pending[0], pending[1] - pending[0], pending[2])
            pending = [start, end, role]
        if pending:
            yield (pending[0], pending[1] - pending[0], pending[2])

    def _clipped_segments(self, lo: int, hi: int) -> Iterator[_Segment]:
        """Chunk segments clipped to [lo, hi), never overlapping each other."""
        floor = lo
        for chunk in self._chunks_overlapping(lo, hi):
            for start, end, role in chunk.role_segments():
                start, end = max(start, floor), min(end, hi)
                if end > start and role != HeapRole.NONE:
                    yield (start, end, role)
                    floor = end

    def _chunks_overlapping(self, lo: int, hi: int) -> Iterator[HeapChunk]:
        if hi <= lo or not self.chunks:
            return
        first = int(np.searchsorted(self._starts, np.uint64(max(lo, 0)),
                                    side="right")) - 1
        for chunk in self.chunks[max(first, 0):]:
            if chunk.va >= hi:
                break
            if chunk.end > lo:
                yield chunk

    def role_counts(self, lo: int, hi: int) -> Dict[str, int]:
        """Byte count per role name (lower-case) in [lo, hi); NONE omitted."""
        counts: Dict[str, int] = {}
        for _va, length, role in self.role_runs(lo, hi):
            key = role.name.lower()
            counts[key] = counts.get(key, 0) + length
        return counts

    def to_dict(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """JSON-safe dict; at most *limit* chunks (all when ``None``)."""
        shown = self.chunks if limit is None else self.chunks[:max(limit, 0)]
        return {
            "allocator": self.allocator.value,
            "version_hint": self.version_hint,
            "platform": asdict(self.platform) if self.platform else None,
            "regions": [asdict(r) for r in self.regions],
            "chunk_count": len(self.chunks),
            "chunks_truncated": len(shown) < len(self.chunks),
            "chunks": [c.to_dict() for c in shown],
            "free_lists": [_free_list_dict(f) for f in self.free_lists],
            "evidence": [asdict(e) for e in self.evidence],
            "confidence": self.confidence,
            "diagnostics": list(self.diagnostics),
            "coverage": _json_safe(self.coverage),
        }


def _free_list_dict(free_list: FreeList) -> Dict[str, Any]:
    data = asdict(free_list)
    data["chunk_vas"] = list(free_list.chunk_vas)
    return data


def _json_safe(value: Any) -> Any:
    """Recursively turn enums/tuples/numpy scalars into JSON-native values."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


__all__ = [
    "AllocatorKind", "ChunkState", "HeapRole", "HeapChunk", "HeapRegion",
    "FreeList", "Evidence", "HeapLayout",
]
