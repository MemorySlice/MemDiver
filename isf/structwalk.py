"""Struct-walk helpers: check layout hypotheses on a kernel view without vol3 symbols (T4.5).

Everything reads through a ``ViewReader`` (``read(va, length) -> bytes`` that
RAISES on bytes the image does not hold, e.g. ``NoIsfKernelAdapter``). A failed
read is recorded as a gap with its reason, never as zeros, and every result
carries the facts needed to tell a complete answer from a truncated one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

CLOSED = "closed"
MAX_NODES = "max_nodes"
UNREADABLE = "unreadable"
NULL = "null"
CYCLE_NOT_THROUGH_HEAD = "cycle_not_through_head"

_PRINTABLE_MIN, _PRINTABLE_MAX = 0x20, 0x7E


class ViewReader(Protocol):
    """Anything that reads captured bytes by VA and raises on anything else."""

    def read(self, address: int, length: int) -> bytes: ...


def _try_read(view: ViewReader, va: int, length: int) -> Tuple[Optional[bytes], Optional[str]]:
    """``(bytes, None)`` or ``(None, reason)``; short reads are failures too."""
    try:
        data = bytes(view.read(va, length))
    except Exception as exc:  # the reader's own error type is not part of the protocol
        return None, f"{type(exc).__name__}: {exc}"
    if len(data) != length:
        return None, f"short read: {len(data)} of {length} bytes at {va:#x}"
    return data, None


def _word(view: ViewReader, va: int, ptr_size: int, endian: str) -> Tuple[Optional[int], Optional[str]]:
    data, reason = _try_read(view, va, ptr_size)
    return (None, reason) if data is None else (int.from_bytes(data, endian), None)


# ---------------------------------------------------------------- list_head walks
@dataclass(frozen=True)
class ListWalk:
    """Result of following a ``list_head`` ring.

    ``nodes`` are container VAs (node - container_off); the head's container is
    ``nodes[0]`` when ``include_head``. ``closed`` is True only when the walk
    returned to the head.
    """

    nodes: Tuple[int, ...]
    closed: bool
    stop_reason: str
    gap: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": list(self.nodes), "count": len(self.nodes), "closed": self.closed,
                "stop_reason": self.stop_reason, "gap": self.gap}


def walk_list(view: ViewReader, head_va: int, next_off: int, *, max_nodes: int = 10000,
              ptr_size: int = 8, endian: str = "little", container_off: int = 0,
              include_head: bool = True) -> ListWalk:
    """Follow ``next`` pointers from ``head_va`` (Linux ``list_head``) until back at the head.

    ``head_va`` is the address of a ``list_head``; ``next_off`` is the offset of
    the next pointer inside it (0 for ``list_head``). ``include_head`` counts the
    head's container as the first node (right for a ring of embedded nodes whose
    head is itself one, like ``init_task.tasks``); pass False for a standalone head.
    """
    nodes: List[int] = [head_va - container_off] if include_head else []
    seen = {head_va}
    node = head_va
    while True:
        nxt, reason = _word(view, node + next_off, ptr_size, endian)
        if nxt is None:
            return ListWalk(tuple(nodes), False, UNREADABLE,
                            {"va": node + next_off, "reason": reason})
        if nxt == head_va:
            return ListWalk(tuple(nodes), True, CLOSED)
        if nxt == 0:
            return ListWalk(tuple(nodes), False, NULL)
        if nxt in seen:
            return ListWalk(tuple(nodes), False, CYCLE_NOT_THROUGH_HEAD)
        if len(nodes) >= max_nodes:
            return ListWalk(tuple(nodes), False, MAX_NODES)
        seen.add(nxt)
        nodes.append(nxt - container_off)
        node = nxt


@dataclass(frozen=True)
class CycleScan:
    """Candidate in-region offsets whose pointer chains close into rings."""

    candidates: Tuple[Dict[str, Any], ...]   # {offset, ring_len, sample_nodes}
    truncated: bool                          # work budget hit: later offsets not tried
    scanned: int                             # offsets examined
    unreadable_offsets: int                  # offsets whose own word could not be read

    def to_dict(self) -> Dict[str, Any]:
        return {"candidates": [dict(c) for c in self.candidates], "truncated": self.truncated,
                "scanned": self.scanned, "unreadable_offsets": self.unreadable_offsets}


def find_list_cycles(view: ViewReader, region_va: int, length: int, *, ptr_size: int = 8,
                     min_len: int = 3, max_len: int = 4096, stride: int = 8,
                     endian: str = "little", max_work: int = 200_000,
                     sample: int = 4) -> CycleScan:
    """Offsets ``o`` in ``[0, length)`` where ``*(region_va+o)`` heads a closed ring.

    The ring is followed as a ``list_head`` (next at offset 0) and must return to
    ``region_va+o`` within ``max_len`` nodes, with at least ``min_len`` nodes. Total
    pointer reads are bounded by ``max_work``; ``truncated`` says it was hit. A chain
    still unclosed after ``max_len`` nodes is reported (never dropped) as a candidate
    with ``ring_len_exceeds_max: True`` (``ring_len`` is then only a lower bound).
    """
    found: List[Dict[str, Any]] = []
    budget, scanned, unreadable, truncated = max_work, 0, 0, False
    for offset in range(0, max(length - ptr_size, -1) + 1, stride):
        if budget <= 0:
            truncated = True
            break
        scanned += 1
        head = region_va + offset
        value, _ = _word(view, head, ptr_size, endian)
        if value is None:
            unreadable += 1
            continue
        if value == 0:
            continue
        walk = walk_list(view, head, 0, max_nodes=max_len, ptr_size=ptr_size, endian=endian)
        budget -= len(walk.nodes) + 1
        if walk.stop_reason == MAX_NODES and len(walk.nodes) >= min_len:
            found.append({"offset": offset, "ring_len": len(walk.nodes),
                          "ring_len_exceeds_max": True,
                          "sample_nodes": list(walk.nodes[:sample])})
        elif walk.closed and len(walk.nodes) >= min_len:
            found.append({"offset": offset, "ring_len": len(walk.nodes),
                          "sample_nodes": list(walk.nodes[:sample])})
    return CycleScan(tuple(found), truncated, scanned, unreadable)


# ------------------------------------------------------------------ struct rendering
def _sections(draft: Any) -> Tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    """``(user_types, base_types, enums)`` from an ``IsfDraft`` or a plain ISF dict."""
    if isinstance(draft, Mapping):
        return (draft.get("user_types") or {}, draft.get("base_types") or {},
                draft.get("enums") or {})
    return draft.user_types, draft.base_types, draft.enums


class _Types:
    def __init__(self, draft: Any) -> None:
        self.user, self.base, self.enums = _sections(draft)

    def size(self, t: Mapping[str, Any]) -> Optional[int]:
        kind = t.get("kind")
        if kind in ("base", "enum"):
            table = self.base if kind == "base" else self.enums
            size = (table.get(t.get("name")) or {}).get("size")
            return size if isinstance(size, int) else None
        if kind == "pointer":
            size = (self.base.get("pointer") or {}).get("size")
            return size if isinstance(size, int) else None
        if kind == "bitfield":
            return self.size(t.get("type") or {})
        if kind == "array":
            elem, count = self.size(t.get("subtype") or {}), t.get("count")
            return elem * count if elem is not None and isinstance(count, int) else None
        if kind in ("struct", "union"):
            size = (self.user.get(t.get("name")) or {}).get("size")
            return size if isinstance(size, int) else None
        return None

    def signed(self, t: Mapping[str, Any]) -> bool:
        if t.get("kind") == "base":
            return bool((self.base.get(t.get("name")) or {}).get("signed"))
        if t.get("kind") == "bitfield":
            return self.signed(t.get("type") or {})
        return False

    def endian(self, t: Mapping[str, Any]) -> str:
        if t.get("kind") == "base":
            return (self.base.get(t.get("name")) or {}).get("endian") or "little"
        if t.get("kind") == "pointer":
            return (self.base.get("pointer") or {}).get("endian") or "little"
        if t.get("kind") == "enum":
            enum = self.enums.get(t.get("name")) or {}
            base = self.base.get(enum.get("base")) or {}
            return base.get("endian") or (self.base.get("pointer") or {}).get("endian") \
                or "little"
        return "little"


def _type_label(t: Mapping[str, Any]) -> str:
    kind = t.get("kind")
    if kind == "array":
        return f"{_type_label(t.get('subtype') or {})}[{t.get('count')}]"
    if kind == "pointer":
        return f"{_type_label(t.get('subtype') or {})} *" if t.get("subtype") else "void *"
    if kind == "bitfield":
        return f"{_type_label(t.get('type') or {})}:{t.get('bit_length')}"
    return str(t.get("name") or kind or "?")


def _char_array(t: Mapping[str, Any], types: _Types) -> bool:
    sub = t.get("subtype") or {}
    return (t.get("kind") == "array" and sub.get("kind") == "base"
            and sub.get("name") in ("char", "unsigned char", "signed char")
            and types.size(sub) == 1)


def _decode(raw: bytes, t: Mapping[str, Any], types: _Types) -> Any:
    kind = t.get("kind")
    if _char_array(t, types):
        text = raw.split(b"\x00", 1)[0]
        return text.decode("ascii", "replace") if all(
            _PRINTABLE_MIN <= b <= _PRINTABLE_MAX for b in text) else None
    if kind == "pointer" or kind == "enum":
        return int.from_bytes(raw, types.endian(t))
    if kind == "base":
        base_kind = (types.base.get(t.get("name")) or {}).get("kind")
        if base_kind == "bool":
            return bool(int.from_bytes(raw, types.endian(t)))
        if base_kind in ("int", "char", None):
            return int.from_bytes(raw, types.endian(t), signed=types.signed(t))
    if kind == "bitfield":
        inner = t.get("type") or {}
        value = int.from_bytes(raw, types.endian(inner), signed=False)
        value = (value >> int(t.get("bit_position", 0))) & ((1 << int(t["bit_length"])) - 1)
        return value
    return None  # struct/union/array of non-chars/float: raw bytes only


def render_struct(view: ViewReader, va: int, draft: Any, struct: str) -> Dict[str, Any]:
    """Decode ``struct`` at ``va`` using ``draft`` (an ``IsfDraft`` or an ISF dict).

    Each field reports ``raw_hex`` and, for ints/pointers/enums/bitfields/char
    arrays, a decoded ``value``; unknown or unsized types carry raw bytes (or
    nothing, if unsized) and ``value`` None. ``coverage`` is ``full`` / ``partial`` /
    ``none`` (per field: ``full`` / ``gap`` / ``unsized``); an unreadable field
    carries ``gap_reason`` and NO bytes, never zeros.
    """
    types = _Types(draft)
    definition = types.user.get(struct)
    if definition is None:
        raise KeyError(f"struct {struct!r} is not defined in the draft")
    size = definition.get("size")
    whole, _ = _try_read(view, va, size) if isinstance(size, int) and size > 0 else (None, None)
    fields: List[Dict[str, Any]] = []
    for name, spec in sorted((definition.get("fields") or {}).items(),
                             key=lambda kv: kv[1].get("offset", 0)):
        fields.append(_render_field(view, va, name, spec, types, whole))
    return {"struct": struct, "va": va, "size": size, "fields": fields,
            "coverage": _struct_coverage(fields)}


def _render_field(view: ViewReader, va: int, name: str, spec: Mapping[str, Any],
                  types: _Types, whole: Optional[bytes]) -> Dict[str, Any]:
    t, offset = spec.get("type") or {}, int(spec.get("offset", 0))
    out: Dict[str, Any] = {"name": name, "offset": offset, "type": _type_label(t),
                           "raw_hex": None, "value": None, "coverage": "unsized"}
    width = types.size(t)
    if width is None:
        return out
    raw, reason = (whole[offset:offset + width], None) if whole is not None \
        and offset + width <= len(whole) else _try_read(view, va + offset, width)
    if raw is None:
        out.update(coverage="gap", gap_reason=reason)
        return out
    out.update(raw_hex=raw.hex(), coverage="full", value=_decode(raw, t, types))
    return out


def _struct_coverage(fields: Sequence[Mapping[str, Any]]) -> str:
    states = {f["coverage"] for f in fields if f["coverage"] != "unsized"}
    if not states:
        return "none"
    if states == {"full"}:
        return "full"
    return "none" if states == {"gap"} else "partial"


# ------------------------------------------------- thin wrappers over pakunoda walkers
@dataclass(frozen=True)
class TreeWalk:
    """``nodes`` is None when the structure is not a well-formed tree OR a read failed."""

    nodes: Optional[Tuple[int, ...]]
    gap: Optional[Dict[str, Any]] = None

    @property
    def ok(self) -> bool:
        return self.nodes is not None


class _Gaps:
    """Records the first failed read so a None from pakunoda can be explained."""

    def __init__(self, view: ViewReader, ptr_size: int, endian: str) -> None:
        self.view, self.ptr_size, self.endian = view, ptr_size, endian
        self.gap: Optional[Dict[str, Any]] = None

    def word(self, va: int) -> Optional[int]:
        value, reason = _word(self.view, va, self.ptr_size, self.endian)
        if value is None and self.gap is None:
            self.gap = {"va": va, "reason": reason}
        return value

    # pakunoda ``ModuleReads`` surface
    ptr = word

    def raw(self, va: int, length: int) -> Optional[bytes]:
        data, reason = _try_read(self.view, va, length)
        if data is None and self.gap is None:
            self.gap = {"va": va, "reason": reason}
        return data

    def u32(self, va: int) -> Optional[int]:
        data = self.raw(va, 4)
        return None if data is None else int.from_bytes(data, self.endian)


def walk_rbtree_view(view: ViewReader, root_node_va: Optional[int], *, left_off: int,
                     right_off: int, max_nodes: int = 100_000, ptr_size: int = 8,
                     endian: str = "little") -> TreeWalk:
    """pakunoda ``walk_rbtree`` over a view: in-order ``rb_node`` VAs of ``rb_root.rb_node``."""
    from pakunoda.recovery.rbtree import walk_rbtree

    reads = _Gaps(view, ptr_size, endian)
    nodes = walk_rbtree(root_node_va, read_ptr_at=reads.word, left_off=left_off,
                        right_off=right_off, max_nodes=max_nodes)
    return TreeWalk(nodes, reads.gap)


def walk_xarray_view(view: ViewReader, xa_head: int, layout: Any, *, max_entries: int = 100_000,
                     ptr_size: int = 8, endian: str = "little") -> Tuple[Optional[Tuple[Tuple[int, int], ...]], Optional[Dict[str, Any]]]:
    """pakunoda ``walk_xarray`` over a view: ``((index, entry), ...)`` or None, plus first gap.

    ``layout`` is a pakunoda ``XaNodeLayout``.
    """
    from pakunoda.recovery.xarray import walk_xarray

    reads = _Gaps(view, ptr_size, endian)
    entries = walk_xarray(xa_head, reads=reads, layout=layout, max_entries=max_entries)
    return entries, reads.gap
