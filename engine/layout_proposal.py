"""propose_layout — field-boundary hypotheses around a verified anchor.

Input is an :class:`~memdiver.engine.anchor_consensus.AnchorConsensus`: N
instances of one object, each window aligned on its own verified anchor. From
it this module proposes WHERE fields are and WHAT KIND they might be, with the
evidence for each proposal:

* **anchor** -- the verified artifact itself (``anchor_length`` bytes at delta 0).
* **verified_field** -- another verified value (e.g. the session's
  client_random) found in EVERY instance at the SAME delta. A constant delta
  across independently allocated instances is the strongest same-object
  evidence available without code.
* **pointer** -- an 8-byte, VA-aligned word whose value lies inside a
  captured run of the same capture in at least ``pointer_quorum`` of the
  instances.
* **constant** / **small_set** / **variable** / **undetermined** -- the
  remaining bytes, split by consensus class (memo §5). These are evidence of
  segmentation, NOT fields: adjacent bytes of one class need not be one field,
  and one field can span classes, so a long ``variable`` run carries the
  alternative "several fields".
* **object bounds** -- when an allocator chunk contains the anchor in every
  instance at the same delta, the chunk's user range is proposed as the object.

Circularity guard (memo §4): the proposal never feeds back into which
instances correspond; correspondence is fixed by the anchors' ``basis``, and
the alternatives are preserved so a held-out test can reject them.

Pure engine: callers hand in callables for the per-capture facts
(``captured_runs_of``, ``chunk_of``) so this module never opens a dump.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np

from memdiver.core.structure_defs import FieldDef, FieldType, StructureDef
from memdiver.engine.anchor_consensus import AnchorConsensus, CLASS_NAMES, UNDETERMINED

WORD = 8
SMALL_SET_MAX = 4

# (va_start, length) runs of one capture; (user_va, user_len) of a chunk.
RunsOf = Callable[[int], Sequence[Tuple[int, int]]]
ChunkOf = Callable[[int, int], Optional[Tuple[int, int]]]


@dataclass
class FieldProposal:
    delta: int
    length: int
    kind: str
    evidence: List[str] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)
    name: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {"delta": self.delta, "length": self.length, "kind": self.kind,
                "name": self.name or f"{self.kind}_{_signed_hex(self.delta)}",
                "evidence": list(self.evidence), "alternatives": list(self.alternatives)}


@dataclass
class LayoutProposal:
    """Field proposals keyed by delta from the anchor, plus object bounds."""

    fields: List[FieldProposal]
    base_delta: Optional[int] = None   # object start relative to the anchor
    total_size: Optional[int] = None
    bounds_evidence: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"base_delta": self.base_delta, "total_size": self.total_size,
                "bounds_evidence": list(self.bounds_evidence), "warnings": list(self.warnings),
                "fields": [f.to_dict() for f in self.fields]}

    def to_structure(self, name: str, *, library: Optional[str] = None) -> StructureDef:
        """A StructureDef over the proposed object (fields re-based to its start).

        Without object bounds the window itself is the structure and the
        window start is the base; fields outside the bounds are dropped."""
        base = self.base_delta if self.base_delta is not None else min(f.delta for f in self.fields)
        size = self.total_size or (max(f.delta + f.length for f in self.fields) - base)
        defs = tuple(_field_def(f, base) for f in self.fields
                     if f.kind != "undetermined" and base <= f.delta and f.delta + f.length <= base + size)
        return StructureDef(name=name, total_size=size, fields=defs, library=library,
                            stability="experimental", description="proposed by propose_layout")


def propose_layout(consensus: AnchorConsensus, *, anchor_length: int,
                   related: Optional[Dict[str, Sequence[Optional[bytes]]]] = None,
                   captured_runs_of: Optional[RunsOf] = None,
                   chunk_of: Optional[ChunkOf] = None,
                   pointer_quorum: Optional[int] = None) -> LayoutProposal:
    """Propose fields around the anchor; see the module docstring for the kinds.

    *related* maps a name to one needle per instance (None where unknown).
    The window must contain the anchor (``delta_start <= 0`` and
    ``delta_start + length >= anchor_length``): the anchor field is claimed
    at delta 0 and would otherwise steal bytes that are not the anchor's.
    """
    _require_anchor_in_window(consensus, anchor_length)
    warnings: List[str] = []
    claimed = np.zeros(consensus.length, dtype=bool)
    fields = [_claim(consensus, claimed, 0, anchor_length, "anchor", "anchor",
                     ["verified artifact (the anchors' basis)"])]
    for name, needles in (related or {}).items():
        fields += _verified_fields(consensus, claimed, name, needles)
    if captured_runs_of is not None:
        quorum = pointer_quorum or len(consensus.instances)
        fields += _pointer_fields(consensus, claimed, captured_runs_of, quorum, warnings)
    fields += _class_fields(consensus, claimed)
    proposal = LayoutProposal(fields=sorted(fields, key=lambda f: f.delta), warnings=warnings)
    if chunk_of is not None:
        _propose_bounds(consensus, proposal, chunk_of)
    return proposal


def _require_anchor_in_window(consensus: AnchorConsensus, anchor_length: int) -> None:
    start, end = consensus.delta_start, consensus.delta_start + consensus.length
    if start > 0 or end < anchor_length:
        raise ValueError(
            f"window [{start}, {end}) must contain the anchor [0, {anchor_length}): "
            "need delta_start <= 0 and delta_start + length >= anchor_length")


# -- verified co-located values ------------------------------------------------

def _verified_fields(consensus: AnchorConsensus, claimed: np.ndarray, name: str,
                     needles: Sequence[Optional[bytes]]) -> List[FieldProposal]:
    deltas = [_find_in_window(w.data, w.captured, n) for w, n in zip(consensus.instances, needles)]
    known = [d for d in deltas if d is not None]
    if not known or len(set(known)) != 1 or len(known) != len(consensus.instances):
        return []
    offset, length = known[0], len(next(n for n in needles if n))
    evidence = [f"{name} found at the same delta in {len(known)}/{len(known)} instances"]
    return [_claim(consensus, claimed, consensus.delta_start + offset, length,
                   "verified_field", name, evidence)]


def _find_in_window(data: bytes, captured: np.ndarray, needle: Optional[bytes]) -> Optional[int]:
    """Window offset of the single captured occurrence of *needle* (None if 0 or >1)."""
    if not needle:
        return None
    first = data.find(needle)
    if first < 0 or data.find(needle, first + 1) >= 0:
        return None
    return first if bool(captured[first:first + len(needle)].all()) else None


# -- pointers -------------------------------------------------------------------

def _pointer_fields(consensus: AnchorConsensus, claimed: np.ndarray, runs_of: RunsOf,
                    quorum: int, warnings: Optional[List[str]] = None) -> List[FieldProposal]:
    phases = _instance_phases(consensus)
    if warnings is not None and len(set(phases)) > 1:
        warnings.append("anchor VAs differ mod 8 across instances (alignment phases "
                        f"{sorted(set(phases))}); a pointer word votes only for the "
                        "instances where it is VA-aligned")
    out: List[FieldProposal] = []
    for phase in sorted(set(phases), key=lambda p: (p != phases[0], p)):
        voters = [i for i, p in enumerate(phases) if p == phase]
        for start in range(phase, consensus.length - WORD + 1, WORD):
            if claimed[start:start + WORD].any():
                continue
            hits = _pointer_votes(consensus, start, runs_of, voters)
            if hits >= quorum:
                out.append(_claim(consensus, claimed, consensus.delta_start + start, WORD,
                                  "pointer", "",
                                  [f"value inside a captured run in {hits}/{len(consensus.instances)} instances"]))
    return out


def _instance_phases(consensus: AnchorConsensus) -> List[int]:
    """Per instance: window offset of its first VA-aligned word (VA-less → 0)."""
    return [0 if w.anchor.va is None else (-(w.anchor.va + consensus.delta_start)) % WORD
            for w in consensus.instances]


def _pointer_votes(consensus: AnchorConsensus, start: int, runs_of: RunsOf,
                   voters: Optional[Sequence[int]] = None) -> int:
    votes = 0
    for index in (range(len(consensus.instances)) if voters is None else voters):
        window = consensus.instances[index]
        if not window.captured[start:start + WORD].all():
            continue
        value = int.from_bytes(window.data[start:start + WORD], "little")
        votes += any(va <= value < va + n for va, n in runs_of(index))
    return votes


# -- consensus-class segmentation -------------------------------------------------

def _class_fields(consensus: AnchorConsensus, claimed: np.ndarray) -> List[FieldProposal]:
    out: List[FieldProposal] = []
    for start, end in _unclaimed_runs(claimed):
        for region in _regions_in(consensus, start, end):
            out.append(_segment_field(consensus, *region))
    return out


def _unclaimed_runs(claimed: np.ndarray) -> List[Tuple[int, int]]:
    free = np.flatnonzero(~claimed)
    if free.size == 0:
        return []
    breaks = np.flatnonzero(np.diff(free) != 1)
    starts = np.concatenate(([free[0]], free[breaks + 1]))
    ends = np.concatenate((free[breaks] + 1, [free[-1] + 1]))
    return list(zip(starts.tolist(), ends.tolist()))


def _regions_in(consensus: AnchorConsensus, start: int, end: int) -> List[Tuple[int, int, str]]:
    kinds = [_segment_kind(consensus, i) for i in range(start, end)]
    out, run_start = [], start
    for i in range(start + 1, end + 1):
        if i == end or kinds[i - start] != kinds[run_start - start]:
            out.append((run_start, i, kinds[run_start - start]))
            run_start = i
    return out


def _segment_kind(consensus: AnchorConsensus, i: int) -> str:
    code = int(consensus.classes[i])
    if code == UNDETERMINED:
        return "undetermined"
    if CLASS_NAMES[code] == "invariant":
        return "constant"
    if int(consensus.distinct_values[i]) <= min(SMALL_SET_MAX, len(consensus.instances) // 2):
        return "small_set"
    return "variable"


def _segment_field(consensus: AnchorConsensus, start: int, end: int, kind: str) -> FieldProposal:
    proposal = FieldProposal(delta=consensus.delta_start + start, length=end - start, kind=kind,
                             evidence=[f"consensus class run over {len(consensus.instances)} instances"])
    if kind in ("variable", "small_set") and end - start > WORD:
        proposal.alternatives.append("several adjacent fields sharing a variance class")
    if kind == "constant":
        proposal.alternatives.append("constant field, padding, or an input the experiment did not vary")
    return proposal


# -- object bounds -------------------------------------------------------------------

def _propose_bounds(consensus: AnchorConsensus, proposal: LayoutProposal, chunk_of: ChunkOf) -> None:
    spans = [chunk_of(i, w.anchor.va) if w.anchor.va is not None else None
             for i, w in enumerate(consensus.instances)]
    if any(s is None for s in spans):
        proposal.warnings.append("no allocator chunk contains the anchor in every instance")
        return
    shapes = {(user_va - w.anchor.va, size) for (user_va, size), w in zip(spans, consensus.instances)}
    if len(shapes) != 1:
        proposal.warnings.append(f"allocator chunks disagree across instances: {sorted(shapes)[:4]}")
        return
    (proposal.base_delta, proposal.total_size), = shapes
    proposal.bounds_evidence.append(
        f"anchor at user+{-proposal.base_delta:#x} of a {proposal.total_size:#x}-byte chunk "
        f"in {len(spans)}/{len(spans)} instances")


# -- helpers ----------------------------------------------------------------------------

def _claim(consensus: AnchorConsensus, claimed: np.ndarray, delta: int, length: int,
           kind: str, name: str, evidence: List[str]) -> FieldProposal:
    lo = delta - consensus.delta_start
    if lo < 0 or lo + length > consensus.length:
        raise ValueError(f"{kind} span [{delta}, {delta + length}) is outside the window")
    claimed[lo:lo + length] = True
    return FieldProposal(delta=delta, length=length, kind=kind, evidence=evidence, name=name)


def _field_def(f: FieldProposal, base: int) -> FieldDef:
    ftype = FieldType.POINTER if f.kind == "pointer" else FieldType.BYTES
    constraints = {"not_zero": True} if f.kind in ("anchor", "verified_field") else {}
    d = f.to_dict()
    return FieldDef(name=str(d["name"]), field_type=ftype, offset=f.delta - base, size=f.length,
                    description=f"{f.kind}: {'; '.join(f.evidence)}", constraints=constraints)


def _signed_hex(value: int) -> str:
    return f"m{-value:x}" if value < 0 else f"p{value:x}"
