"""Build an :class:`~memdiver.architect.artifact_model.ArtifactModel` from a layout proposal.

The analyst (or agent) decides WHICH proposed fields mean what and how they
relate; this module turns those decisions plus the evidence already computed
(:mod:`engine.anchor_consensus`, :mod:`engine.layout_proposal`) into a model the
exporter can deploy on one image (P5).

**The prefilter is chosen for distinctiveness, not size.** A window of
invariant bytes is only a detector if those bytes are informative: the corpus
proved that a constant 64-byte pad of zeros matched 825,779 times (memory
``reference_vol3_runtime_and_corpus_facts``). So :func:`select_prefilter`
scores each candidate window by its invariant bytes that are NOT ``00``/``ff``,
weighted by how many distinct values they take, and only inside the proposed
object when bounds are known. Whether the chosen window is actually unique is
an empirical question answered by the held-out run, never assumed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple

import numpy as np

from memdiver.architect.artifact_model import (
    Applicability, ArtifactModel, Assertion, Evidence, Locator, Relationship, Validation,
)
from memdiver.core.variance import ByteClass
from memdiver.engine.anchor_consensus import AnchorConsensus
from memdiver.engine.layout_proposal import LayoutProposal

DEFAULT_PREFILTER = 64
_UNINFORMATIVE = (0x00, 0xFF)


@dataclass(frozen=True)
class Prefilter:
    delta: int            # window start relative to the anchor
    length: int
    informative_bytes: int
    pattern: Dict[str, object]


def select_prefilter(consensus: AnchorConsensus, *, anchor_length: int,
                     length: int = DEFAULT_PREFILTER, name: str = "artifact",
                     within: Optional[Tuple[int, int]] = None,
                     exclude: Sequence[Tuple[int, int]] = ()) -> Prefilter:
    """The most informative invariant window (delta range *within*, half-open).

    *exclude* lists ``(delta, length)`` spans that must never be matched
    literally -- the proposed POINTER fields. A pointer can be invariant across
    one corpus only because the platform's address space is (the ``aa`` of an
    aarch64 heap pointer ``0xaaaa...``); matching it would tie the detector to
    that platform/layout instead of the object. Those bytes become ``??``.
    """
    reference = np.frombuffer(consensus.instances[0].data, dtype=np.uint8)
    static = _static_mask(consensus, exclude)
    useful = static & ~np.isin(reference, _UNINFORMATIVE)
    lo, hi = _search_span(consensus, within, length)
    sums = np.concatenate(([0], np.cumsum(useful[lo:hi])))
    scores = sums[length:] - sums[:-length]
    if scores.size == 0 or scores.max() == 0:
        raise ValueError("no window holds an informative invariant byte; no single-image prefilter")
    start = lo + int(np.argmax(scores))
    pattern = _pattern_dict(consensus, reference, static, start, length, anchor_length, name)
    return Prefilter(delta=consensus.delta_start + start, length=length,
                     informative_bytes=int(scores.max()), pattern=pattern)


def _informative_mask(consensus: AnchorConsensus, reference: np.ndarray) -> np.ndarray:
    invariant = consensus.classes == int(ByteClass.INVARIANT)
    return invariant & ~np.isin(reference, _UNINFORMATIVE)


def _static_mask(consensus: AnchorConsensus, exclude: Sequence[Tuple[int, int]]) -> np.ndarray:
    """Invariant positions that may be matched literally (excluded spans are not)."""
    static = consensus.classes == int(ByteClass.INVARIANT)
    for delta, span in exclude:
        lo = max(0, delta - consensus.delta_start)
        static[lo:max(lo, delta - consensus.delta_start + span)] = False
    return static


def _search_span(consensus: AnchorConsensus, within: Optional[Tuple[int, int]],
                 length: int) -> Tuple[int, int]:
    lo, hi = 0, consensus.length
    if within is not None:
        lo = max(lo, within[0] - consensus.delta_start)
        hi = min(hi, within[1] - consensus.delta_start)
    if hi - lo < length:
        raise ValueError(f"search span of {hi - lo} bytes is shorter than the {length}-byte prefilter")
    return lo, hi


def _pattern_dict(consensus: AnchorConsensus, reference: np.ndarray, static_mask: np.ndarray,
                  start: int, length: int, anchor_length: int, name: str) -> Dict[str, object]:
    window = reference[start:start + length]
    static = static_mask[start:start + length]
    tokens = [f"{b:02x}" if s else "??" for b, s in zip(window.tolist(), static.tolist())]
    count = int(static.sum())
    return {"name": name, "length": length, "hex_pattern": " ".join(f"{b:02x}" for b in window.tolist()),
            "wildcard_pattern": " ".join(tokens), "static_ratio": round(count / length, 4),
            "static_count": count, "volatile_count": length - count,
            "key_offset": -(consensus.delta_start + start), "key_length": anchor_length}


@dataclass(frozen=True)
class FieldMeaning:
    """The caller's decision about one proposed field (by proposal name)."""

    field: str
    meaning: str
    label: str = ""
    support: Tuple[Evidence, ...] = ()


def build_structure_model(consensus: AnchorConsensus, proposal: LayoutProposal, *, name: str,
                          anchor_length: int, meanings: Sequence[FieldMeaning],
                          relationships: Sequence[Tuple[str, str, str]] = (),
                          applicability: Applicability = Applicability(),
                          prefilter_length: int = DEFAULT_PREFILTER) -> ArtifactModel:
    """A ``structure``-locator model; *relationships* are ``(kind, source, target)``."""
    layout = proposal.to_structure(name, library=applicability.library or None)
    within = _object_span(proposal)
    pointers = [(f.delta, f.length) for f in proposal.fields if f.kind == "pointer"]
    prefilter = select_prefilter(consensus, anchor_length=anchor_length, length=prefilter_length,
                                 name=name, within=within, exclude=pointers)
    anchor = _anchor_field_name(proposal)
    model = ArtifactModel(
        name=name, layout=layout, applicability=applicability,
        locator=Locator(kind="structure", pattern=prefilter.pattern, anchor_field=anchor),
        assertions=tuple(Assertion(m.field, m.meaning, m.label, m.support) for m in meanings),
        relationships=tuple(_relationship(proposal, consensus, *r) for r in relationships),
        validation=Validation(learned_on=tuple(w.anchor.dump_path for w in consensus.instances)),
        description=f"learned from {len(consensus.instances)} instances; prefilter "
                    f"{prefilter.informative_bytes} informative bytes at delta {prefilter.delta}")
    problems = model.check()
    if problems:
        raise ValueError("inconsistent artifact model: " + "; ".join(problems))
    return model


def _object_span(proposal: LayoutProposal) -> Optional[Tuple[int, int]]:
    if proposal.base_delta is None or proposal.total_size is None:
        return None
    return proposal.base_delta, proposal.base_delta + proposal.total_size


def _anchor_field_name(proposal: LayoutProposal) -> str:
    anchor = next(f for f in proposal.fields if f.kind == "anchor")
    return str(anchor.to_dict()["name"])


def _relationship(proposal: LayoutProposal, consensus: AnchorConsensus, kind: str,
                  source: str, target: str) -> Relationship:
    by_name = {str(f.to_dict()["name"]): f for f in proposal.fields}
    if source not in by_name or target not in by_name:
        raise ValueError(f"relationship {kind} names an unproposed field: {source!r} -> {target!r}")
    src, dst = by_name[source], by_name[target]
    evidence = tuple(Evidence("consensus", e) for e in dst.evidence + src.evidence)
    return Relationship(kind=kind, source=source, target=target, delta=dst.delta - src.delta,
                        description=f"{target} at {dst.delta - src.delta:+#x} from {source} "
                                    f"in {len(consensus.instances)} instances",
                        support=evidence)
