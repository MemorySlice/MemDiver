"""Artifact model — what a learned artifact is, how to find it, and why we believe it.

A pattern dict (``PatternGenerator.generate``) says only "these bytes, with
these wildcards, surround a key". The artifact model (memo §7, plan T5.4)
wraps that locator with everything a deployable extractor and its reviewer
need:

``locator``
    How instances are found in ONE new image (P5: no corpus, no agent).
    ``kind="byte_pattern"`` is today's exporter input verbatim;
    ``kind="structure"`` uses the same pattern as a PREFILTER and then decodes
    the ``layout`` around each hit.
``layout``
    A :class:`~memdiver.core.structure_defs.StructureDef` plus which field the
    locator lands on (``anchor_field``); the structure base is
    ``hit + pattern.key_offset - anchor_field.offset``.
``relationships``
    Facts linking fields: ``owned_by`` (field X belongs to the object
    identified by field Y, e.g. a TLS secret and its session's
    client_random), ``same_object`` (constant delta inside one object),
    ``pointer`` (a field holds the VA of another object).
``assertions``
    What a field means (``meaning``) and the label it is reported under,
    each with its ``support`` -- hypotheses with evidence, never bare labels.
``applicability``
    Builds/architectures/states it was learned for; outside them it is untested.
``validation``
    The captures it was learned on and per-capture HELD-OUT results (P4).

Stdlib + ``core`` only, so the exporter, the engine and every surface can
share it. JSON is the exchange form (``to_dict``/``from_dict``); ``check()``
lists every inconsistency instead of stopping at the first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from memdiver.core.structure_defs import FieldDef, FieldType, StructureDef

SCHEMA = "memdiver.artifact_model/1"
LOCATOR_KINDS = ("byte_pattern", "structure")
RELATIONSHIP_KINDS = ("owned_by", "same_object", "pointer")


@dataclass(frozen=True)
class Evidence:
    """One piece of support: ``kind`` slug (``consensus``, ``ground_truth``,
    ``code``, ``experiment``, ``entry``...) and a ``ref`` pointing at it."""

    kind: str
    ref: str


@dataclass(frozen=True)
class Locator:
    kind: str
    pattern: Dict[str, Any]
    anchor_field: Optional[str] = None


@dataclass(frozen=True)
class Relationship:
    kind: str
    source: str
    target: str
    delta: Optional[int] = None
    description: str = ""
    support: Tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Assertion:
    field: str
    meaning: str
    label: str = ""
    support: Tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Applicability:
    library: str = ""
    library_version: str = ""
    arch: str = ""
    os: str = ""
    states: Tuple[str, ...] = ()
    cohorts: Tuple[str, ...] = ()


@dataclass(frozen=True)
class HeldOutResult:
    """One held-out capture: what was expected, what the extractor returned."""

    capture: str
    expected: int
    true_positives: int
    false_positives: int
    false_negatives: int
    relationships_correct: int = 0
    relationships_checked: int = 0
    detail: str = ""


@dataclass(frozen=True)
class Validation:
    learned_on: Tuple[str, ...] = ()
    held_out: Tuple[HeldOutResult, ...] = ()
    verdict: str = "untested"  # untested | pass | fail | indeterminate


@dataclass(frozen=True)
class ArtifactModel:
    name: str
    locator: Locator
    layout: Optional[StructureDef] = None
    relationships: Tuple[Relationship, ...] = ()
    assertions: Tuple[Assertion, ...] = ()
    applicability: Applicability = field(default_factory=Applicability)
    validation: Validation = field(default_factory=Validation)
    description: str = ""

    def field_names(self) -> Tuple[str, ...]:
        return tuple(f.name for f in self.layout.fields) if self.layout else ()

    def check(self) -> List[str]:
        """Every inconsistency, as human-readable problems (empty = valid)."""
        return _locator_problems(self) + _reference_problems(self)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA, "name": self.name, "description": self.description,
            "locator": _locator_dict(self.locator),
            "layout": None if self.layout is None else structure_to_dict(self.layout),
            "relationships": [_relationship_dict(r) for r in self.relationships],
            "assertions": [_assertion_dict(a) for a in self.assertions],
            "applicability": _applicability_dict(self.applicability),
            "validation": _validation_dict(self.validation),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ArtifactModel":
        if data.get("schema") != SCHEMA:
            raise ValueError(f"not an artifact model (schema {data.get('schema')!r}, want {SCHEMA!r})")
        layout = data.get("layout")
        return cls(
            name=str(data["name"]), description=str(data.get("description", "")),
            locator=Locator(**data["locator"]),
            layout=None if layout is None else structure_from_dict(layout),
            relationships=tuple(_relationship_from(r) for r in data.get("relationships", ())),
            assertions=tuple(_assertion_from(a) for a in data.get("assertions", ())),
            applicability=_applicability_from(data.get("applicability") or {}),
            validation=_validation_from(data.get("validation") or {}),
        )


def model_from_pattern(pattern: Dict[str, Any], name: Optional[str] = None) -> ArtifactModel:
    """Today's exporter input as a ``byte_pattern`` model (no layout, nothing asserted)."""
    return ArtifactModel(name=name or str(pattern.get("name", "memdiver_pattern")),
                         locator=Locator(kind="byte_pattern", pattern=dict(pattern)))


def structure_base_delta(model: ArtifactModel) -> int:
    """Structure base minus the prefilter hit (window start) for a ``structure`` locator."""
    anchor = model.layout.field_by_name(model.locator.anchor_field) if model.layout else None
    if anchor is None:
        raise ValueError("structure locator needs a layout containing its anchor_field")
    return int(model.locator.pattern.get("key_offset", 0)) - anchor.offset


# -- consistency -------------------------------------------------------------

def _locator_problems(model: ArtifactModel) -> List[str]:
    loc, problems = model.locator, []
    if loc.kind not in LOCATOR_KINDS:
        problems.append(f"locator.kind {loc.kind!r} not in {LOCATOR_KINDS}")
    if not loc.pattern.get("wildcard_pattern"):
        problems.append("locator.pattern has no wildcard_pattern")
    if loc.kind == "structure":
        if model.layout is None:
            problems.append("a structure locator needs a layout")
        elif loc.anchor_field not in model.field_names():
            problems.append(f"locator.anchor_field {loc.anchor_field!r} is not a layout field")
    return problems


def _reference_problems(model: ArtifactModel) -> List[str]:
    names, problems = set(model.field_names()), []
    for rel in model.relationships:
        if rel.kind not in RELATIONSHIP_KINDS:
            problems.append(f"relationship kind {rel.kind!r} not in {RELATIONSHIP_KINDS}")
        problems += [f"relationship {rel.kind} names unknown field {n!r}"
                     for n in (rel.source, rel.target) if n not in names]
    problems += [f"assertion names unknown field {a.field!r}"
                 for a in model.assertions if a.field not in names]
    if model.layout is not None:
        problems += _field_bound_problems(model.layout)
    return problems


def _field_bound_problems(layout: StructureDef) -> List[str]:
    return [f"field {f.name!r} [{f.offset}, {f.offset + f.size}) exceeds total_size {layout.total_size}"
            for f in layout.fields if f.offset < 0 or f.offset + f.size > layout.total_size]


# -- (de)serialization -------------------------------------------------------

def structure_to_dict(s: StructureDef) -> Dict[str, Any]:
    return {"name": s.name, "total_size": s.total_size, "protocol": s.protocol,
            "description": s.description, "tags": list(s.tags), "library": s.library,
            "library_version": s.library_version, "stability": s.stability,
            "fields": [_field_dict(f) for f in s.fields]}


def structure_from_dict(d: Dict[str, Any]) -> StructureDef:
    return StructureDef(
        name=str(d["name"]), total_size=int(d["total_size"]),
        fields=tuple(_field_from(f) for f in d.get("fields", ())),
        protocol=str(d.get("protocol", "")), description=str(d.get("description", "")),
        tags=tuple(d.get("tags", ())), library=d.get("library"),
        library_version=d.get("library_version"), stability=str(d.get("stability", "experimental")))


def _field_dict(f: FieldDef) -> Dict[str, Any]:
    return {"name": f.name, "field_type": f.field_type.value, "offset": f.offset, "size": f.size,
            "description": f.description, "constraints": dict(f.constraints)}


def _field_from(d: Dict[str, Any]) -> FieldDef:
    return FieldDef(name=str(d["name"]), field_type=FieldType(d["field_type"]),
                    offset=int(d["offset"]), size=int(d["size"]),
                    description=str(d.get("description", "")),
                    constraints=dict(d.get("constraints") or {}))


def _evidence_list(items: Tuple[Evidence, ...]) -> List[Dict[str, str]]:
    return [{"kind": e.kind, "ref": e.ref} for e in items]


def _evidence_from(items: Any) -> Tuple[Evidence, ...]:
    return tuple(Evidence(kind=str(e["kind"]), ref=str(e["ref"])) for e in items or ())


def _locator_dict(loc: Locator) -> Dict[str, Any]:
    return {"kind": loc.kind, "pattern": dict(loc.pattern), "anchor_field": loc.anchor_field}


def _relationship_dict(r: Relationship) -> Dict[str, Any]:
    return {"kind": r.kind, "source": r.source, "target": r.target, "delta": r.delta,
            "description": r.description, "support": _evidence_list(r.support)}


def _relationship_from(d: Dict[str, Any]) -> Relationship:
    return Relationship(kind=str(d["kind"]), source=str(d["source"]), target=str(d["target"]),
                        delta=d.get("delta"), description=str(d.get("description", "")),
                        support=_evidence_from(d.get("support")))


def _assertion_dict(a: Assertion) -> Dict[str, Any]:
    return {"field": a.field, "meaning": a.meaning, "label": a.label,
            "support": _evidence_list(a.support)}


def _assertion_from(d: Dict[str, Any]) -> Assertion:
    return Assertion(field=str(d["field"]), meaning=str(d["meaning"]),
                     label=str(d.get("label", "")), support=_evidence_from(d.get("support")))


def _applicability_dict(a: Applicability) -> Dict[str, Any]:
    return {"library": a.library, "library_version": a.library_version, "arch": a.arch,
            "os": a.os, "states": list(a.states), "cohorts": list(a.cohorts)}


def _applicability_from(d: Dict[str, Any]) -> Applicability:
    return Applicability(library=str(d.get("library", "")),
                         library_version=str(d.get("library_version", "")),
                         arch=str(d.get("arch", "")), os=str(d.get("os", "")),
                         states=tuple(d.get("states", ())), cohorts=tuple(d.get("cohorts", ())))


def _validation_dict(v: Validation) -> Dict[str, Any]:
    return {"learned_on": list(v.learned_on), "verdict": v.verdict,
            "held_out": [dict(vars(h)) for h in v.held_out]}


def _validation_from(d: Dict[str, Any]) -> Validation:
    return Validation(learned_on=tuple(d.get("learned_on", ())), verdict=str(d.get("verdict", "untested")),
                      held_out=tuple(HeldOutResult(**h) for h in d.get("held_out", ())))
