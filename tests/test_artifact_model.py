"""ArtifactModel: round-trip, consistency checks, helpers."""

import json
from dataclasses import FrozenInstanceError
from dataclasses import replace

import pytest

from memdiver.architect.artifact_model import (
    Applicability, ArtifactModel, Assertion, Evidence, HeldOutResult, Locator, Relationship,
    SCHEMA, Validation, model_from_pattern, structure_base_delta,
)
from memdiver.core.structure_defs import FieldDef, FieldType, StructureDef

PATTERN = {"name": "p", "wildcard_pattern": "aa ?? bb", "key_offset": 40, "key_length": 16}


def _layout(total=64, extra=()):
    fields = (
        FieldDef("anchor", FieldType.BYTES, 16, 16, "a", {"not_zero": True}),
        FieldDef("ptr", FieldType.POINTER, 40, 8),
    ) + tuple(extra)
    return StructureDef("obj", total, fields, library="lib", stability="experimental")


def _model(**kw):
    base = dict(
        name="m", locator=Locator("structure", dict(PATTERN), "anchor"), layout=_layout(),
        relationships=(Relationship("owned_by", "ptr", "anchor", -24, "d", (Evidence("consensus", "x"),)),),
        assertions=(Assertion("anchor", "tls secret", "KEY", (Evidence("ground_truth", "g"),)),),
        applicability=Applicability("lib", "1.0", "x86_64", "linux", ("idle",), ("c1",)),
        validation=Validation(("d0", "d1"), (HeldOutResult("d2", 1, 1, 0, 0, 1, 1, "ok"),), "pass"),
        description="desc")
    base.update(kw)
    return ArtifactModel(**base)


def test_valid_model_has_no_problems():
    assert _model().check() == []


def test_round_trip_through_json_is_lossless():
    m = _model()
    assert ArtifactModel.from_dict(json.loads(json.dumps(m.to_dict()))) == m


def test_round_trip_without_layout():
    m = model_from_pattern(PATTERN)
    assert ArtifactModel.from_dict(m.to_dict()) == m


def test_from_dict_rejects_wrong_schema():
    d = _model().to_dict()
    d["schema"] = "other/1"
    with pytest.raises(ValueError, match="not an artifact model"):
        ArtifactModel.from_dict(d)
    del d["schema"]
    with pytest.raises(ValueError):
        ArtifactModel.from_dict(d)


def test_to_dict_carries_schema():
    assert _model().to_dict()["schema"] == SCHEMA


def test_model_from_pattern_is_byte_pattern_without_layout():
    m = model_from_pattern(PATTERN)
    assert (m.locator.kind, m.layout, m.name) == ("byte_pattern", None, "p")
    assert model_from_pattern(PATTERN, name="x").name == "x"
    assert model_from_pattern({"wildcard_pattern": "aa"}).name == "memdiver_pattern"
    assert m.check() == []


def test_model_from_pattern_copies_the_pattern():
    p = dict(PATTERN)
    m = model_from_pattern(p)
    p["key_offset"] = 0
    assert m.locator.pattern["key_offset"] == 40


def test_unknown_locator_kind_reported():
    m = _model(locator=Locator("magic", dict(PATTERN), "anchor"))
    assert any("locator.kind 'magic'" in p for p in m.check())


def test_missing_wildcard_pattern_reported():
    m = _model(locator=Locator("structure", {"key_offset": 1}, "anchor"))
    assert any("wildcard_pattern" in p for p in m.check())


def test_structure_locator_without_layout_reported():
    m = _model(layout=None, relationships=(), assertions=())
    assert any("needs a layout" in p for p in m.check())


def test_structure_locator_with_unknown_anchor_field_reported():
    m = _model(locator=Locator("structure", dict(PATTERN), "nope"))
    assert any("anchor_field 'nope'" in p for p in m.check())


def test_unknown_relationship_kind_and_fields_reported():
    m = _model(relationships=(Relationship("friend", "ghost", "anchor"),))
    problems = m.check()
    assert any("kind 'friend'" in p for p in problems)
    assert any("unknown field 'ghost'" in p for p in problems)
    assert not any("unknown field 'anchor'" in p for p in problems)


def test_unknown_assertion_field_reported():
    m = _model(assertions=(Assertion("ghost", "x"),))
    assert any("assertion names unknown field 'ghost'" in p for p in m.check())


def test_field_out_of_bounds_reported():
    m = _model(layout=_layout(total=44))
    assert any("'ptr'" in p and "exceeds total_size 44" in p for p in m.check())


def test_negative_offset_reported():
    m = _model(layout=_layout(extra=(FieldDef("neg", FieldType.BYTES, -1, 2),)))
    assert any("'neg'" in p for p in m.check())


def test_check_lists_every_problem_not_just_first():
    m = _model(locator=Locator("magic", {}, "anchor"), assertions=(Assertion("ghost", "x"),),
               layout=_layout(total=10))
    assert len(m.check()) >= 4


def test_structure_base_delta_is_key_offset_minus_anchor_offset():
    assert structure_base_delta(_model()) == 40 - 16


def test_structure_base_delta_defaults_key_offset_to_zero():
    m = _model(locator=Locator("structure", {"wildcard_pattern": "aa"}, "anchor"))
    assert structure_base_delta(m) == -16


def test_structure_base_delta_rejects_missing_anchor():
    with pytest.raises(ValueError):
        structure_base_delta(_model(locator=Locator("structure", dict(PATTERN), "nope")))
    with pytest.raises(ValueError):
        structure_base_delta(model_from_pattern(PATTERN))


def test_field_names_empty_without_layout():
    assert model_from_pattern(PATTERN).field_names() == ()
    assert _model().field_names() == ("anchor", "ptr")


def test_models_are_frozen():
    with pytest.raises(FrozenInstanceError):
        _model().name = "other"
    assert replace(_model(), name="o").name == "o"
