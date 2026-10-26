"""Artifact model -> Volatility3 plugin (``Volatility3Exporter.export_model``).

Byte-pattern models must emit exactly what ``export(pattern)`` emits; structure
models emit a plugin that is RUN here (``run_rows_over_buffer``) over synthetic
buffers and, when the TLS corpus is present, over one real captured region.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import os
from pathlib import Path

import pytest

from memdiver.architect.artifact_model import (
    ArtifactModel, Assertion, Locator, Relationship, model_from_pattern,
)
from memdiver.architect.volatility3_exporter import Volatility3Exporter
from memdiver.core.structure_defs import FieldDef, FieldType, StructureDef
from memdiver.architect.pattern_generator import PatternGenerator
from tests._emit_pins import strip_timestamp

pytest.importorskip("volatility3")
from memdiver.engine.vol3_verify import load_plugin_class, run_rows_over_buffer  # noqa: E402

PAGE = 4096
FILLER = b"\x00"
PREFILTER = bytes.fromhex("deadbeef112200 33".replace(" ", ""))  # byte 6 is wildcarded
RID = bytes.fromhex("a1a2a3a4")
SECRET = bytes(range(1, 9))
FAR = bytes.fromhex("f0f1f2f3f4f5f6f7")
ANCHOR_OFF, FAR_OFF, TOTAL = 16, 6000, 8192


def _model() -> ArtifactModel:
    layout = StructureDef(name="obj", total_size=TOTAL, fields=(
        FieldDef("rid", FieldType.BYTES, 0, 4, constraints={"not_zero": True}),
        FieldDef("anchor", FieldType.BYTES, ANCHOR_OFF, 8, constraints={"not_zero": True}),
        FieldDef("far", FieldType.BYTES, FAR_OFF, 8),
    ))
    pattern = {"name": "obj_scan", "length": 8, "wildcard_pattern": "de ad be ef 11 22 ?? 33",
               "static_ratio": 0.875, "key_offset": ANCHOR_OFF - 8, "key_length": 8}
    return ArtifactModel(
        name="obj_model", layout=layout,
        locator=Locator(kind="structure", pattern=pattern, anchor_field="anchor"),
        assertions=(Assertion("anchor", "test.secret", "SECRET"),
                    Assertion("rid", "test.id", ""),
                    Assertion("far", "test.far", "FAR")),
        relationships=(Relationship("owned_by", "anchor", "rid"),
                       Relationship("owned_by", "far", "rid")))


def _put(buf: bytearray, base: int, anchor: bytes = SECRET) -> int:
    hit = base + ANCHOR_OFF - 8
    buf[base:base + 4] = RID
    buf[hit:hit + 8] = PREFILTER[:6] + b"\x7e" + PREFILTER[7:]
    buf[base + ANCHOR_OFF:base + ANCHOR_OFF + 8] = anchor
    if base + FAR_OFF + 8 <= len(buf):
        buf[base + FAR_OFF:base + FAR_OFF + 8] = FAR
    return hit


@pytest.fixture(scope="module")
def synthetic():
    buf = bytearray(PAGE * 6)
    bases = [PAGE + 64, 3 * PAGE + 64]
    hits = [_put(buf, b) for b in bases]
    # prefilter-only decoy: anchor bytes are zero -> must be skipped entirely
    decoy_base = 4 * PAGE + 200
    _put(buf, decoy_base, anchor=bytes(8))
    return bytes(buf), bases, hits


def _by(rows, hit):
    return {r["Field"]: r for r in rows if r["PatternOffset"] == hit}


def test_byte_pattern_model_is_identical_to_export():
    window = bytes(range(48)) + bytes(16)
    pattern = PatternGenerator.generate(window, [True] * 40 + [False] * 24, name="parity")
    pattern.update(key_offset=40, key_length=16)
    direct = Volatility3Exporter.export(pattern, None, None)
    via_model = Volatility3Exporter.export_model(model_from_pattern(pattern))
    assert strip_timestamp(via_model) == strip_timestamp(direct)


def test_structure_plugin_source_is_importable():
    source = Volatility3Exporter.export_model(_model(), plugin_name="ObjModel")
    ast.parse(source)
    cls = load_plugin_class(source, "memdiver_test_structure_import")
    names = {r.name for r in cls.get_requirements()}
    assert {"contiguous", "virtual", "pid", "primary"} <= names
    assert "MODEL = " in source


def test_structure_plugin_rows_with_owner(synthetic):
    data, bases, hits = synthetic
    rows = run_rows_over_buffer(Volatility3Exporter.export_model(_model()), data,
                                extra_config={"contiguous": True})
    assert len(rows) == 6                      # 2 instances x 3 assertions; decoy skipped
    assert {r["PatternOffset"] for r in rows} == set(hits)
    for base, hit in zip(bases, hits):
        got = _by(rows, hit)
        assert got["anchor"]["ValueHex"] == SECRET.hex()
        assert got["anchor"]["Meaning"] == "test.secret" and got["anchor"]["Label"] == "SECRET"
        assert got["anchor"]["StructOffset"] == base + ANCHOR_OFF
        assert got["anchor"]["OwnerField"] == "rid" and got["anchor"]["OwnerHex"] == RID.hex()
        assert got["far"]["ValueHex"] == FAR.hex() and got["far"]["OwnerHex"] == RID.hex()
        assert got["rid"]["OwnerField"] == "" and got["rid"]["OwnerHex"] == ""
        assert {r["Status"] for r in got.values()} == {"ok"}


def test_non_contiguous_layer_decodes_only_inside_the_matched_window(synthetic):
    # File offsets are not physical pages: a field on the same 4 KiB page as
    # the hit but outside [hit, hit + PATTERN_LENGTH) is NOT proven adjacent.
    data, bases, hits = synthetic
    rows = run_rows_over_buffer(Volatility3Exporter.export_model(_model()), data)
    got = _by(rows, hits[0])
    assert hits[0] // PAGE == (bases[0] + ANCHOR_OFF) // PAGE   # same page, still refused
    for name in ("anchor", "rid", "far"):
        assert got[name]["Status"] == "not_contiguous" and got[name]["ValueHex"] == ""


def test_non_contiguous_layer_decodes_a_field_inside_the_matched_window(synthetic):
    data, bases, hits = synthetic
    base = _model()
    layout = dataclasses.replace(base.layout, fields=base.layout.fields + (
        FieldDef("head", FieldType.BYTES, ANCHOR_OFF - 8, 4),))   # == hit
    model = dataclasses.replace(
        base, layout=layout,
        assertions=base.assertions + (Assertion("head", "test.head", ""),),
        relationships=())
    rows = run_rows_over_buffer(Volatility3Exporter.export_model(model), data)
    got = _by(rows, hits[0])
    assert got["head"]["Status"] == "ok" and got["head"]["ValueHex"] == data[hits[0]:hits[0] + 4].hex()
    assert got["rid"]["Status"] == "not_contiguous"
    assert got["anchor"]["Status"] == "not_contiguous"


def test_truncated_buffer_is_unreadable_not_zero(synthetic):
    data, bases, hits = synthetic
    cut = data[:bases[1] + FAR_OFF]            # second instance loses its far field
    rows = run_rows_over_buffer(Volatility3Exporter.export_model(_model()), cut,
                                extra_config={"contiguous": True})
    assert _by(rows, hits[0])["far"]["Status"] == "ok"
    second = _by(rows, hits[1])
    assert second["far"]["Status"] == "unreadable" and second["far"]["ValueHex"] == ""
    assert second["anchor"]["Status"] == "ok"


def test_inconsistent_model_raises_value_error():
    bad = dataclasses.replace(_model(), assertions=(Assertion("nope", "x"),))
    with pytest.raises(ValueError, match="nope"):
        Volatility3Exporter.export_model(bad)


# -- real capture (corpus-gated) ------------------------------------------------

_CORPUS = os.environ.get("MEMDIVER_TLS_CORPUS", "")
_RUN = Path(_CORPUS) / "TLS13" / "openssl" / "openssl_run_13_2" if _CORPUS else None
_MODEL_JSON = os.environ.get("MEMDIVER_OPENSSL_MODEL_JSON", "")


def _client_secret(run: Path) -> str:
    for line in (run / "keylog.csv").read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "CLIENT_TRAFFIC_SECRET_0":
            return parts[2]
    raise AssertionError("no CLIENT_TRAFFIC_SECRET_0")


@pytest.mark.skipif(not (_RUN and _RUN.is_dir() and _MODEL_JSON and Path(_MODEL_JSON).is_file()),
                    reason="set MEMDIVER_TLS_CORPUS and MEMDIVER_OPENSSL_MODEL_JSON")
def test_real_openssl_model_recovers_client_secret_from_capture():
    from memdiver.core.dump_source import open_dump
    model = ArtifactModel.from_dict(json.loads(Path(_MODEL_JSON).read_text()))
    source = Volatility3Exporter.export_model(model)
    msl = next((_RUN / "dumps" / "msl").glob("*.msl"))
    dump = open_dump(msl)
    dump.open()
    try:
        runs = dump.captured_runs()
        span0 = dump.va_span_start()
        found = []
        for va, length, _vas in runs:
            data, _ = dump.read_range_valid(va - span0, length, view="va")
            rows = run_rows_over_buffer(source, data, extra_config={"contiguous": True})
            found += [r["ValueHex"] for r in rows
                      if r["Label"] == "CLIENT_TRAFFIC_SECRET_0" and r["Status"] == "ok"]
    finally:
        dump.close()
    assert _client_secret(_RUN) in found
