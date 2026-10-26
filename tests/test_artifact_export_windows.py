"""Multi-window structure plugin: match on ANY window, dedup by object base."""

from __future__ import annotations

import dataclasses

import pytest

from memdiver.architect.artifact_model import Locator, structure_base_deltas
from memdiver.architect.volatility3_exporter import Volatility3Exporter
from tests.test_artifact_export import ANCHOR_OFF, PAGE, PREFILTER, SECRET, _model, _put

pytest.importorskip("volatility3")
from memdiver.engine.vol3_verify import run_rows_over_buffer  # noqa: E402

ALT_AT = 100
ALT_BYTES = bytes.fromhex("c0c1c2c3c4c5c6c7")


def _multi_model():
    base = _model()
    alt = {"wildcard_pattern": "c0 c1 c2 c3 c4 c5 c6 c7", "length": 8,
           "key_offset": ANCHOR_OFF - ALT_AT}
    loc = Locator(kind="structure", pattern=base.locator.pattern,
                  anchor_field="anchor", alternatives=(alt,))
    return dataclasses.replace(base, locator=loc)


def _buffer(primary: bool = True, alt: bool = True, anchor: bytes = SECRET):
    buf = bytearray(PAGE * 3)
    base = PAGE + 64
    _put(buf, base, anchor)
    if not primary:
        buf[base + ANCHOR_OFF - 8:base + ANCHOR_OFF] = bytes(8)
    if alt:
        buf[base + ALT_AT:base + ALT_AT + 8] = ALT_BYTES
    return bytes(buf), base


def _run(data):
    return run_rows_over_buffer(
        Volatility3Exporter.export_model(_multi_model()), data,
        extra_config={"contiguous": True})


def test_base_deltas_per_window():
    assert structure_base_deltas(_multi_model()) == [-8, -ALT_AT]


def test_object_hit_by_two_windows_is_one_row_set():
    data, base = _buffer()
    rows = _run(data)
    anchors = [r for r in rows if r["Field"] == "anchor"]
    assert len(anchors) == 1
    assert anchors[0]["StructOffset"] == base + ANCHOR_OFF
    assert anchors[0]["Windows"] == "0,1"
    assert anchors[0]["Status"] == "ok"


def test_alternative_alone_finds_object_with_its_own_base():
    data, base = _buffer(primary=False)
    anchors = [r for r in _run(data) if r["Field"] == "anchor"]
    assert len(anchors) == 1
    assert anchors[0]["Windows"] == "1"
    assert anchors[0]["StructOffset"] == base + ANCHOR_OFF  # not offset by the primary delta
    assert anchors[0]["ValueHex"] == SECRET.hex()


def test_alternative_hit_with_invalid_anchor_is_skipped():
    data, _ = _buffer(primary=False, anchor=bytes(8))
    assert _run(data) == []


def test_single_window_model_reports_window_zero():
    data, _ = _buffer(alt=False)
    rows = run_rows_over_buffer(Volatility3Exporter.export_model(_model()), data,
                                extra_config={"contiguous": True})
    assert {r["Windows"] for r in rows} == {"0"}


def test_tp_windows_and_redundancy_summary():
    from memdiver.engine.artifact_validation import CaptureRun, tp_windows, window_redundancy
    rows = [{"Label": "L", "ValueHex": "AA", "Status": "ok", "Windows": "0,1"},
            {"Label": "L", "ValueHex": "bb", "Status": "ok", "Windows": "1"},
            {"Label": "L", "ValueHex": "cc", "Status": "ok", "Windows": "0"}]  # not expected
    run = CaptureRun(capture="c", rows=rows)
    tps = tp_windows(run, {("L", "o", "aa"), ("L", "o", "bb")})
    assert [t["windows"] for t in tps] == [[0, 1], [1]]
    red = window_redundancy({"c": tps})
    assert red == {"tp_by_window": {"0": 1, "1": 2},
                   "tps_found_by_multiple_windows": 1, "tp_total": 2}


def _run_flat(data, model=None):
    """Non-contiguous (flat layer) run: fields decode only inside matched windows."""
    return run_rows_over_buffer(
        Volatility3Exporter.export_model(model or _multi_model()), data)


def test_weak_alternative_hit_with_failing_anchor_emits_no_row_on_flat_layer():
    # Alternative bytes present, anchor (outside the 8-byte window) is all zero.
    data, _ = _buffer(primary=False, anchor=bytes(8))
    assert _run_flat(data) == []


def test_anchor_outside_matched_window_is_read_and_validated_on_flat_layer():
    data, base = _buffer(primary=False)
    anchors = [r for r in _run_flat(data) if r["Field"] == "anchor"]
    assert len(anchors) == 1
    assert anchors[0]["Status"] in ("ok", "not_contiguous")  # owner (rid) is unreadable here
    assert anchors[0]["ValueHex"] == SECRET.hex()
    assert anchors[0]["StructOffset"] == base + ANCHOR_OFF


def test_single_pass_finds_every_window_including_close_ones():
    # Two objects, each hit by a different window only; plus alt bytes of the
    # first sitting 3 bytes after the second's primary match (overlapping spans).
    buf = bytearray(PAGE * 3)
    b1, b2 = PAGE + 64, 2 * PAGE + 64
    _put(buf, b1)                                   # primary only
    buf[b1 + ANCHOR_OFF - 8:b1 + ANCHOR_OFF] = bytes(8)
    buf[b1 + ALT_AT:b1 + ALT_AT + 8] = ALT_BYTES    # alt for b1
    _put(buf, b2)                                   # primary for b2
    anchors = {r["StructOffset"]: r["Windows"]
               for r in _run(bytes(buf)) if r["Field"] == "anchor"}
    assert anchors == {b1 + ANCHOR_OFF: "1", b2 + ANCHOR_OFF: "0"}


def test_overlapping_matches_of_different_windows_are_both_found():
    # Alternative window placed so it overlaps the primary's matched bytes.
    base = _model()
    alt = {"wildcard_pattern": "7e 33 c0 c1", "length": 4, "key_offset": ANCHOR_OFF - 14}
    loc = Locator(kind="structure", pattern=base.locator.pattern, anchor_field="anchor",
                  alternatives=(alt,))
    model = dataclasses.replace(base, locator=dataclasses.replace(loc))
    buf = bytearray(PAGE * 2)
    b = PAGE + 64
    hit = _put(buf, b)
    buf[hit + 8:hit + 10] = b"\xc0\xc1"   # alt "7e 33 c0 c1" overlaps primary [hit, hit+8)
    exported = Volatility3Exporter.export_model(model)
    rows = run_rows_over_buffer(exported, bytes(buf), extra_config={"contiguous": True})
    anchors = [r for r in rows if r["Field"] == "anchor"]
    assert len(anchors) == 1 and anchors[0]["Windows"] == "0,1"


def test_weak_alternative_build_warning():
    from memdiver.engine.artifact_builder import _prefilter_warnings
    from memdiver.engine.artifact_builder import Prefilter
    strong = Prefilter(delta=0, length=16, informative_bytes=12, pattern={})
    weak = Prefilter(delta=40, length=16, informative_bytes=5, pattern={})
    warnings = _prefilter_warnings(strong, [weak], 1)
    assert any(w.startswith("prefilter.weak_alternative") for w in warnings)
    assert not any(w.startswith("prefilter.weak_alternative")
                   for w in _prefilter_warnings(strong, [strong], 1))


def test_alternative_only_hit_resolves_owner_outside_window_on_flat_layer():
    data, base = _buffer(primary=False)
    rows = _run_flat(data)
    anchor = next(r for r in rows if r["Field"] == "anchor")
    from tests.test_artifact_export import RID
    assert anchor["Windows"] == "1"
    assert anchor["OwnerField"] == "rid" and anchor["OwnerHex"] == RID.hex()
    assert anchor["Status"] == "ok"   # relationship resolved, not inherited not_contiguous
