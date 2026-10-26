"""Held-out validation: per-run plugin scan, scoring, verdict (engine/artifact_validation)."""

from __future__ import annotations

import pytest

from memdiver.architect.artifact_model import HeldOutResult
from memdiver.architect.volatility3_exporter import Volatility3Exporter
from memdiver.engine.artifact_validation import (
    CaptureRun, run_plugin_on_capture, score_capture, validation_record, verdict,
)

pytest.importorskip("volatility3")
from tests.test_artifact_export import (  # noqa: E402
    ANCHOR_OFF, RID, SECRET, _model, _put,
)

SPAN = 0x10000
RUN_LEN = 8192


class FakeSource:
    def __init__(self, runs, span=SPAN, valid=None):
        self._runs = runs                      # [(va, bytes)]
        self._span = span
        self._valid = valid or {}              # va -> [(start, n)]

    def va_span_start(self):
        return self._span

    def captured_runs(self):
        return [(va, len(b), 0) for va, b in self._runs]

    def read_range_valid(self, offset, length, view):
        assert view == "va"
        for va, b in self._runs:
            if va - self._span == offset:
                return b[:length], self._valid.get(va, [(0, len(b))])
        raise AssertionError(f"unexpected read at {offset}")


@pytest.fixture(scope="module")
def plugin():
    return Volatility3Exporter.export_model(_model())


def _anchor_rows(run):
    return [r for r in run.rows if r["Field"] == "anchor" and r["Status"] == "ok"]


def test_instance_in_second_run_gets_run_va_plus_offset(plugin):
    run1_va, run2_va = SPAN + 0x1000, SPAN + 0x40000
    b1, b2 = bytearray(RUN_LEN), bytearray(RUN_LEN)
    _put(b2, 64)
    out = run_plugin_on_capture(plugin, FakeSource([(run1_va, bytes(b1)), (run2_va, bytes(b2))]), "cap")
    rows = _anchor_rows(out)
    assert len(rows) == 1 and rows[0]["ValueHex"] == SECRET.hex()
    assert rows[0]["StructOffset"] == 64 + ANCHOR_OFF
    assert rows[0]["StructVA"] == run2_va + 64 + ANCHOR_OFF
    assert out.scanned_runs == 2 and out.scanned_bytes == 2 * RUN_LEN and out.capture == "cap"


def test_no_seam_fabrication_across_non_adjacent_runs(plugin):
    b1, b2 = bytearray(128), bytearray(128)
    base = 112                                  # rid+prefilter fit run 1; anchor would be run 2 start
    b1[base:base + 4] = RID
    b1[base + 8:base + 16] = bytes.fromhex("deadbeef11227e33")
    b2[0:8] = SECRET                            # what a concatenation would read as the anchor
    src = FakeSource([(SPAN + 0x1000, bytes(b1)), (SPAN + 0x9000, bytes(b2))])
    out = run_plugin_on_capture(plugin, src, "cap")
    assert _anchor_rows(out) == []
    assert not any(r["ValueHex"] == SECRET.hex() for r in out.rows)


def test_short_run_is_skipped(plugin):
    b = bytearray(48)
    out = run_plugin_on_capture(plugin, FakeSource([(SPAN, bytes(b))]), "cap")
    assert out.scanned_runs == 0 and out.scanned_bytes == 0 and out.rows == []


def test_partially_captured_run_yields_only_captured_subrun(plugin):
    va = SPAN + 0x2000
    buf = bytearray(RUN_LEN)
    _put(buf, 4096 + 64)
    src = FakeSource([(va, bytes(buf))], valid={va: [(0, 32), (4096, RUN_LEN - 4096)]})
    out = run_plugin_on_capture(plugin, src, "cap")
    assert out.scanned_runs == 1 and out.scanned_bytes == RUN_LEN - 4096   # 32-byte part skipped
    rows = _anchor_rows(out)
    assert len(rows) == 1
    assert rows[0]["StructVA"] == va + 4096 + 64 + ANCHOR_OFF


def test_uncaptured_instance_not_scanned(plugin):
    va = SPAN
    buf = bytearray(RUN_LEN)
    _put(buf, 64)
    src = FakeSource([(va, bytes(buf))], valid={va: [(2048, 4096)]})
    assert _anchor_rows(run_plugin_on_capture(plugin, src, "cap")) == []


def test_no_va_view_raises():
    with pytest.raises(ValueError, match="no open VA view"):
        run_plugin_on_capture("x", FakeSource([], span=None), "cap")


# -- score_capture --------------------------------------------------------------

LBL = "CLIENT_TRAFFIC_SECRET_0"


def _row(value, owner="aa", label=LBL, status="ok"):
    return {"Label": label, "OwnerHex": owner, "ValueHex": value, "Status": status}


def _run(*rows):
    return CaptureRun(capture="c", rows=list(rows), scanned_runs=2, scanned_bytes=10, seconds=0.5)


def test_exact_match():
    r = score_capture(_run(_row("11")), {(LBL, "aa", "11")}, owned_labels={LBL})
    assert (r.true_positives, r.false_positives, r.false_negatives) == (1, 0, 0)
    assert r.relationships_correct == r.relationships_checked == 1 and r.expected == 1
    assert "2 runs / 10 bytes" in r.detail


def test_wrong_owner_is_tp_but_relationship_wrong():
    r = score_capture(_run(_row("11", owner="bb")), {(LBL, "aa", "11")}, owned_labels={LBL})
    assert r.true_positives == 1 and r.relationships_checked == 1 and r.relationships_correct == 0


def test_case_insensitive_hex():
    r = score_capture(_run(_row("AB", owner="AA")), {(LBL, "aa", "ab")}, owned_labels={LBL})
    assert r.true_positives == 1 and r.relationships_correct == 1


def test_extra_value_is_false_positive():
    r = score_capture(_run(_row("11"), _row("22")), {(LBL, "aa", "11")})
    assert r.true_positives == 1 and r.false_positives == 1 and r.false_negatives == 0


def test_missing_value_is_false_negative():
    r = score_capture(_run(_row("11")), {(LBL, "aa", "11"), (LBL, "aa", "33")})
    assert r.true_positives == 1 and r.false_negatives == 1 and r.expected == 2


def test_non_ok_rows_ignored():
    r = score_capture(_run(_row("11", status="unreadable"), _row("22", status="not_contiguous")),
                      {(LBL, "aa", "11")})
    assert (r.true_positives, r.false_positives, r.false_negatives) == (0, 0, 1)


def test_labels_filter():
    rows = [_row("11"), _row("99", label="OTHER")]
    expected = {(LBL, "aa", "11")}
    assert score_capture(_run(*rows), expected).false_positives == 0   # default: expected labels only
    wide = score_capture(_run(*rows), expected, labels=[LBL, "OTHER"])
    assert wide.false_positives == 1
    narrow = score_capture(_run(*rows), expected, labels=["OTHER"])
    assert narrow.true_positives == 0 and narrow.false_negatives == 1


# -- verdict / record -----------------------------------------------------------

def _res(capture="h", exp=1, tp=1, fp=0, fn=0, rc=1, rk=1):
    return HeldOutResult(capture=capture, expected=exp, true_positives=tp, false_positives=fp,
                         false_negatives=fn, relationships_correct=rc, relationships_checked=rk)


def test_relationships_checked_only_for_owned_labels():
    r = score_capture(_run(_row("11", owner="bb")), {(LBL, "aa", "11")})   # no owned_by in model
    assert r.true_positives == 1 and r.relationships_checked == 0 and r.relationships_correct == 0
    assert verdict([r], {"c": 2}) == "pass"                                # must not be unpassable
    owned = score_capture(_run(_row("11", owner="bb")), {(LBL, "aa", "11")}, owned_labels={LBL})
    assert verdict([owned], {"c": 2}) == "fail"                            # wrong owner still fails


def test_verdict_pass_fail_indeterminate():
    two = {"h": 1, "h2": 1}
    assert verdict([_res(), _res("h2")], two) == "pass"
    assert verdict([], {}) == "indeterminate"
    assert verdict([_res(), _res("h2", fp=1)], two) == "fail"
    assert verdict([_res(tp=0, fn=1, rc=0, rk=0)], {"h": 1}) == "fail"
    assert verdict([_res(rc=0)], {"h": 1}) == "fail"


def test_vacuous_capture_is_indeterminate_not_pass():
    empty = _res(exp=0, tp=0, rc=0, rk=0)              # label typo filtered every triple out
    assert verdict([empty], {"h": 3}) == "indeterminate"
    assert verdict([_res()], {"h": 0}) == "indeterminate"   # nothing scanned
    assert verdict([_res()], {}) == "indeterminate"
    assert verdict([_res(), empty], {"h": 1}) == "indeterminate"
    assert verdict([_res("h2", fp=1), empty], {"h2": 1, "h": 1}) == "fail"   # fail wins


def test_validation_record_builds_and_refuses_leak():
    v = validation_record(["a", "b"], [_res("h")], {"h": 1})
    assert v.verdict == "pass" and v.learned_on == ("a", "b") and len(v.held_out) == 1
    with pytest.raises(ValueError, match="'b'"):
        validation_record(["a", "b"], [_res("b")], {"b": 1})
