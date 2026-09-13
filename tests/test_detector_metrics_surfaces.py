"""D2 — ``analysis.score_detector`` on all four surfaces.

``scan_yara_rule`` (D1, ``tests/test_yara_scan_surfaces.py``) can RUN a
MemDiver-emitted rule and report a per-dump census of its firings. It cannot
say whether those firings were RIGHT, and "matched" is not a synonym for "was
right": a rule that fires on every 4 KiB page produces a beautiful
``dumps_matched`` count and is worthless. ``engine/detector_metrics.py`` is the
half that answers the real question — interval precision/recall under three
criteria — and it sat in exactly the hole ``engine/yara_scan.py`` sat in before
D1: 472 lines, fully tested, reachable from NO surface, so a detector census
came with no way to judge it. ``score_detector_matches`` is that missing half,
and this module is its four-surface proof.

What these tests pin, in order:

* the exactly-one-of guard over the two intakes — the single ``matches`` /
  ``truths`` pair and the N-row form — refused BY NAME rather than resolved by
  precedence, because silently preferring one hands the caller a confident
  report scored over data they did not mean;

* **the dict/``getattr`` conversion, which is the load-bearing section of this
  file.** ``engine/detector_metrics.py`` reads every input through ``getattr``
  and coerces a missing field to ``0`` (``_int_or``), and that duck typing is
  DELIBERATE and documented ("anything exposing those attributes works"), which
  is what keeps the metric module independent of whichever scanner produced the
  hits. But this producer's inputs arrive as DICTS —
  ``RuleMatch.to_dict()`` out of D1, JSON off the web and MCP surfaces — and

      getattr({"offset": 370672, "length": 48}, "offset", None)  ->  None
      _int_or(None)                                              ->  0

  so an unconverted dict scores as a firing at offset 0, SILENTLY, producing a
  complete and plausible-looking report of entirely fictional precision and
  recall with nothing raised anywhere. Section (b) is what fails if that
  conversion is ever removed or bypassed;

* the row model and the THREE-valued verdict, which together are the
  capability. A row that carried no truth interval must stay distinguishable
  from one whose detector missed every key it had: the first is a vacuous zero
  and the second a measured total miss, and collapsing them turns a missing
  input into a damning result (or the reverse);

* that all three criteria always come back together, and that the fan-in /
  fan-out structure the engine publishes "precisely so that structure stays
  visible" survives into the payload and into a diagnostic — a recall of 1.0
  reached by one window that swallowed every key must not read as a triumph;

* the END-TO-END JOIN with D1: a rule built by the real emitter chain, run by
  ``scan_yara_rule`` over a planted dump, whose ``dumps[].scan.matches`` go
  straight into this producer with the planted offset as truth. That test is
  what proves the dict conversion holds in the real data path rather than only
  in a fixture;

* the four surfaces routing to one producer, MCP and web byte-for-byte
  included.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pytest
import yara  # noqa: F401  — the end-to-end join runs a real scan; see D1's note

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app.tools_pipeline import (  # noqa: E402
    SCORE_DETECTOR_FAN_IN_CODE,
    SCORE_DETECTOR_FAN_OUT_CODE,
    SCORE_DETECTOR_INTAKES,
    SCORE_DETECTOR_NO_KEY_OFFSET_CODE,
    SCORE_DETECTOR_NO_MATCHES_CODE,
    SCORE_DETECTOR_NO_TRUTHS_CODE,
    SCORE_DETECTOR_SCORED_CODE,
    SCORE_DETECTOR_UNSCORABLE_ROWS_CODE,
    SCORE_DETECTOR_VERDICTS,
    SCORE_INTAKE_PAIR,
    SCORE_INTAKE_ROWS,
    SCORE_NO_MATCHES,
    SCORE_NO_TRUTHS,
    SCORE_ROW_SCORED,
    SCORE_ROW_STATUSES,
    SCORE_ROW_UNSCORABLE,
    SCORE_SCORED,
    scan_yara_rule,
    score_detector_matches,
)
from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    ErrorCategory,
)
from memdiver.engine.detector_metrics import (  # noqa: E402
    CRITERIA,
    CRITERION_CONTAINMENT,
    CRITERION_EXACT,
    CRITERION_KEY_OFFSET,
    DEFAULT_TOLERANCE_BYTES,
)

_ROUTE = "/api/scan/score"

#: A deliberately LARGE, deliberately non-round offset. Every positional
#: assertion in this file is anchored on it, because the failure this module
#: exists to catch reports offset 0 — so a fixture near 0, or on a round
#: boundary, would let it pass.
_KEY_OFFSET = 370672
#: The window the detector claims, which STARTS BEFORE the key: a wildcarded
#: window rule matches static neighbourhood bytes and reports the window's
#: start, not the key's. Conflating the two is the other half of what the
#: ``key_offset`` meta exists to prevent.
_WINDOW_START = _KEY_OFFSET - 64
_WINDOW_LENGTH = 160
_KEY_LENGTH = 32


# --------------------------------------------------------------------------- #
# Inputs in the shape they REALLY arrive in — dicts
# --------------------------------------------------------------------------- #

def match_dict(offset=_WINDOW_START, length=_WINDOW_LENGTH, *, key_offset=64,
               key_length=_KEY_LENGTH, rule="memdiver_key_pattern"):
    """One firing as ``RuleMatch.to_dict()`` shapes it — a plain dict.

    Deliberately carrying the extra keys ``RuleMatch.to_dict()`` really emits
    (``rule``, ``tags``, ``string_id``, ``matched_hex``), so the normalisation
    is exercised on the actual payload rather than on a minimal stand-in.
    """
    return {
        "rule": rule,
        "tags": ["memdiver"],
        "string_id": "$pattern",
        "offset": offset,
        "length": length,
        "matched_hex": "00ff",
        "key_offset": key_offset,
        "key_length": key_length,
    }


def truth_dict(start=_KEY_OFFSET, length=_KEY_LENGTH, *, source="keylog"):
    """One truth interval as ``TruthInterval.to_dict()`` shapes it."""
    return {
        "start": start,
        "length": length,
        "secret_type": "CLIENT_TRAFFIC_SECRET_0",
        "key_hex": "ab" * length,
        "client_random": "cd" * 32,
        "source": source,
    }


def containment(payload):
    """The roll-up's containment block — the headline criterion."""
    return payload["report"]["overall"]["metrics"][CRITERION_CONTAINMENT]


def codes(payload):
    return [d["code"] for d in payload["diagnostics"]]


# --------------------------------------------------------------------------- #
# (a) the intake guard — exactly one form, named in the refusal
# --------------------------------------------------------------------------- #

def test_producer_refuses_both_intakes():
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches(
            matches=[match_dict()],
            truths=[truth_dict()],
            rows=[{"matches": [match_dict()], "truths": [truth_dict()]}],
        )

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    message = str(excinfo.value)
    # BOTH names, and the absence of precedence, are the point: a caller who
    # set the wrong field must not receive a complete, confident report.
    assert "matches=/truths=" in message
    assert "rows=" in message
    assert "both were supplied" in message
    assert "no precedence" in message


def test_producer_refuses_neither_intake():
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches()

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "neither was" in str(excinfo.value)


def test_a_pair_only_label_beside_rows_is_refused_not_ignored():
    """``detector`` / ``dump`` / ``truth_sources`` decorate the PAIR form; in
    the rows form every row carries its own. Ignoring them would silently drop
    provenance the caller asked to record."""
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches(
            rows=[{"matches": [match_dict()], "truths": [truth_dict()]}],
            detector="memdiver_key_pattern",
        )

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    # And the refusal NAMES the colliding argument, so the caller does not have
    # to guess which of the five it was.
    assert "rows= alongside detector=" in str(excinfo.value)


def test_producer_refuses_an_empty_rows_list():
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches(rows=[])

    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert "at least 1 row" in str(excinfo.value)


def test_producer_refuses_a_negative_tolerance():
    """Refused rather than clamped: the engine clamps the RELATION to 0 but
    publishes ``tolerance_bytes`` verbatim on every metrics block, so -5 would
    be reported as the slack that was applied when it was not."""
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches(
            matches=[match_dict()], truths=[truth_dict()], tolerance_bytes=-5)

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "tolerance_bytes must be >= 0" in str(excinfo.value)


def test_a_non_mapping_row_is_refused_by_index():
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches(rows=[{"matches": [], "truths": []}, "nope"])

    assert "rows[1]" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# (b) THE DICT / getattr CONVERSION — the load-bearing section
# --------------------------------------------------------------------------- #

def test_a_DICT_shaped_match_is_scored_at_its_REAL_offset():
    """THE most important test in this file.

    The metrics engine reads its inputs by ``getattr`` and coerces a missing
    field to ``0``, so an unconverted dict is scored as a firing at offset 0
    with nothing raised — precision and recall come back looking entirely
    plausible and are entirely fictional. Here the firing's window spans
    ``[370608, 370768)`` and the key sits at ``370672``, so a correctly
    converted input has the truth CONTAINED in the window; a dict read straight
    through ``getattr`` would be a zero-length window at offset 0, containing
    nothing at all, and every count below would flip.
    """
    payload = score_detector_matches(
        matches=[match_dict()], truths=[truth_dict()])

    assert payload["verdict"] == SCORE_SCORED
    block = containment(payload)
    assert block["matches"] == 1
    assert block["truths"] == 1
    # The whole assertion in one line: the window did contain the key.
    assert block["tp_matches"] == 1
    assert block["covered_truths"] == 1
    assert block["precision"] == 1.0
    assert block["recall"] == 1.0
    # And the positional delta proves WHICH offsets were compared: the key sat
    # 64 bytes into the window. Under the failure mode this is unreachable —
    # there would be no pair at all.
    row_metrics = payload["rows"][0]["metrics"]
    assert row_metrics[CRITERION_CONTAINMENT]["pairs"] == [
        [0, 0, _KEY_OFFSET - _WINDOW_START]]


def test_a_dict_shaped_match_that_MISSES_is_scored_as_a_miss():
    """The other side of the same guard, and it is not redundant.

    The test above pins that a real hit is scored as a hit; this pins that a
    real miss is scored as a miss, so neither can be satisfied by a producer
    that answers the same way to everything.

    Both failure modes are reachable. Zero the MATCH side only and every window
    collapses to ``[0, 0)``, which contains nothing — so a detector that works
    perfectly reports precision 0.0. Zero BOTH sides and ``0 <= 0 and 0 + 0 <=
    0 + 0`` holds, so every zeroed match contains every zeroed truth and
    everything becomes a true positive, this row included.
    """
    payload = score_detector_matches(
        matches=[match_dict(offset=1024, length=64, key_offset=0)],
        truths=[truth_dict()],
    )

    block = containment(payload)
    assert block["tp_matches"] == 0
    assert block["fp_matches"] == 1
    assert block["missed_truths"] == 1
    assert block["precision"] == 0.0
    assert block["recall"] == 0.0


def test_the_key_offset_criterion_reads_the_dicts_predicted_position():
    """``key_offset`` is relative to the window start, so the predicted key
    position is ``offset + key_offset``. Reading either field as 0 moves that
    prediction by up to a whole window."""
    payload = score_detector_matches(
        matches=[match_dict()], truths=[truth_dict()])

    row = payload["rows"][0]["metrics"]
    # Right to the byte, so even the zero-tolerance criterion agrees.
    assert row[CRITERION_KEY_OFFSET]["tp_matches"] == 1
    assert row[CRITERION_EXACT]["tp_matches"] == 1
    assert row[CRITERION_KEY_OFFSET]["pairs"] == [[0, 0, 0]]


@pytest.mark.parametrize("delta,exact_tp", [(0, 1), (15, 0), (17, 0)])
def test_the_tolerance_is_measured_in_real_bytes(delta, exact_tp):
    """A prediction 15 bytes low is within the alignment slack and 17 is not —
    an assertion that can only pass if the real offsets reached the engine."""
    payload = score_detector_matches(
        matches=[match_dict()], truths=[truth_dict(start=_KEY_OFFSET + delta)])

    row = payload["rows"][0]["metrics"]
    assert row[CRITERION_KEY_OFFSET]["tp_matches"] == (1 if delta <= 15 else 0)
    assert row[CRITERION_EXACT]["tp_matches"] == exact_tp


def test_a_match_with_NO_offset_is_refused_not_defaulted_to_zero():
    """The second half of the guard: what cannot be converted is REFUSED.

    There is no safe default for "where did it fire", and the engine's ``0``
    is the least safe of all — it is a real position, at the start of the dump,
    that scores like any other.
    """
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches(
            matches=[{"length": 160, "key_offset": 64}], truths=[truth_dict()])

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    message = str(excinfo.value)
    assert "matches[0]" in message
    assert "offset" in message
    # And the refusal SAYS why, so the next reader does not "fix" it by
    # defaulting the field.
    assert "fictional" in message


def test_a_truth_with_no_start_or_offset_is_refused():
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches(
            matches=[match_dict()], truths=[{"length": 32}])

    assert "truths[0]" in str(excinfo.value)
    assert "'start'" in str(excinfo.value)
    assert "'offset'" in str(excinfo.value)


def test_a_truth_may_name_its_start_offset_the_way_locate_key_does():
    """``offset`` is accepted as an alias because the engine's own
    ``_truth_start`` accepts it, and a caller pasting a hit row from
    ``locate_key`` has ``offset`` rather than ``start``."""
    payload = score_detector_matches(
        matches=[match_dict()],
        truths=[{"offset": _KEY_OFFSET, "length": _KEY_LENGTH}],
    )

    assert containment(payload)["tp_matches"] == 1


@pytest.mark.parametrize("bad", [True, 4096.5, "not a number", None, [4096]])
def test_a_non_integral_byte_position_is_refused(bad):
    """``bool`` is refused because ``int(True) == 1`` — a ``key_offset`` of
    ``true`` would score as a one-byte prediction instead of as the mistake it
    is — and a fractional float because truncation moves a byte boundary
    silently. ``None`` is "absent", which is refused for ``offset`` too."""
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches(
            matches=[{"offset": bad, "length": 160}], truths=[truth_dict()])

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT


def test_a_json_string_byte_position_is_accepted():
    """A JSON encoder that stringifies large integers must not silently score
    as offset 0 either; an exactly-integral string is converted."""
    payload = score_detector_matches(
        matches=[{"offset": str(_WINDOW_START), "length": "160",
                  "key_offset": "64"}],
        truths=[{"start": str(_KEY_OFFSET), "length": 32}],
    )

    assert containment(payload)["tp_matches"] == 1
    assert payload["rows"][0]["metrics"][CRITERION_EXACT]["tp_matches"] == 1


def test_a_negative_byte_position_is_refused():
    with pytest.raises(CapabilityError) as excinfo:
        score_detector_matches(
            matches=[match_dict(offset=-1)], truths=[truth_dict()])

    assert "must be >= 0" in str(excinfo.value)


def test_ATTRIBUTE_carrying_objects_still_work_unchanged():
    """The engine's duck typing is a designed property, and the app layer must
    not have broken it for a library caller holding the real objects.

    A caller with ``RuleMatch`` / ``TruthInterval`` instances should not have to
    serialise them first — so both shapes are accepted, and both must score
    identically. This is also the assertion that would fail if the conversion
    were "simplified" into an unconditional dict subscript.
    """
    from memdiver.engine.truth_labels import TruthInterval
    from memdiver.engine.yara_scan import RuleMatch

    match = RuleMatch(
        rule="memdiver_key_pattern", tags=("memdiver",), string_id="$pattern",
        offset=_WINDOW_START, length=_WINDOW_LENGTH, matched_hex="00ff",
        key_offset=64, key_length=_KEY_LENGTH,
    )
    truth = TruthInterval(
        start=_KEY_OFFSET, length=_KEY_LENGTH, secret_type="s",
        key_hex="ab", client_random="cd", source="keylog",
    )

    from_objects = score_detector_matches(matches=[match], truths=[truth])
    from_dicts = score_detector_matches(
        matches=[match_dict()], truths=[truth_dict()])

    from_objects.pop("elapsed_s")
    from_dicts.pop("elapsed_s")
    assert from_objects == from_dicts


# --------------------------------------------------------------------------- #
# (c) the row model and the THREE-valued verdict
# --------------------------------------------------------------------------- #

def test_the_vocabularies_are_closed_and_say_what_they_say():
    assert SCORE_DETECTOR_VERDICTS == (
        SCORE_SCORED, SCORE_NO_MATCHES, SCORE_NO_TRUTHS)
    assert SCORE_ROW_STATUSES == (SCORE_ROW_SCORED, SCORE_ROW_UNSCORABLE)
    assert SCORE_DETECTOR_INTAKES == (SCORE_INTAKE_PAIR, SCORE_INTAKE_ROWS)
    assert list(CRITERIA) == [
        CRITERION_CONTAINMENT, CRITERION_KEY_OFFSET, CRITERION_EXACT]


def test_a_row_with_NO_truths_is_unscorable_and_carries_no_metrics():
    """The vacuous-zero guard, and the reason ``metrics`` is nested.

    With an empty truth set every rate the engine returns is ``0.0`` because
    its denominator is zero — which reads exactly like "the detector missed
    everything". So the row gets ``metrics: None``, ``report`` is ``None``, and
    the verdict claims nothing.
    """
    payload = score_detector_matches(matches=[match_dict()], truths=[])

    row = payload["rows"][0]
    assert row["status"] == SCORE_ROW_UNSCORABLE
    assert row["metrics"] is None
    # The firing count is still published — it is not hidden, just unjudged.
    assert row["matches"] == 1
    assert row["truths"] == 0
    assert payload["verdict"] == SCORE_NO_TRUTHS
    assert payload["report"] is None
    assert SCORE_DETECTOR_NO_TRUTHS_CODE in codes(payload)


def test_a_row_that_HAD_keys_and_found_none_is_a_MEASURED_miss():
    """The other zero, and the distinction that carries the capability: here
    the denominator is real, so ``recall == 0.0`` is a result, not a gap."""
    payload = score_detector_matches(matches=[], truths=[truth_dict()])

    row = payload["rows"][0]
    assert row["status"] == SCORE_ROW_SCORED
    assert row["metrics"][CRITERION_CONTAINMENT]["truths"] == 1
    assert row["metrics"][CRITERION_CONTAINMENT]["missed_truths"] == 1
    assert row["metrics"][CRITERION_CONTAINMENT]["recall"] == 0.0
    assert payload["verdict"] == SCORE_NO_MATCHES
    # And a report EXISTS, unlike the no_truths case: something was measured.
    assert payload["report"] is not None
    assert SCORE_DETECTOR_NO_MATCHES_CODE in codes(payload)
    assert SCORE_DETECTOR_NO_TRUTHS_CODE not in codes(payload)


def test_an_unscorable_row_is_EXCLUDED_from_the_report_and_said_so():
    """Pooling a no-truth row's firings into the precision denominator asserts
    they are false positives — a claim a row with no truth set cannot support.
    So it is excluded, and the exclusion is a WARNING rather than a silence.
    """
    payload = score_detector_matches(rows=[
        {"matches": [match_dict()], "truths": [truth_dict()],
         "detector": "r", "dump": "/scored.dump"},
        {"matches": [match_dict(offset=8192), match_dict(offset=16384)],
         "truths": [], "detector": "r", "dump": "/no_truth.dump"},
    ])

    assert payload["verdict"] == SCORE_SCORED
    counts = payload["counts"]
    assert counts["rows_total"] == 2
    assert counts["rows_scored"] == 1
    assert counts["rows_unscorable"] == 1
    assert counts["matches_total"] == 3
    # THE precision denominator counts only the scorable row's firing.
    assert counts["matches_scored"] == 1
    assert counts["matches_unscorable"] == 2
    assert containment(payload)["matches"] == 1
    assert payload["report"]["rows"] == 1
    diagnostic = next(d for d in payload["diagnostics"]
                      if d["code"] == SCORE_DETECTOR_UNSCORABLE_ROWS_CODE)
    assert diagnostic["severity"] == "warning"
    assert diagnostic["details"]["matches_unscorable"] == 2
    assert diagnostic["details"]["rows"] == ["/no_truth.dump"]


def test_rows_keep_the_supplied_order_and_their_own_labels():
    payload = score_detector_matches(rows=[
        {"matches": [match_dict()], "truths": [truth_dict()],
         "detector": "alpha", "dump": "/first.dump"},
        {"matches": [match_dict()], "truths": [truth_dict()],
         "detector": "beta", "dump": "/second.dump"},
    ])

    assert [r["dump"] for r in payload["rows"]] == ["/first.dump", "/second.dump"]
    assert payload["intake"] == SCORE_INTAKE_ROWS
    assert payload["counts"]["detectors"] == 2
    # ``detectors`` in the report is sorted by NAME, which is the engine's
    # contract and not the supplied order.
    assert [d["detector"] for d in payload["report"]["detectors"]] == [
        "alpha", "beta"]


def test_rows_are_scored_INDEPENDENTLY_never_pooled():
    """The assertion that a firing on one dump cannot pair with a truth on
    another whose offsets happen to line up.

    Both rows here use the SAME offsets, and each row's firing matches only its
    own row's key. Pooling the intervals first would give every firing two
    partners and invent a true positive per row.
    """
    payload = score_detector_matches(rows=[
        {"matches": [match_dict()], "truths": [truth_dict()], "dump": "/a"},
        {"matches": [match_dict()], "truths": [truth_dict()], "dump": "/b"},
    ])

    block = containment(payload)
    assert block["matches"] == 2
    assert block["truths"] == 2
    assert block["tp_matches"] == 2
    # The fan-out is 1, not 2: no window swallowed the OTHER row's key.
    assert block["max_truths_per_match"] == 1
    assert block["max_matches_per_truth"] == 1


def test_the_row_status_and_metrics_payload_are_a_biconditional():
    """The roll-up and the verdict trust this, so a violation is a programming
    error rather than a strange result to be tolerated."""
    from memdiver.app.tools_pipeline import _score_detector_row, _ScoreRow

    row = _ScoreRow(detector="r", dump="/a", matches=(), truths=(),
                    truth_sources=())
    with pytest.raises(ValueError, match="contradicts metrics payload"):
        _score_detector_row(row, status=SCORE_ROW_SCORED)
    with pytest.raises(ValueError, match="contradicts metrics payload"):
        _score_detector_row(row, status=SCORE_ROW_UNSCORABLE, metrics={})
    with pytest.raises(ValueError, match="unknown detector-score row status"):
        _score_detector_row(row, status="nonsense")


def test_truth_provenance_is_derived_and_carried_through():
    """A report scored against the sparse DuckDB ledger must never be mistaken
    for one scored against the complete key-log truth."""
    payload = score_detector_matches(rows=[
        {"matches": [match_dict()], "truths": [truth_dict(source="ledger")],
         "dump": "/a"},
        {"matches": [match_dict()], "truths": [truth_dict(source="keylog")],
         "dump": "/b"},
    ])

    assert payload["rows"][0]["truth_sources"] == ["ledger"]
    assert payload["rows"][1]["truth_sources"] == ["keylog"]
    assert payload["report"]["overall"]["truth_sources"] == ["keylog", "ledger"]


def test_an_explicit_truth_sources_override_wins():
    payload = score_detector_matches(
        matches=[match_dict()], truths=[truth_dict(source="keylog")],
        truth_sources=["ledger"])

    assert payload["rows"][0]["truth_sources"] == ["ledger"]
    assert payload["report"]["overall"]["truth_sources"] == ["ledger"]


# --------------------------------------------------------------------------- #
# (d) the three criteria, and the structure the engine refuses to launder
# --------------------------------------------------------------------------- #

def test_all_three_criteria_come_back_on_every_row_and_the_rollup():
    payload = score_detector_matches(
        matches=[match_dict()], truths=[truth_dict()])

    assert payload["criteria"] == list(CRITERIA)
    assert set(payload["rows"][0]["metrics"]) == set(CRITERIA)
    assert set(payload["report"]["overall"]["metrics"]) == set(CRITERIA)
    # ``exact`` is ``key_offset`` at zero tolerance whatever was requested.
    assert payload["rows"][0]["metrics"][CRITERION_EXACT][
        "tolerance_bytes"] == 0


def test_a_firing_without_key_offset_is_UNSCORABLE_not_a_false_positive():
    """It makes no positional claim at all, so it leaves the
    ``key_offset``/``exact`` precision denominator rather than being charged
    against the rule — and the difference in denominators is announced."""
    payload = score_detector_matches(
        matches=[match_dict(), match_dict(offset=8192, key_offset=None)],
        truths=[truth_dict()],
    )

    metrics = payload["rows"][0]["metrics"]
    assert metrics[CRITERION_CONTAINMENT]["matches"] == 2
    assert metrics[CRITERION_KEY_OFFSET]["matches"] == 1
    # 1/1, not 1/2: the silent firing is excluded, not counted as wrong.
    assert metrics[CRITERION_KEY_OFFSET]["precision"] == 1.0
    diagnostic = next(d for d in payload["diagnostics"]
                      if d["code"] == SCORE_DETECTOR_NO_KEY_OFFSET_CODE)
    assert diagnostic["details"]["matches_without_key_offset"] == 1


def test_a_window_that_swallowed_every_key_is_a_WARNING_not_a_triumph():
    """The engine publishes ``max_truths_per_match`` "precisely so that
    structure stays visible rather than being laundered into a single
    flattering score". A caller reading a rendered payload will not go looking
    for it, so it is lifted into a WARNING here.

    One 64 KiB window over three keys gives recall 1.0 — a property of how wide
    the emitted pattern is, not of the detector localising anything.
    """
    payload = score_detector_matches(
        matches=[match_dict(offset=0, length=65536, key_offset=None)],
        truths=[truth_dict(start=1024), truth_dict(start=32768),
                truth_dict(start=60000)],
    )

    block = containment(payload)
    assert block["recall"] == 1.0
    assert block["max_truths_per_match"] == 3
    diagnostic = next(d for d in payload["diagnostics"]
                      if d["code"] == SCORE_DETECTOR_FAN_OUT_CODE)
    assert diagnostic["severity"] == "warning"
    assert "EVERY key" in diagnostic["message"]


def test_duplicate_detections_of_one_key_are_reported_as_fan_in():
    """Precision is match-indexed, so two overlapping rules hitting one key
    both count as true positives. That flatters the rule set, so it is
    published rather than deduplicated."""
    payload = score_detector_matches(
        matches=[match_dict(), match_dict(rule="second_rule")],
        truths=[truth_dict()],
    )

    block = containment(payload)
    assert block["max_matches_per_truth"] == 2
    assert block["precision"] == 1.0
    assert SCORE_DETECTOR_FAN_IN_CODE in codes(payload)


def test_the_scored_diagnostic_reports_the_headline_numbers():
    payload = score_detector_matches(
        matches=[match_dict(), match_dict(offset=8192)],
        truths=[truth_dict()],
    )

    diagnostic = next(d for d in payload["diagnostics"]
                      if d["code"] == SCORE_DETECTOR_SCORED_CODE)
    assert diagnostic["details"]["containment"]["precision"] == 0.5
    assert diagnostic["details"]["containment"]["recall"] == 1.0
    assert "containment precision 0.500" in diagnostic["message"]


def test_the_rollup_micro_averages_and_empties_the_row_local_pairs():
    """Counts are additive and the rates recomputed from the sums; ``pairs``
    is emptied because its indices are meaningful only inside one row, and
    concatenating them would invent cross-row pairings."""
    payload = score_detector_matches(rows=[
        {"matches": [match_dict()], "truths": [truth_dict()], "dump": "/a"},
        {"matches": [match_dict(offset=8192)], "truths": [truth_dict()],
         "dump": "/b"},
    ])

    assert containment(payload)["precision"] == 0.5
    assert containment(payload)["recall"] == 0.5
    assert containment(payload)["pairs"] == []
    # The per-row pairs SURVIVE, which is what makes the miss attributable to
    # a specific dump and a specific delta.
    assert payload["rows"][0]["metrics"][CRITERION_CONTAINMENT]["pairs"] == [
        [0, 0, 64]]
    assert payload["rows"][1]["metrics"][CRITERION_CONTAINMENT]["pairs"] == []


def test_the_tolerance_default_is_the_engine_constant():
    payload = score_detector_matches(
        matches=[match_dict()], truths=[truth_dict()])

    assert payload["tolerance_bytes"] == DEFAULT_TOLERANCE_BYTES
    assert payload["rows"][0]["metrics"][CRITERION_KEY_OFFSET][
        "tolerance_bytes"] == DEFAULT_TOLERANCE_BYTES


def test_the_producer_opens_no_dump_and_needs_no_key_material():
    """It takes matches and truths as DATA. ``_raise_if_locked`` guards
    producers that read bytes, and this one reads a list — which is why it is
    deliberately absent from ``test_g9_producers_surface_locked_dump``."""
    import inspect

    signature = inspect.signature(score_detector_matches)
    for forbidden in ("key_file", "passphrase", "kem_key_file",
                      "key_material", "dump_paths", "view"):
        assert forbidden not in signature.parameters
    source = inspect.getsource(score_detector_matches)
    assert "_raise_if_locked" not in source
    assert "open_dump_source" not in source


# --------------------------------------------------------------------------- #
# (e) the END-TO-END JOIN with D1 — the reason both producers exist
# --------------------------------------------------------------------------- #

def test_a_real_scans_matches_score_against_the_planted_offset(tmp_path):
    """The whole point, in one test.

    A rule built by the REAL emitter chain, run by ``scan_yara_rule`` over a
    dump with the pattern planted at a known offset, and its
    ``dumps[].scan.matches`` handed STRAIGHT to the scorer with that offset as
    truth. Nothing is reshaped in between — which is exactly what makes this
    the proof that the dict conversion holds in the real data path: those
    matches are ``RuleMatch.to_dict()`` output, so if the producer ever stopped
    converting them, this reports a firing at offset 0 and the containment
    counts below collapse.
    """
    from tests.test_yara_scan_surfaces import emitted_rule, write_dump

    plant = 4096
    rule, reference = emitted_rule(91)
    dump = write_dump(tmp_path / "join.dump", {plant: reference})

    scan = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)
    row = scan["dumps"][0]
    assert row["scan"]["match_count"] >= 1, scan
    matches = row["scan"]["matches"]
    # The emitter wildcards the key in the middle of the window, so the truth
    # interval is derived from the rule's OWN meta rather than guessed.
    key_offset = matches[0]["key_offset"]
    key_length = matches[0]["key_length"]
    assert key_offset is not None and key_offset > 0

    payload = score_detector_matches(
        matches=matches,
        truths=[{"start": plant + key_offset, "length": key_length,
                 "source": "keylog"}],
        detector=matches[0]["rule"],
        dump=row["dump_path"],
    )

    assert payload["verdict"] == SCORE_SCORED
    block = containment(payload)
    assert block["truths"] == 1
    assert block["covered_truths"] == 1
    assert block["recall"] == 1.0
    # At least one real firing enclosed the planted key, and its predicted key
    # position was right to the byte.
    assert block["tp_matches"] >= 1
    exact = payload["rows"][0]["metrics"][CRITERION_EXACT]
    assert exact["covered_truths"] == 1
    # And the delta the scorer computed is the plant, not zero.
    pairs = payload["rows"][0]["metrics"][CRITERION_CONTAINMENT]["pairs"]
    assert any(p[2] == key_offset for p in pairs), pairs


def test_a_real_scan_of_a_dump_WITHOUT_the_key_scores_as_precision_loss(
        tmp_path):
    """The join's negative half: a dump where the pattern was planted but the
    key was not is a row with firings and no truths — unscorable, excluded, and
    counted, rather than quietly deflating the precision."""
    from tests.test_yara_scan_surfaces import emitted_rule, write_dump

    plant = 4096
    rule, reference = emitted_rule(92)
    hit = write_dump(tmp_path / "hit.dump", {plant: reference}, seed=1)
    miss = write_dump(tmp_path / "miss.dump", {}, seed=2)

    scan = scan_yara_rule(dump_paths=[str(hit), str(miss)], rule_source=rule)
    key_offset = scan["dumps"][0]["scan"]["matches"][0]["key_offset"]

    payload = score_detector_matches(rows=[
        {
            "matches": r["scan"]["matches"],
            "truths": ([{"start": plant + key_offset, "length": 16,
                         "source": "keylog"}] if i == 0 else []),
            "detector": "planted_pattern",
            "dump": r["dump_path"],
        }
        for i, r in enumerate(scan["dumps"])
    ])

    assert payload["counts"]["rows_total"] == 2
    assert payload["counts"]["rows_scored"] == 1
    assert payload["counts"]["rows_unscorable"] == 1
    assert containment(payload)["recall"] == 1.0
    assert SCORE_DETECTOR_UNSCORABLE_ROWS_CODE in codes(payload)


# --------------------------------------------------------------------------- #
# (f) the web surface — POST /api/scan/score
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app

    return TestClient(create_app())


def test_route_returns_the_producer_payload(client):
    resp = client.post(_ROUTE, json={
        "matches": [match_dict()], "truths": [truth_dict()]})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == SCORE_SCORED
    # The route is on the MODERN funnel and must carry the real offsets: this
    # is the dict trap arriving as JSON off the wire, which is the shape it
    # will really arrive in.
    assert body["report"]["overall"]["metrics"][
        CRITERION_CONTAINMENT]["tp_matches"] == 1
    assert body["rows"][0]["metrics"][CRITERION_CONTAINMENT]["pairs"] == [
        [0, 0, 64]]


def test_route_returns_200_for_an_unscorable_request(client):
    """A vacuous result is a RESULT, not an error, so the route must not turn
    it into a 4xx — and ``report`` stays ``null`` rather than becoming zeros."""
    resp = client.post(_ROUTE, json={"matches": [match_dict()], "truths": []})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == SCORE_NO_TRUTHS
    assert body["report"] is None


def test_route_rejects_both_intakes_on_the_modern_contract(client):
    """``{error, code, category}`` from the single global handler in
    ``api/main.py`` — not ``{"detail": ...}``, which is why this route lives on
    ``scan.py`` and not on the legacy ``analysis`` router."""
    resp = client.post(_ROUTE, json={
        "matches": [match_dict()],
        "truths": [truth_dict()],
        "rows": [{"matches": [], "truths": []}],
    })

    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["category"] == "INVALID_INPUT"
    assert "exactly ONE" in body["error"]
    assert "detail" not in body


def test_route_lets_the_producer_own_the_missing_offset_refusal(client):
    """NOT a 422 in FastAPI's words: the request model types the lists loosely
    on purpose so all four surfaces report a firing with no byte position in the
    producer's words — the ones that explain what a default would have done."""
    resp = client.post(_ROUTE, json={
        "matches": [{"length": 160}], "truths": [truth_dict()]})

    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["category"] == "INVALID_INPUT"
    assert "matches[0]" in body["error"]


def test_route_advertises_the_engine_tolerance_default(client):
    resp = client.post(_ROUTE, json={
        "matches": [match_dict()], "truths": [truth_dict()]})

    assert resp.json()["tolerance_bytes"] == DEFAULT_TOLERANCE_BYTES


def test_route_accepts_the_rows_intake(client):
    resp = client.post(_ROUTE, json={"rows": [
        {"matches": [match_dict()], "truths": [truth_dict()], "dump": "/a"},
        {"matches": [], "truths": [truth_dict()], "dump": "/b"},
    ]})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["intake"] == SCORE_INTAKE_ROWS
    assert body["counts"]["rows_scored"] == 2
    assert body["counts"]["rows_without_matches"] == 1


# --------------------------------------------------------------------------- #
# (g) the MCP surface
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def mcp_tool():
    """The registered MCP tool's callable, funnel and all."""
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "score_detector_matches" in tools, sorted(tools)
    return tools["score_detector_matches"].fn


def test_mcp_tool_returns_json_payload(mcp_tool):
    """A JSON STRING (the MCP transport contract) carrying the producer's dict."""
    raw = mcp_tool(matches=[match_dict()], truths=[truth_dict()])

    assert isinstance(raw, str)
    payload = json.loads(raw)
    assert "error" not in payload, payload
    assert payload["verdict"] == SCORE_SCORED
    assert payload["report"]["overall"]["metrics"][
        CRITERION_CONTAINMENT]["recall"] == 1.0


def test_mcp_tool_funnels_the_both_intakes_error(mcp_tool):
    """A CapabilityError escaping the body is rendered as the structured
    ``{error, code, category}`` dict — an agent gets machine-readable text."""
    payload = json.loads(mcp_tool(
        matches=[match_dict()],
        truths=[truth_dict()],
        rows=[{"matches": [], "truths": []}],
    ))

    assert payload["category"] == "INVALID_INPUT"
    assert "exactly ONE" in payload["error"]


def test_mcp_tool_funnels_the_missing_offset(mcp_tool):
    payload = json.loads(mcp_tool(
        matches=[{"length": 160}], truths=[truth_dict()]))

    assert payload["category"] == "INVALID_INPUT"
    assert "matches[0]" in payload["error"]


def test_mcp_tool_funnels_the_empty_rows_precondition(mcp_tool):
    payload = json.loads(mcp_tool(rows=[]))

    assert payload["category"] == "PRECONDITION"
    assert "at least 1 row" in payload["error"]


def test_mcp_and_web_return_byte_identical_payloads(mcp_tool, client):
    """Cross-surface parity, and the load-bearing test of this whole file.

    Both adapters dispatch through the ONE producer, so identical input must
    yield the identical payload — not merely a compatible one. Any future change
    that inlines the normalisation or the roll-up in one adapter fails here.

    ``elapsed_s`` is dropped from both sides before comparing: it is a
    wall-clock measurement, so it is the one key that MUST differ between two
    runs, and keeping it would make this assertion vacuous-by-failure rather
    than meaningful.
    """
    request = {
        "rows": [
            {"matches": [match_dict()], "truths": [truth_dict()],
             "detector": "planted_pattern", "dump": "/hit.dump"},
            {"matches": [match_dict(offset=8192)], "truths": [],
             "detector": "planted_pattern", "dump": "/no_truth.dump"},
        ],
        "tolerance_bytes": 8,
    }

    from_mcp = json.loads(mcp_tool(**request))
    resp = client.post(_ROUTE, json=request)

    assert resp.status_code == 200, resp.text
    from_web = resp.json()
    from_mcp.pop("elapsed_s")
    from_web.pop("elapsed_s")
    assert from_mcp == from_web
    # And the payload actually said something, so the equality above is not two
    # empty dicts agreeing.
    assert from_web["verdict"] == SCORE_SCORED
    assert from_web["counts"]["rows_total"] == 2
    assert from_web["tolerance_bytes"] == 8


# --------------------------------------------------------------------------- #
# (h) the CLI surface
# --------------------------------------------------------------------------- #

def _run_cli(argv, tmp_path):
    """Invoke the ``score-detector`` handler and return ``(exit, payload)``."""
    from memdiver.cli import _cmd_score_detector, build_parser

    out = tmp_path / f"cli_{abs(hash(tuple(argv))) % 10**8}.json"
    args = build_parser().parse_args(["score-detector", *argv, "-o", str(out)])
    code = _cmd_score_detector(args)
    return code, json.loads(out.read_text())


def test_cli_is_a_TOP_LEVEL_command_not_an_inspect_action():
    """``inspect`` is single-dump, session-first and ``ServiceResult``-shaped,
    none of which an N-row score can express. ``score-detector`` follows the
    ``scan-yara`` / ``locate-field-pairs`` precedent instead."""
    from memdiver.cli import _INSPECT_HANDLERS, build_parser

    assert "score_detector" not in _INSPECT_HANDLERS
    assert "score" not in _INSPECT_HANDLERS
    args = build_parser().parse_args(
        ["score-detector", "--matches", "[]", "--truths", "[]"])
    assert args.command == "score-detector"


def test_cli_exits_zero_on_scored(tmp_path, capsys):
    """Exit 0 = a measurement was established, and the headline line plus every
    diagnostic go to STDERR so an operator piping the JSON onward still sees
    the qualifications."""
    code, payload = _run_cli([
        "--matches", json.dumps([match_dict()]),
        "--truths", json.dumps([truth_dict()]),
        "--detector", "planted_pattern",
    ], tmp_path)

    assert code == 0
    assert payload["verdict"] == SCORE_SCORED
    err = capsys.readouterr().err
    assert "verdict=scored" in err
    assert "1 firing(s) vs 1 key(s)" in err
    assert "containment precision 1.000" in err


def test_cli_exits_three_on_a_measured_total_miss(tmp_path):
    """``3`` is ``_CLI_EXIT[NOT_FOUND]``: there were keys to find and the
    detector fired on none of them. That is an absence, and a real result."""
    code, payload = _run_cli([
        "--matches", "[]",
        "--truths", json.dumps([truth_dict()]),
    ], tmp_path)

    assert code == 3
    assert payload["verdict"] == SCORE_NO_MATCHES


def test_cli_exits_two_when_nothing_was_scorable(tmp_path):
    """Exit 2, NOT 3: with no truth intervals there was no denominator, so this
    is a missing input rather than an absence — the fix is in the invocation."""
    code, payload = _run_cli([
        "--matches", json.dumps([match_dict()]),
        "--truths", "[]",
    ], tmp_path)

    assert code == 2
    assert payload["verdict"] == SCORE_NO_TRUTHS
    assert payload["report"] is None


def test_cli_reads_its_json_from_files_too(tmp_path):
    """A real scan's match list is far too long to type, so a path is tried
    FIRST and inline JSON only when no such file exists."""
    matches = tmp_path / "matches.json"
    matches.write_text(json.dumps([match_dict()]))
    truths = tmp_path / "truths.json"
    truths.write_text(json.dumps([truth_dict()]))

    code, payload = _run_cli(
        ["--matches", str(matches), "--truths", str(truths)], tmp_path)

    assert code == 0
    assert containment(payload)["tp_matches"] == 1


def test_cli_distinguishes_an_omitted_flag_from_an_empty_list(tmp_path):
    """``--matches '[]'`` is a detector that fired nowhere — a real, scorable
    result — and must not fall through to the ``--rows`` intake."""
    from memdiver.cli import build_parser

    args = build_parser().parse_args(
        ["score-detector", "--matches", "[]", "--truths", "[]"])
    assert args.matches == "[]"
    assert args.rows is None

    code, payload = _run_cli(["--rows", json.dumps([
        {"matches": [match_dict()], "truths": [truth_dict()]}])], tmp_path)
    assert code == 0
    assert payload["intake"] == SCORE_INTAKE_ROWS


def test_cli_refuses_json_that_is_neither_a_file_nor_valid(tmp_path):
    from memdiver.cli import _cmd_score_detector, build_parser

    args = build_parser().parse_args(
        ["score-detector", "--matches", "{not json"])
    with pytest.raises(CapabilityError) as excinfo:
        _cmd_score_detector(args)

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "--matches is neither a readable JSON file" in str(excinfo.value)


def test_cli_refuses_json_that_is_not_a_list(tmp_path):
    from memdiver.cli import _cmd_score_detector, build_parser

    args = build_parser().parse_args(
        ["score-detector", "--matches", json.dumps({"offset": 1})])
    with pytest.raises(CapabilityError) as excinfo:
        _cmd_score_detector(args)

    assert "must hold a JSON list" in str(excinfo.value)


def test_cli_leaves_the_both_intakes_refusal_to_the_producer(tmp_path):
    """Deliberately NOT an argparse mutually-exclusive group: the producer owns
    the message so all four surfaces report the mistake in the same words."""
    from memdiver.cli import _cmd_score_detector, build_parser

    args = build_parser().parse_args([
        "score-detector",
        "--matches", json.dumps([match_dict()]),
        "--truths", json.dumps([truth_dict()]),
        "--rows", json.dumps([{"matches": [], "truths": []}]),
    ])
    with pytest.raises(CapabilityError) as excinfo:
        _cmd_score_detector(args)

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "matches=/truths=" in str(excinfo.value)


def test_cli_parser_default_is_the_imported_engine_constant():
    """A re-literalled default is how a surface starts advertising a tolerance
    the library does not apply."""
    from memdiver.cli import build_parser

    args = build_parser().parse_args(["score-detector", "--matches", "[]"])
    assert args.tolerance_bytes == DEFAULT_TOLERANCE_BYTES
    assert args.detector is None
    assert args.truth_source is None


def test_cli_takes_no_dump_paths_and_no_decryption_flags():
    """It reads no bytes, so ``--key-file`` and friends are absent by design —
    the ``_decrypt_parent_parser`` every dump-reading command inherits is not
    on this one."""
    from memdiver.cli import build_parser

    args = build_parser().parse_args(["score-detector", "--matches", "[]"])
    for absent in ("dumps", "key_file", "passphrase", "kem_key_file", "view"):
        assert not hasattr(args, absent), absent


# --------------------------------------------------------------------------- #
# (i) the four surfaces are ONE producer
# --------------------------------------------------------------------------- #

def test_the_library_surface_reaches_the_same_object():
    """``memdiver.score_detector_matches`` /
    ``memdiver.services.score_detector_matches`` are the SAME object as the app
    producer, not a wrapper that could drift."""
    import memdiver
    import memdiver.services as services
    from memdiver.app import tools_pipeline

    assert services.score_detector_matches is tools_pipeline.score_detector_matches
    assert memdiver.score_detector_matches is tools_pipeline.score_detector_matches
    assert "score_detector_matches" in services.__all__
    assert "score_detector_matches" in memdiver.__all__


def test_the_capability_claims_all_four_surfaces():
    """No ``KNOWN_PARITY_GAPS`` entry, and none possible: that baseline is
    shrink-only, so a capability that needed one could never be added."""
    from memdiver.app.capabilities import (
        CAPABILITIES,
        IN_SCOPE_SURFACES,
        KNOWN_PARITY_GAPS,
    )

    cap = next(c for c in CAPABILITIES if c.name == "analysis.score_detector")
    assert cap.producer == (
        "memdiver.app.tools_pipeline.score_detector_matches")
    assert IN_SCOPE_SURFACES <= cap.surfaces
    assert not any(
        name == "analysis.score_detector" for name, _ in KNOWN_PARITY_GAPS)


def test_cli_and_library_agree_on_the_same_input(tmp_path):
    """The last of the four pairings: the CLI handler adds presentation and an
    exit code on top of the producer's payload, and changes nothing else."""
    rows = [
        {"matches": [match_dict()], "truths": [truth_dict()], "dump": "/a"},
        {"matches": [match_dict(offset=8192)], "truths": [truth_dict()],
         "dump": "/b"},
    ]

    code, from_cli = _run_cli(["--rows", json.dumps(rows)], tmp_path)
    from_lib = score_detector_matches(rows=rows)

    assert code == 0
    from_cli.pop("elapsed_s")
    from_lib.pop("elapsed_s")
    assert from_cli == from_lib


def test_the_engine_module_is_no_longer_reachable_from_nowhere():
    """The point of the whole change: a 472-line tested module that no surface
    could reach was, functionally, absent from the product."""
    assert random is not None  # keep the import honest for the fixtures above
    from memdiver.app import tools_pipeline

    source = Path(tools_pipeline.__file__).read_text()
    assert "engine.detector_metrics" in source
