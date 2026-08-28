"""Tests for engine/detector_metrics.py — the interval detection metric.

Table-driven over hand-built intervals for the three criteria, plus the
many-to-many structure (fan-in / fan-out), the empty-input conventions, the
tolerance boundary, the strictness ordering, the aggregate report, and a
hypothesis property test pinning the counting rule
(``0 <= precision <= 1``, ``0 <= recall <= 1``).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.engine.detector_metrics import (  # noqa: E402
    CRITERIA,
    CRITERION_CONTAINMENT,
    CRITERION_EXACT,
    CRITERION_KEY_OFFSET,
    DEFAULT_TOLERANCE_BYTES,
    IntervalDetectionMetrics,
    aggregate_detector_report,
    score_intervals,
)
from memdiver.engine.truth_labels import TruthInterval  # noqa: E402


@dataclass(frozen=True)
class Match:
    """Stand-in for ``engine.yara_scan.RuleMatch`` (deliberately not imported)."""

    offset: int
    length: int
    key_offset: Optional[int] = None
    key_length: Optional[int] = None


def truth(start: int, length: int = 32, secret_type: str = "CLIENT_TRAFFIC_SECRET_0"):
    return TruthInterval(
        start=start, length=length, secret_type=secret_type,
        key_hex="aa" * length, client_random="bb" * 32, source="keylog")


# --------------------------------------------------------------------------- #
# containment
# --------------------------------------------------------------------------- #

CONTAINMENT_CASES = [
    # (label, match, truth, related?)
    ("truth strictly inside window", Match(1000, 96), truth(1032), True),
    ("truth flush at window start", Match(1000, 96), truth(1000), True),
    ("truth flush at window end", Match(1000, 96), truth(1064), True),
    ("truth end one byte past window", Match(1000, 96), truth(1065), False),
    ("truth starts one byte before window", Match(1000, 96), truth(999), False),
    ("window shorter than truth", Match(1000, 16), truth(1000), False),
    ("window exactly the truth", Match(1000, 32), truth(1000), True),
    ("window elsewhere entirely", Match(1000, 96), truth(50000), False),
]


@pytest.mark.parametrize(
    "label,match,tru,related",
    CONTAINMENT_CASES,
    ids=[c[0] for c in CONTAINMENT_CASES],
)
def test_containment_relation(label, match, tru, related):
    metrics = score_intervals([match], [tru])[CRITERION_CONTAINMENT]
    assert bool(metrics.pairs) is related, label
    assert metrics.tp_matches == (1 if related else 0)
    assert metrics.fp_matches == (0 if related else 1)
    assert metrics.covered_truths == (1 if related else 0)
    assert metrics.missed_truths == (0 if related else 1)
    assert metrics.precision == (1.0 if related else 0.0)
    assert metrics.recall == (1.0 if related else 0.0)


def test_containment_delta_is_the_key_position_inside_the_window():
    metrics = score_intervals([Match(1000, 96)], [truth(1036)])[CRITERION_CONTAINMENT]
    assert metrics.pairs == ((0, 0, 36),)


def test_containment_ignores_key_offset_meta():
    """A window that encloses the key is a containment hit even with no meta."""
    metrics = score_intervals([Match(1000, 96, key_offset=None)],
                              [truth(1032)])[CRITERION_CONTAINMENT]
    assert metrics.tp_matches == 1
    assert metrics.matches == 1


# --------------------------------------------------------------------------- #
# key_offset / exact
# --------------------------------------------------------------------------- #

KEY_OFFSET_CASES = [
    # (label, key_offset, truth_start, tolerance, related?)
    ("prediction dead on", 32, 1032, 16, True),
    ("prediction 15 bytes low", 32, 1047, 16, True),
    ("prediction exactly +tolerance", 32, 1048, 16, True),
    ("prediction exactly -tolerance", 32, 1016, 16, True),
    ("prediction tolerance+1 high", 32, 1049, 16, False),
    ("prediction tolerance+1 low", 32, 1015, 16, False),
    ("zero tolerance, dead on", 32, 1032, 0, True),
    ("zero tolerance, off by one", 32, 1033, 0, False),
]


@pytest.mark.parametrize(
    "label,key_offset,truth_start,tolerance,related",
    KEY_OFFSET_CASES,
    ids=[c[0] for c in KEY_OFFSET_CASES],
)
def test_key_offset_relation(label, key_offset, truth_start, tolerance, related):
    metrics = score_intervals(
        [Match(1000, 4096, key_offset=key_offset)],
        [truth(truth_start)],
        tolerance_bytes=tolerance,
    )[CRITERION_KEY_OFFSET]
    assert bool(metrics.pairs) is related, label
    assert metrics.tolerance_bytes == tolerance
    assert metrics.precision == (1.0 if related else 0.0)


def test_key_offset_delta_is_signed():
    high = score_intervals([Match(1000, 4096, key_offset=32)],
                           [truth(1040)])[CRITERION_KEY_OFFSET]
    low = score_intervals([Match(1000, 4096, key_offset=32)],
                          [truth(1024)])[CRITERION_KEY_OFFSET]
    assert high.pairs == ((0, 0, 8),)
    assert low.pairs == ((0, 0, -8),)


def test_default_tolerance_is_the_alignment_filter_alignment():
    assert DEFAULT_TOLERANCE_BYTES == 16
    metrics = score_intervals([Match(1000, 4096, key_offset=32)], [truth(1047)])
    assert metrics[CRITERION_KEY_OFFSET].tolerance_bytes == 16
    assert metrics[CRITERION_KEY_OFFSET].tp_matches == 1


def test_exact_is_key_offset_with_zero_tolerance():
    metrics = score_intervals([Match(1000, 4096, key_offset=32)], [truth(1040)])
    assert metrics[CRITERION_KEY_OFFSET].tp_matches == 1     # within 16
    assert metrics[CRITERION_EXACT].tolerance_bytes == 0
    assert metrics[CRITERION_EXACT].tp_matches == 0          # not byte-exact


def test_matches_without_key_offset_are_unscorable_not_false_positives():
    """No ``key_offset`` meta means no positional claim — excluded, not charged.

    The window still counts under ``containment``, which is the claim it does
    make.
    """
    metrics = score_intervals(
        [Match(1000, 96), Match(1000, 96, key_offset=32)], [truth(1032)])
    assert metrics[CRITERION_CONTAINMENT].matches == 2
    assert metrics[CRITERION_KEY_OFFSET].matches == 1
    assert metrics[CRITERION_KEY_OFFSET].fp_matches == 0
    assert metrics[CRITERION_EXACT].matches == 1
    # Indices stay global to the original sequence: the scorable match is #1.
    assert metrics[CRITERION_KEY_OFFSET].pairs == ((1, 0, 0),)


def test_no_scorable_matches_yields_zero_rates_without_dividing_by_zero():
    metrics = score_intervals([Match(1000, 96)], [truth(50000)])
    assert metrics[CRITERION_KEY_OFFSET].matches == 0
    assert metrics[CRITERION_KEY_OFFSET].precision == 0.0
    assert metrics[CRITERION_KEY_OFFSET].f1 == 0.0


# --------------------------------------------------------------------------- #
# Many-to-many structure
# --------------------------------------------------------------------------- #

def test_fan_out_one_window_containing_two_truths():
    """One wildcarded window swallowing two keys: recall 1.0 but fan-out 2."""
    metrics = score_intervals(
        [Match(1000, 256, key_offset=32)],
        [truth(1032), truth(1200, secret_type="SERVER_TRAFFIC_SECRET_0")],
    )[CRITERION_CONTAINMENT]
    assert metrics.matches == 1
    assert metrics.truths == 2
    assert metrics.tp_matches == 1
    assert metrics.covered_truths == 2
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.max_truths_per_match == 2      # fan-out is visible
    assert metrics.max_matches_per_truth == 1


def test_fan_in_two_matches_containing_one_truth():
    """Two overlapping rules firing on the same key: fan-in 2, recall still 1.0."""
    metrics = score_intervals(
        [Match(1000, 96, key_offset=32), Match(1016, 64, key_offset=16)],
        [truth(1032)],
    )[CRITERION_CONTAINMENT]
    assert metrics.matches == 2
    assert metrics.truths == 1
    assert metrics.tp_matches == 2
    assert metrics.covered_truths == 1
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.max_matches_per_truth == 2     # fan-in is visible
    assert metrics.max_truths_per_match == 1


def test_precision_and_recall_are_indexed_on_different_sets():
    """3 matches / 2 truths: precision counts matches, recall counts truths."""
    metrics = score_intervals(
        [Match(1000, 96), Match(1000, 96), Match(90000, 96)],
        [truth(1032), truth(50000)],
    )[CRITERION_CONTAINMENT]
    assert (metrics.tp_matches, metrics.fp_matches) == (2, 1)
    assert (metrics.covered_truths, metrics.missed_truths) == (1, 1)
    assert metrics.precision == pytest.approx(2 / 3)
    assert metrics.recall == 0.5
    assert metrics.f1 == pytest.approx(2 * (2 / 3) * 0.5 / ((2 / 3) + 0.5))


# --------------------------------------------------------------------------- #
# Strictness ordering
# --------------------------------------------------------------------------- #

def test_exact_is_stricter_than_key_offset_is_stricter_than_nothing():
    matches = [
        Match(1000, 256, key_offset=32),    # dead on truth(1032)
        Match(2000, 256, key_offset=32),    # 8 bytes off truth(2040)
        Match(3000, 256, key_offset=32),    # 64 bytes off truth(3096)
    ]
    truths = [truth(1032), truth(2040), truth(3096)]
    metrics = score_intervals(matches, truths)

    containment = metrics[CRITERION_CONTAINMENT]
    fuzzy = metrics[CRITERION_KEY_OFFSET]
    exact = metrics[CRITERION_EXACT]

    # Every criterion's relation is a subset of "no criterion at all" (3x3),
    # exact ⊆ key_offset, and containment sees all three windows here.
    assert set(exact.pairs) <= set(fuzzy.pairs)
    assert containment.covered_truths == 3
    assert fuzzy.covered_truths == 2
    assert exact.covered_truths == 1
    assert exact.tp_matches <= fuzzy.tp_matches <= containment.tp_matches
    assert exact.recall < fuzzy.recall < containment.recall


# --------------------------------------------------------------------------- #
# Empty-input conventions
# --------------------------------------------------------------------------- #

EMPTY_CASES = [
    ("no matches, some truths", [], [truth(1000)], 0, 1),
    ("some matches, no truths", [Match(1000, 96, key_offset=32)], [], 1, 0),
    ("both empty", [], [], 0, 0),
]


@pytest.mark.parametrize(
    "label,matches,truths,n_matches,n_truths",
    EMPTY_CASES,
    ids=[c[0] for c in EMPTY_CASES],
)
def test_empty_inputs_return_zero_rates(label, matches, truths, n_matches, n_truths):
    for criterion, metrics in score_intervals(matches, truths).items():
        assert metrics.precision == 0.0, (label, criterion)
        assert metrics.recall == 0.0, (label, criterion)
        assert metrics.f1 == 0.0, (label, criterion)
        assert metrics.truths == n_truths, (label, criterion)
        assert metrics.pairs == (), (label, criterion)
    assert score_intervals(matches, truths)[CRITERION_CONTAINMENT].matches == n_matches


def test_truths_zero_is_distinguishable_from_a_genuine_zero_recall():
    """Documented convention: the ``truths`` count is the discriminator.

    ``recall == 0.0 and truths == 0`` is vacuous (nothing to find);
    ``recall == 0.0 and truths > 0`` is a real, total miss.
    """
    vacuous = score_intervals([Match(1000, 96, key_offset=32)], [])
    real_miss = score_intervals([Match(1000, 96, key_offset=32)], [truth(50000)])
    for criterion in CRITERIA:
        assert vacuous[criterion].recall == 0.0
        assert vacuous[criterion].truths == 0
        assert vacuous[criterion].missed_truths == 0
        assert real_miss[criterion].recall == 0.0
        assert real_miss[criterion].truths == 1
        assert real_miss[criterion].missed_truths == 1


# --------------------------------------------------------------------------- #
# Payload shape
# --------------------------------------------------------------------------- #

def test_score_intervals_returns_all_three_criteria():
    metrics = score_intervals([Match(1000, 96, key_offset=32)], [truth(1032)])
    assert set(metrics) == set(CRITERIA) == {"containment", "key_offset", "exact"}
    for criterion, value in metrics.items():
        assert isinstance(value, IntervalDetectionMetrics)
        assert value.criterion == criterion


def test_to_dict_is_json_serialisable_and_complete():
    metrics = score_intervals([Match(1000, 96, key_offset=32)], [truth(1032)])
    payload = metrics[CRITERION_CONTAINMENT].to_dict()
    assert payload["pairs"] == [[0, 0, 32]]
    assert json.loads(json.dumps(payload)) == payload
    assert set(payload) == {
        "criterion", "tolerance_bytes", "matches", "truths", "tp_matches",
        "fp_matches", "covered_truths", "missed_truths", "precision", "recall",
        "f1", "max_matches_per_truth", "max_truths_per_match", "pairs",
    }


def test_truth_like_objects_with_offset_instead_of_start_are_accepted():
    @dataclass(frozen=True)
    class OffsetTruth:
        offset: int
        length: int

    metrics = score_intervals([Match(1000, 96)], [OffsetTruth(1032, 32)])
    assert metrics[CRITERION_CONTAINMENT].tp_matches == 1


# --------------------------------------------------------------------------- #
# aggregate_detector_report
# --------------------------------------------------------------------------- #

def _report_rows():
    return [
        {
            "detector": "openssl_traffic_secret",
            "dump": "run_1.dump",
            "matches": [Match(1000, 96, key_offset=32), Match(90000, 96, key_offset=32)],
            "truths": [truth(1032)],
        },
        {
            "detector": "openssl_traffic_secret",
            "dump": "run_2.dump",
            "matches": [Match(1000, 96, key_offset=32)],
            "truths": [truth(1032), truth(80000)],
        },
        {
            "detector": "boringssl_traffic_secret",
            "dump": "run_1.dump",
            "matches": [],
            "truths": [truth(1032)],
        },
    ]


def test_aggregate_detector_report_groups_and_micro_averages():
    report = aggregate_detector_report(_report_rows())

    assert report["tolerance_bytes"] == DEFAULT_TOLERANCE_BYTES
    assert report["criteria"] == list(CRITERIA)
    assert report["rows"] == 3
    assert [d["detector"] for d in report["detectors"]] == [
        "boringssl_traffic_secret", "openssl_traffic_secret"]

    openssl = report["detectors"][1]
    containment = openssl["metrics"][CRITERION_CONTAINMENT]
    assert openssl["rows"] == 2
    assert openssl["dumps"] == ["run_1.dump", "run_2.dump"]
    assert containment["matches"] == 3
    assert containment["truths"] == 3
    assert containment["tp_matches"] == 2
    assert containment["fp_matches"] == 1
    assert containment["covered_truths"] == 2
    assert containment["missed_truths"] == 1
    assert containment["precision"] == pytest.approx(2 / 3)
    assert containment["recall"] == pytest.approx(2 / 3)

    overall = report["overall"]["metrics"][CRITERION_CONTAINMENT]
    assert overall["matches"] == 3
    assert overall["truths"] == 4
    assert overall["covered_truths"] == 2
    assert overall["pairs"] == []           # per-row indices don't aggregate
    assert json.loads(json.dumps(report)) == report


def test_aggregate_detector_report_derives_truth_source_provenance():
    report = aggregate_detector_report(_report_rows())
    assert report["overall"]["truth_sources"] == ["keylog"]

    ledger_row = [{
        "detector": "d",
        "matches": [Match(1000, 96, key_offset=32)],
        "truths": [TruthInterval(1032, 32, "T", "aa", "bb", "ledger")],
    }]
    assert aggregate_detector_report(ledger_row)["overall"]["truth_sources"] == ["ledger"]


def test_aggregate_scores_rows_independently_so_offsets_never_cross_dumps():
    """Pooling would let dump A's match pair with dump B's truth."""
    rows = [
        {"detector": "d", "dump": "a", "matches": [Match(1000, 96, key_offset=32)],
         "truths": [truth(50000)]},
        {"detector": "d", "dump": "b", "matches": [Match(40000, 96, key_offset=32)],
         "truths": [truth(1032)]},
    ]
    containment = aggregate_detector_report(rows)["overall"]["metrics"][CRITERION_CONTAINMENT]
    assert containment["tp_matches"] == 0
    assert containment["covered_truths"] == 0
    assert containment["fp_matches"] == 2
    assert containment["missed_truths"] == 2


def test_aggregate_detector_report_on_no_rows():
    report = aggregate_detector_report([])
    assert report["rows"] == 0
    assert report["detectors"] == []
    for criterion in CRITERIA:
        metrics = report["overall"]["metrics"][criterion]
        assert metrics["matches"] == 0
        assert metrics["truths"] == 0
        assert metrics["precision"] == 0.0
        assert metrics["max_matches_per_truth"] == 0


def test_aggregate_detector_report_defaults_missing_keys():
    report = aggregate_detector_report([{}])
    assert report["rows"] == 1
    assert report["detectors"][0]["detector"] == "unknown"
    assert report["detectors"][0]["dumps"] == []


# --------------------------------------------------------------------------- #
# Property test — this is the assertion that pins the counting rule.
# --------------------------------------------------------------------------- #

_match_strategy = st.builds(
    Match,
    offset=st.integers(min_value=0, max_value=4096),
    length=st.integers(min_value=0, max_value=512),
    key_offset=st.one_of(st.none(), st.integers(min_value=-64, max_value=512)),
    key_length=st.just(32),
)

_truth_strategy = st.builds(
    truth,
    start=st.integers(min_value=0, max_value=4096),
    length=st.integers(min_value=1, max_value=64),
    secret_type=st.sampled_from(["A", "B", "C"]),
)


@settings(max_examples=250, deadline=None)
@given(
    matches=st.lists(_match_strategy, max_size=8),
    truths=st.lists(_truth_strategy, max_size=8),
    tolerance=st.integers(min_value=0, max_value=64),
)
def test_property_rates_are_always_bounded(matches, truths, tolerance):
    """Over arbitrary interval sets both rates stay in [0, 1] and the counts close.

    Precision is match-indexed and recall truth-indexed, so each numerator
    counts distinct members of its own denominator's set — bounded by
    construction. This property is what pins that counting rule.
    """
    report = score_intervals(matches, truths, tolerance_bytes=tolerance)
    assert set(report) == set(CRITERIA)
    for criterion, m in report.items():
        assert 0.0 <= m.precision <= 1.0, (criterion, m)
        assert 0.0 <= m.recall <= 1.0, (criterion, m)
        assert 0.0 <= m.f1 <= 1.0, (criterion, m)
        # Counts partition their own set.
        assert m.tp_matches + m.fp_matches == m.matches, (criterion, m)
        assert m.covered_truths + m.missed_truths == m.truths, (criterion, m)
        assert m.tp_matches <= m.matches and m.covered_truths <= m.truths
        # Pair indices address the ORIGINAL sequences.
        for match_idx, truth_idx, _delta in m.pairs:
            assert 0 <= match_idx < len(matches), (criterion, match_idx)
            assert 0 <= truth_idx < len(truths), (criterion, truth_idx)
        # Fan counts are consistent with the pair set.
        assert m.max_matches_per_truth <= max(len(matches), 0)
        assert m.max_truths_per_match <= max(len(truths), 0)
        if not m.pairs:
            assert m.max_matches_per_truth == 0 and m.max_truths_per_match == 0
    # exact ⊆ key_offset always holds.
    assert set(report[CRITERION_EXACT].pairs) <= set(report[CRITERION_KEY_OFFSET].pairs)


@settings(max_examples=150, deadline=None)
@given(
    rows=st.lists(
        st.fixed_dictionaries({
            "detector": st.sampled_from(["r1", "r2"]),
            "matches": st.lists(_match_strategy, max_size=4),
            "truths": st.lists(_truth_strategy, max_size=4),
        }),
        max_size=4,
    ),
)
def test_property_aggregate_rates_are_also_bounded(rows):
    report = aggregate_detector_report(rows)
    groups = [report["overall"]] + list(report["detectors"])
    for group in groups:
        for criterion in CRITERIA:
            m = group["metrics"][criterion]
            assert 0.0 <= m["precision"] <= 1.0, (criterion, m)
            assert 0.0 <= m["recall"] <= 1.0, (criterion, m)
            assert 0.0 <= m["f1"] <= 1.0, (criterion, m)
            assert m["tp_matches"] + m["fp_matches"] == m["matches"]
            assert m["covered_truths"] + m["missed_truths"] == m["truths"]
