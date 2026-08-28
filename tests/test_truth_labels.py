"""Tests for engine/truth_labels.py — the keylog truth locator.

Covers the two locators (:func:`locate_keylog_truth`, :func:`ledger_truth`),
the load-bearing behaviours (all occurrences, empty-secret guard, deterministic
order, ``view`` forwarding, the ``key_hex``/``value_hex`` ledger confusion) and
one corpus-gated proof against a REAL dump.

Also covers the zero-length ledger-row guard (scored through
:func:`engine.detector_metrics.score_intervals`, so the regression is proven at
the place the damage actually happened), the corroboration API
(:func:`corroborate`) and the per-``(run, dump)`` entry point
(:func:`truth_for_dump`) with its keylog parse status.
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.dump_source import open_dump  # noqa: E402
from memdiver.core.keylog import KeylogParser  # noqa: E402
from memdiver.core.models import CryptoSecret  # noqa: E402
from memdiver.core.keylog import (  # noqa: E402
    KEYLOG_STATUS_MISSING,
    KEYLOG_STATUS_OK,
    KEYLOG_STATUS_PARTIAL,
    KEYLOG_STATUS_UNREADABLE,
)
from memdiver.engine.detector_metrics import score_intervals  # noqa: E402
from memdiver.engine.truth_labels import (  # noqa: E402
    DEFAULT_KEYLOG_FILENAME,
    LEDGER_KEY_HEX_FIELDS,
    SOURCE_BOTH,
    SOURCE_KEYLOG,
    SOURCE_LEDGER,
    TRUTH_SOURCES,
    CorroboratedTruth,
    DumpTruth,
    TruthInterval,
    corroborate,
    keylog_secrets_for_run,
    ledger_truth,
    locate_keylog_truth,
    truth_for_dump,
)

# The real corpus run every TLS fixture is anchored to, relative to a dataset
# root; and the verified truth offset of its CLIENT_TRAFFIC_SECRET_0 in the
# pre_server_key_update dump.
REAL_RUN_RELPATH = Path("TLS13/100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1")
REAL_DUMP_NAME = "20251020_171845_606711_pre_server_key_update.dump"
REAL_CLIENT_TRAFFIC_SECRET_0 = (
    "a05312cbc2ba85f6b5413fa97eb3627642e6049c98722c0d326b48dd3382c2c5"
)
REAL_CLIENT_TRAFFIC_SECRET_0_OFFSET = 585084


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def secret(type_name: str, value: bytes, client_random: bytes = b"\xab\xcd") -> CryptoSecret:
    return CryptoSecret(
        secret_type=type_name, identifier=client_random, secret_value=value)


def write_raw_dump(tmp_path: Path, blob: bytes, name: str = "synthetic.dump") -> Path:
    """Materialise a tiny raw dump file under *tmp_path*."""
    path = tmp_path / name
    path.write_bytes(blob)
    return path


class RecordingSource:
    """Minimal duck-typed DumpSource that records how ``find_all`` was called."""

    def __init__(self, offsets_by_needle: dict):
        self._offsets = offsets_by_needle
        self.calls: list = []

    def find_all(self, needle: bytes, **kwargs):
        self.calls.append((needle, dict(kwargs)))
        return list(self._offsets.get(needle, []))


# --------------------------------------------------------------------------- #
# locate_keylog_truth
# --------------------------------------------------------------------------- #

def test_locate_finds_all_occurrences_of_a_duplicated_secret(tmp_path):
    """A secret copied three times yields three truths, not one.

    TLS libraries keep duplicate copies of the same secret in their own
    structs; every copy is a real truth a detector could fire on.
    """
    key = bytes(range(0x40, 0x60))  # 32 distinctive bytes
    filler = b"\x00" * 64
    blob = filler + key + filler + key + filler + key + filler
    src_path = write_raw_dump(tmp_path, blob)

    with open_dump(src_path) as source:
        truths = locate_keylog_truth(source, [secret("CLIENT_TRAFFIC_SECRET_0", key)])

    assert [t.start for t in truths] == [64, 160, 256]
    assert {t.length for t in truths} == {32}
    assert {t.source for t in truths} == {SOURCE_KEYLOG}
    assert {t.key_hex for t in truths} == {key.hex()}
    assert {t.client_random for t in truths} == {"abcd"}


def test_locate_skips_secrets_with_empty_value(tmp_path):
    """An empty needle would match everywhere — it must never enter the truth set."""
    key = bytes(range(0x70, 0x90))
    src_path = write_raw_dump(tmp_path, b"\xff" * 32 + key)

    with open_dump(src_path) as source:
        truths = locate_keylog_truth(source, [
            secret("EMPTY", b""),
            secret("REAL", key),
        ])

    assert [t.secret_type for t in truths] == ["REAL"]
    assert truths[0].start == 32


def test_locate_returns_empty_list_for_absent_secret(tmp_path):
    src_path = write_raw_dump(tmp_path, b"\x11" * 256)
    with open_dump(src_path) as source:
        assert locate_keylog_truth(source, [secret("ABSENT", b"\x99" * 32)]) == []


def test_locate_is_deterministic_and_sorted_by_start_then_type():
    """Ties on ``start`` break on ``secret_type`` so output order is stable."""
    key_a = b"A" * 8
    key_b = b"B" * 8
    source = RecordingSource({key_a: [500, 100], key_b: [100, 300]})
    secrets = [secret("ZEBRA", key_a), secret("ALPHA", key_b)]

    first = locate_keylog_truth(source, secrets)
    second = locate_keylog_truth(source, list(reversed(secrets)))

    keys = [(t.start, t.secret_type) for t in first]
    assert keys == [(100, "ALPHA"), (100, "ZEBRA"), (300, "ALPHA"), (500, "ZEBRA")]
    assert keys == [(t.start, t.secret_type) for t in second]


def test_locate_omits_view_kwarg_when_not_supplied():
    """Omitting ``view`` must preserve each source's own default view."""
    source = RecordingSource({b"K" * 4: [0]})
    locate_keylog_truth(source, [secret("T", b"K" * 4)])
    assert source.calls == [(b"K" * 4, {})]


def test_locate_forwards_view_when_supplied():
    source = RecordingSource({b"K" * 4: [0]})
    locate_keylog_truth(source, [secret("T", b"K" * 4)], view="vas")
    assert source.calls == [(b"K" * 4, {"view": "vas"})]


def test_locate_parses_a_real_keylog_csv_shape(tmp_path):
    """End-to-end through KeylogParser: CSV -> secrets -> truth intervals."""
    key = bytes.fromhex(REAL_CLIENT_TRAFFIC_SECRET_0)
    client_random = "ab" * 32
    keylog = tmp_path / "keylog.csv"
    keylog.write_text(
        "id,line\n"
        f"1,CLIENT_TRAFFIC_SECRET_0 {client_random} {key.hex()}\n"
    )
    src_path = write_raw_dump(tmp_path, b"\x00" * 16 + key + b"\x00" * 16)

    secrets = KeylogParser.parse(keylog)
    assert len(secrets) == 1

    with open_dump(src_path) as source:
        truths = locate_keylog_truth(source, secrets)

    assert len(truths) == 1
    assert truths[0].start == 16
    assert truths[0].key_hex == REAL_CLIENT_TRAFFIC_SECRET_0
    assert truths[0].client_random == client_random


# --------------------------------------------------------------------------- #
# ledger_truth
# --------------------------------------------------------------------------- #

def test_ledger_truth_accepts_both_key_hex_and_value_hex():
    """The ground_truth column is ``key_hex`` but is written from ``value_hex``."""
    assert LEDGER_KEY_HEX_FIELDS == ("key_hex", "value_hex")
    rows = [
        {"offset": 10, "length": 32, "key_hex": "aa" * 32, "secret_type": "A"},
        {"offset": 20, "length": 32, "value_hex": "bb" * 32, "secret_type": "B"},
    ]
    truths = ledger_truth(rows)
    assert [t.key_hex for t in truths] == ["aa" * 32, "bb" * 32]
    assert {t.source for t in truths} == {SOURCE_LEDGER}


def test_ledger_truth_prefers_key_hex_when_both_present():
    truths = ledger_truth([
        {"offset": 0, "length": 4, "key_hex": "1111", "value_hex": "2222"}])
    assert truths[0].key_hex == "1111"


def test_ledger_truth_length_falls_back_to_key_hex_width():
    truths = ledger_truth([{"offset": 0, "length": None, "value_hex": "aa" * 32}])
    assert truths[0].length == 32


def test_ledger_truth_drops_rows_without_an_offset():
    truths = ledger_truth([
        {"offset": None, "length": 32, "key_hex": "aa" * 32},
        {"length": 32, "key_hex": "bb" * 32},
        {"offset": 7, "length": 32, "key_hex": "cc" * 32},
    ])
    assert [t.start for t in truths] == [7]


def test_ledger_truth_is_sorted_and_tolerates_bytes_valued_columns():
    truths = ledger_truth([
        {"offset": 99, "length": 2, "key_hex": "ffff", "secret_type": "Z"},
        {"offset": 5, "length": 2, "key_hex": b"\x01\x02", "secret_type": "A",
         "client_random": b"\xde\xad"},
    ])
    assert [(t.start, t.secret_type) for t in truths] == [(5, "A"), (99, "Z")]
    assert truths[0].key_hex == "0102"
    assert truths[0].client_random == "dead"


def test_ledger_truth_empty_input():
    assert ledger_truth([]) == []


# --------------------------------------------------------------------------- #
# TruthInterval
# --------------------------------------------------------------------------- #

def test_truth_interval_to_dict_is_complete_and_serialisable():
    import json

    interval = TruthInterval(
        start=1, length=32, secret_type="T", key_hex="aa",
        client_random="bb", source=SOURCE_KEYLOG)
    payload = interval.to_dict()
    assert payload == {
        "start": 1, "length": 32, "secret_type": "T", "key_hex": "aa",
        "client_random": "bb", "source": "keylog",
    }
    assert json.loads(json.dumps(payload)) == payload


def test_truth_interval_is_frozen():
    interval = TruthInterval(0, 1, "T", "", "", SOURCE_KEYLOG)
    with pytest.raises(dataclasses.FrozenInstanceError):
        interval.start = 5  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Real corpus
# --------------------------------------------------------------------------- #

@pytest.mark.requires_dataset
def test_locate_keylog_truth_against_real_corpus_run(dataset_root):
    """Locate a REAL key in a REAL process dump at its verified offset.

    Auto-skips when no dataset root resolves (the ``requires_dataset`` marker
    registered in tests/conftest.py). The corpus is read-only.
    """
    run_dir = dataset_root / REAL_RUN_RELPATH
    dump_path = run_dir / REAL_DUMP_NAME
    keylog_path = run_dir / "keylog.csv"
    if not dump_path.is_file() or not keylog_path.is_file():
        pytest.skip(f"real corpus run not present under {dataset_root}")

    secrets = KeylogParser.parse(keylog_path)
    assert secrets, f"no secrets parsed from {keylog_path}"

    with open_dump(dump_path) as source:
        truths = locate_keylog_truth(source, secrets)

    assert truths, "expected at least one real key hit in the real dump"
    assert all(t.source == "keylog" for t in truths)
    assert truths == sorted(truths, key=lambda t: (t.start, t.secret_type))

    by_type = {t.secret_type: t for t in truths}
    hit = by_type.get("CLIENT_TRAFFIC_SECRET_0")
    assert hit is not None, f"CLIENT_TRAFFIC_SECRET_0 not found; got {sorted(by_type)}"
    assert hit.start == REAL_CLIENT_TRAFFIC_SECRET_0_OFFSET
    assert hit.length == 32
    assert hit.key_hex == REAL_CLIENT_TRAFFIC_SECRET_0

    # The bytes at the reported offset really are the key.
    with open_dump(dump_path) as source:
        assert source.read_range(hit.start, hit.length).hex() == hit.key_hex


# --------------------------------------------------------------------------- #
# Zero-length ledger rows (the recall/precision inflation bug)
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class Match:
    """Minimal duck-typed detector firing, shaped like engine.yara_scan.RuleMatch."""

    offset: int
    length: int
    key_offset: int = None  # type: ignore[assignment]


def test_ledger_truth_drops_rows_whose_extent_nothing_attests():
    """No key bytes and no usable length means no extent — it cannot be scored."""
    truths = ledger_truth([
        {"offset": 20, "secret_type": "NO_KEY_NO_LENGTH"},
        {"offset": 30, "length": None, "key_hex": "", "secret_type": "EMPTY_KEY"},
        {"offset": 35, "length": 0, "key_hex": "", "secret_type": "EMPTY_KEY_ZERO"},
        {"offset": 40, "length": 32, "key_hex": "bb" * 32, "secret_type": "REAL"},
    ])
    assert [(t.start, t.secret_type) for t in truths] == [(40, "REAL")]


def test_ledger_truth_drops_a_non_positive_length_only_when_no_key_vouches_for_it():
    assert ledger_truth([{"offset": 5, "length": -1}]) == []
    assert ledger_truth([{"offset": 5, "length": 0}]) == []
    # A key present at the same row refutes the nonsense length; see
    # test_ledger_truth_recovers_a_zero_length_row_from_its_key_bytes.
    recovered = ledger_truth([{"offset": 5, "length": -1, "key_hex": "aa" * 32}])
    assert [(t.start, t.length) for t in recovered] == [(5, 32)]


def test_ledger_truth_recovers_a_zero_length_row_from_its_key_bytes():
    """A key implies a perfectly good extent — dropping such a row loses truth.

    ``length`` falling back to the key width is the documented contract; it used
    to fire only when ``length`` was ``None``, so an explicit ``0`` beside a real
    32-byte key was thrown away instead of recovered.
    """
    truths = ledger_truth([
        {"offset": 100, "length": 0, "key_hex": "aa" * 32, "secret_type": "ZEROED"}])
    assert [(t.start, t.length, t.secret_type) for t in truths] == [(100, 32, "ZEROED")]


def test_ledger_truth_prefers_the_key_width_over_a_contradicting_length():
    """REGRESSION: a length the key refutes silently destroyed corroboration.

    ``corroborate`` keys on ``(start, length)``, so a ledger row recorded as
    ``length=48`` around a 32-byte key could never match the keylog interval
    ``(100, 32)`` covering those same bytes: the agreement was lost and
    ``ledger_only_truths`` — "the ledger saw something keylog truth didn't" —
    was inflated by a row that saw exactly what keylog truth saw.
    """
    wrong_width = ledger_truth([
        {"offset": 100, "length": 48, "key_hex": "aa" * 32, "secret_type": "T"}])
    assert [(t.start, t.length) for t in wrong_width] == [(100, 32)]

    result = corroborate([_keylog(100, 32, key_hex="aa" * 32)], wrong_width)
    assert result.ledger_corroborated_truths == 1
    assert result.ledger_only_truths == 0
    assert result.truth_source == SOURCE_BOTH


def test_ledger_truth_keeps_a_length_no_key_can_contradict():
    """With no key bytes the row's own length is the only evidence there is."""
    truths = ledger_truth([{"offset": 7, "length": 48, "secret_type": "T"}])
    assert [(t.start, t.length) for t in truths] == [(7, 48)]


def test_ledger_truth_logs_a_count_of_overridden_lengths(caplog):
    with caplog.at_level("WARNING", logger="memdiver.engine.truth_labels"):
        ledger_truth([
            {"offset": 1, "length": 48, "key_hex": "aa" * 32},
            {"offset": 2, "length": 0, "key_hex": "bb" * 32},
            {"offset": 3, "length": 32, "key_hex": "cc" * 32},  # agrees: no override
        ])
    assert "Overrode 2 ledger row length(s)" in caplog.text


def test_ledger_truth_logs_a_count_of_dropped_zero_length_rows(caplog):
    with caplog.at_level("WARNING", logger="memdiver.engine.truth_labels"):
        ledger_truth([{"offset": 1}, {"offset": 2}, {"offset": 3, "length": 4,
                                                     "key_hex": "aabbccdd"}])
    assert "2 ledger row(s)" in caplog.text


def test_a_zero_length_ledger_truth_can_never_be_counted_as_covered():
    """REGRESSION: length-0 truths inflated both recall and precision.

    ``_containment_pairs`` tests ``start <= t_start and t_start + length <= end``.
    With ``length == 0`` that is satisfied by *any* window covering the start, so
    a junk ledger row was scored as a covered truth AND promoted the match to a
    true positive. Dropping the row at the source is the fix; this asserts the
    effect at the place the damage happened.
    """
    junk = ledger_truth([{"offset": 100, "secret_type": "GHOST"}])
    window = Match(offset=90, length=110)  # covers offset 100
    metrics = score_intervals([window], junk)["containment"]

    # Asserted before the drop itself so a regression reports the damage
    # (recall 1.0 off a junk row) rather than only the missing guard.
    assert metrics.covered_truths == 0, "a length-0 truth was counted as covered"
    assert metrics.tp_matches == 0, "a length-0 truth promoted a match to a TP"
    assert metrics.recall == 0.0
    assert metrics.precision == 0.0
    assert metrics.truths == 0
    assert metrics.fp_matches == 1
    assert junk == [], "a length-0 ledger row must never become a TruthInterval"


def test_a_real_length_ledger_truth_is_still_covered():
    """The guard must not cost a legitimate ledger row its containment."""
    real = ledger_truth([{"offset": 100, "length": 32, "key_hex": "aa" * 32}])
    metrics = score_intervals([Match(offset=90, length=110)], real)["containment"]
    assert (metrics.truths, metrics.covered_truths, metrics.tp_matches) == (1, 1, 1)


# --------------------------------------------------------------------------- #
# corroborate
# --------------------------------------------------------------------------- #

def _keylog(start: int, length: int = 32, key_hex: str = "", secret_type: str = "T"):
    return TruthInterval(start, length, secret_type, key_hex or "aa" * length,
                         "cc" * 32, SOURCE_KEYLOG)


def _ledger(start: int, length: int = 32, key_hex: str = "", secret_type: str = "T"):
    return TruthInterval(start, length, secret_type, key_hex or "aa" * length,
                         "cc" * 32, SOURCE_LEDGER)


def test_truth_sources_is_exactly_the_documented_tristate():
    assert TRUTH_SOURCES == ("keylog", "ledger", "both")
    assert SOURCE_BOTH == "both"


def test_corroborate_with_no_ledger_rows_stays_keylog_sourced():
    result = corroborate([_keylog(10), _keylog(50)], [])
    assert result.truth_source == SOURCE_KEYLOG
    assert result.keylog_truths == 2
    assert result.ledger_truths == 0
    assert result.ledger_corroborated_truths == 0
    assert result.is_scorable


def test_corroborate_with_only_ledger_rows_is_ledger_sourced_and_unscorable():
    """No keylog truth means no recall denominator — the tri-state must say so."""
    result = corroborate([], [_ledger(50), _ledger(10)])
    assert result.truth_source == SOURCE_LEDGER
    assert [t.start for t in result.intervals] == [10, 50]  # sorted
    assert result.ledger_only_truths == 2
    assert not result.is_scorable


def test_corroborate_counts_how_many_keylog_truths_the_ledger_confirms():
    keylog = [_keylog(10), _keylog(50), _keylog(90)]
    ledger = [_ledger(10), _ledger(90)]
    result = corroborate(keylog, ledger)
    assert result.truth_source == SOURCE_BOTH
    assert result.keylog_truths == 3
    assert result.ledger_truths == 2
    assert result.ledger_corroborated_truths == 2
    assert result.ledger_only_truths == 0
    assert result.corroboration_rate == pytest.approx(2 / 3)


def test_corroborate_never_widens_the_recall_denominator():
    """Ledger-only rows are counted, never merged into the scored truth set."""
    keylog = [_keylog(10)]
    ledger = [_ledger(10), _ledger(999)]
    result = corroborate(keylog, ledger)
    assert result.intervals == keylog
    assert result.truth_source == SOURCE_BOTH  # one row really did agree
    assert result.ledger_corroborated_truths == 1
    assert result.ledger_only_truths == 1


def test_corroborate_requires_the_same_span_not_merely_an_overlap():
    """A stride artifact one byte away must not launder itself into agreement."""
    result = corroborate([_keylog(100)], [_ledger(101)])
    assert result.ledger_corroborated_truths == 0
    assert result.ledger_only_truths == 1
    # ...and the set it did not corroborate must not be advertised as "both".
    assert result.truth_source == SOURCE_KEYLOG


def test_corroborate_rejects_a_conflicting_key_at_the_same_span():
    result = corroborate([_keylog(10, key_hex="aa" * 32)],
                         [_ledger(10, key_hex="bb" * 32)])
    assert result.ledger_corroborated_truths == 0
    assert result.truth_source == SOURCE_KEYLOG


def test_corroborate_is_not_both_when_the_ledger_corroborates_nothing():
    """REGRESSION: ``both`` was decided by the mere presence of ledger rows.

    ``both`` is an agreement claim — the module docstring calls it "keylog truth
    *corroborated by* ledger rows" — and a consumer branching on it believes the
    set was independently cross-checked. Ledger rows that agree with nothing,
    or that actively conflict, leave the set exactly as authoritative as keylog
    truth alone: no more, and certainly not cross-checked.
    """
    nowhere_near = corroborate([_keylog(10)], [_ledger(9999)])
    assert nowhere_near.truth_source == SOURCE_KEYLOG
    assert nowhere_near.ledger_corroborated_truths == 0
    assert nowhere_near.ledger_truths == 1

    conflicting = corroborate([_keylog(10, key_hex="aa" * 32)],
                              [_ledger(10, key_hex="bb" * 32)])
    assert conflicting.truth_source == SOURCE_KEYLOG

    # One genuine agreement is all it takes to earn "both".
    assert corroborate([_keylog(10), _keylog(9999)],
                       [_ledger(10)]).truth_source == SOURCE_BOTH


def test_corroborate_still_reports_both_when_agreement_is_partial():
    """A set with one confirmed truth among many is still cross-checked."""
    result = corroborate([_keylog(10), _keylog(50), _keylog(90)],
                         [_ledger(10), _ledger(777)])
    assert result.truth_source == SOURCE_BOTH
    assert result.ledger_corroborated_truths == 1
    assert result.ledger_only_truths == 1
    assert result.is_scorable


def test_corroborate_abstains_when_the_ledger_carries_no_key_bytes():
    """The ground_truth key column is nullable; an absent key must not veto."""
    blind = TruthInterval(10, 32, "T", "", "", SOURCE_LEDGER)
    result = corroborate([_keylog(10)], [blind])
    assert result.ledger_corroborated_truths == 1


def test_corroborate_of_two_empty_sets_is_a_vacuous_keylog_set():
    result = corroborate([], [])
    assert result.truth_source == SOURCE_KEYLOG
    assert result.intervals == []
    assert not result.is_scorable
    assert result.corroboration_rate == 0.0


def test_corroborated_truth_to_dict_is_complete_and_serialisable():
    import json

    payload = corroborate([_keylog(10)], [_ledger(10)]).to_dict()
    assert set(payload) == {
        "intervals", "truth_source", "keylog_truths", "ledger_truths",
        "ledger_corroborated_truths", "ledger_only_truths", "corroboration_rate",
    }
    assert json.loads(json.dumps(payload)) == payload


def test_corroborated_truth_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        corroborate([], []).truth_source = "nonsense"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# truth_for_dump / keylog_secrets_for_run — the per-(run, dump) entry point
# --------------------------------------------------------------------------- #

def _run_dir(tmp_path: Path, key: bytes, *, name: str = "run") -> Path:
    """A minimal run directory: one real-shaped keylog.csv plus one dump."""
    run = tmp_path / name
    run.mkdir()
    (run / DEFAULT_KEYLOG_FILENAME).write_text(
        "id,line\n"
        f"1,CLIENT_TRAFFIC_SECRET_0 {'ab' * 32} {key.hex()}\n"
    )
    (run / "d.dump").write_bytes(b"\x00" * 16 + key + b"\x00" * 16)
    return run


def test_truth_for_dump_locates_the_key_and_reports_ok(tmp_path):
    key = bytes(range(0x20, 0x40))
    run = _run_dir(tmp_path, key)

    result = truth_for_dump(run, run / "d.dump")

    assert result.keylog_status == KEYLOG_STATUS_OK
    assert result.truth_is_known
    assert result.secrets_available == 1
    assert [(t.start, t.length) for t in result.intervals] == [(16, 32)]
    assert result.intervals[0].source == SOURCE_KEYLOG
    assert result.dump_path.endswith("d.dump")
    assert result.keylog_path.endswith(DEFAULT_KEYLOG_FILENAME)


def test_truth_for_dump_reports_a_missing_keylog_instead_of_a_silent_zero(tmp_path):
    """The whole point: no keylog is NOT the same cell as a genuine absence."""
    run = tmp_path / "empty_run"
    run.mkdir()
    (run / "d.dump").write_bytes(b"\x00" * 64)

    result = truth_for_dump(run, run / "d.dump")

    assert result.keylog_status == KEYLOG_STATUS_MISSING
    assert result.secrets_available == 0
    assert result.intervals == []
    assert not result.truth_is_known


def test_truth_for_dump_reports_an_unreadable_keylog(tmp_path):
    run = tmp_path / "broken_run"
    run.mkdir()
    (run / DEFAULT_KEYLOG_FILENAME).write_text("")  # no CSV header at all
    (run / "d.dump").write_bytes(b"\x00" * 64)

    result = truth_for_dump(run, run / "d.dump")

    assert result.keylog_status == KEYLOG_STATUS_UNREADABLE
    assert result.keylog_detail
    assert not result.truth_is_known


def test_truth_for_dump_does_not_open_the_dump_when_there_is_no_truth(tmp_path):
    """No secrets means nothing to search for; the dump is never touched."""
    run = tmp_path / "no_keylog"
    run.mkdir()
    result = truth_for_dump(run, run / "does_not_exist.dump")
    assert result.keylog_status == KEYLOG_STATUS_MISSING
    assert result.intervals == []


def test_truth_for_dump_honours_a_custom_keylog_filename(tmp_path):
    key = b"\x5a" * 32
    run = _run_dir(tmp_path, key)
    (run / "other.csv").write_text(
        "id,line\n" f"1,CLIENT_RANDOM {'ab' * 32} {key.hex()}\n")

    result = truth_for_dump(run, run / "d.dump", keylog_filename="other.csv")

    assert result.keylog_status == KEYLOG_STATUS_OK
    assert [s.secret_type for s in result.secrets] == ["CLIENT_RANDOM"]
    assert [t.start for t in result.intervals] == [16]


def test_truth_for_dump_to_dict_is_complete_and_serialisable(tmp_path):
    import json

    key = bytes(range(0x20, 0x40))
    run = _run_dir(tmp_path, key)
    payload = truth_for_dump(run, run / "d.dump").to_dict()
    assert set(payload) == {
        "dump_path", "keylog_path", "keylog_status", "keylog_detail",
        "keylog_rows_read", "keylog_rows_malformed",
        "secrets_available", "secret_types", "truth_is_known", "intervals",
    }
    assert payload["secret_types"] == ["CLIENT_TRAFFIC_SECRET_0"]
    assert (payload["keylog_rows_read"], payload["keylog_rows_malformed"]) == (1, 0)
    assert json.loads(json.dumps(payload)) == payload


def test_dump_truth_is_frozen(tmp_path):
    with pytest.raises(dataclasses.FrozenInstanceError):
        DumpTruth().keylog_status = "nonsense"  # type: ignore[misc]


def test_keylog_secrets_for_run_returns_secrets_and_status(tmp_path):
    key = bytes(range(0x20, 0x40))
    run = _run_dir(tmp_path, key)

    secrets, status = keylog_secrets_for_run(run)

    assert status == KEYLOG_STATUS_OK
    assert [s.secret_value for s in secrets] == [key]


def test_keylog_secrets_for_run_distinguishes_missing_from_genuinely_empty(tmp_path):
    """``([], "missing")`` and ``([], "ok")`` are different facts."""
    absent = tmp_path / "absent"
    absent.mkdir()
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / DEFAULT_KEYLOG_FILENAME).write_text("id,line\n")

    assert keylog_secrets_for_run(absent) == ([], KEYLOG_STATUS_MISSING)
    assert keylog_secrets_for_run(empty) == ([], KEYLOG_STATUS_OK)


def test_truth_for_dump_never_calls_a_corrupted_keylog_a_known_zero(tmp_path):
    """REGRESSION: an unknown secret type read as ``ok`` with zero secrets.

    ``_is_well_formed_keylog_line`` validated the two hex fields but not the
    type token, while ``_parse_line`` rejects the line on exactly that token —
    so every garbled type was classified "well formed, filtered by template"
    and a wholly corrupted key log reported ``ok``. ``truth_is_known`` then
    returned True beside ``secrets_available == 0``, which by its own contract
    means "a zero really means zero", and a survival sweep renders that as a
    genuine post-KeyUpdate absence.
    """
    run = tmp_path / "corrupt"
    run.mkdir()
    (run / DEFAULT_KEYLOG_FILENAME).write_text(
        "id,line\n"
        f"1,CLIENT_TRAFFIC_SECRET_0garbage1 {'ab' * 32} {'cd' * 32}\n"
        f"2,CLIENT_TRAFFIC_SECRET_0garbage2 {'ab' * 32} {'cd' * 32}\n"
        f"3,NOT_A_SECRET_TYPE {'ab' * 32} {'cd' * 32}\n"
    )
    (run / "d.dump").write_bytes(b"\x00" * 64)

    result = truth_for_dump(run, run / "d.dump")

    assert result.keylog_status == KEYLOG_STATUS_PARTIAL
    assert not result.truth_is_known, "a corrupted keylog must never read as a known zero"
    assert result.secrets_available == 0
    # The counters are the surviving evidence: three rows were there.
    assert result.keylog_rows_read == 3
    assert result.keylog_rows_malformed == 3
    assert result.to_dict()["keylog_rows_read"] == 3

    _, status = keylog_secrets_for_run(run)
    assert status == KEYLOG_STATUS_PARTIAL


def test_truth_for_dump_surfaces_the_parser_counters_on_a_clean_keylog(tmp_path):
    """``rows_read`` separates "held nothing" from "held unreadable rows"."""
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / DEFAULT_KEYLOG_FILENAME).write_text("id,line\n")
    (empty / "d.dump").write_bytes(b"\x00" * 64)

    result = truth_for_dump(empty, empty / "d.dump")

    assert result.truth_is_known
    assert result.secrets_available == 0
    assert (result.keylog_rows_read, result.keylog_rows_malformed) == (0, 0)


def test_keylog_secrets_for_run_reports_partial_on_a_malformed_row(tmp_path):
    run = tmp_path / "partial"
    run.mkdir()
    (run / DEFAULT_KEYLOG_FILENAME).write_text(
        "id,line\n"
        f"1,CLIENT_RANDOM {'ab' * 32} {'cd' * 32}\n"
        "2,CLIENT_RANDOM only-two-fields\n"
    )
    secrets, status = keylog_secrets_for_run(run)
    assert status == KEYLOG_STATUS_PARTIAL
    assert len(secrets) == 1


@pytest.mark.requires_dataset
def test_truth_for_dump_against_real_corpus_run(dataset_root):
    """The entry point reproduces the hand-wired real-corpus result exactly."""
    run_dir = dataset_root / REAL_RUN_RELPATH
    dump_path = run_dir / REAL_DUMP_NAME
    if not dump_path.is_file() or not (run_dir / "keylog.csv").is_file():
        pytest.skip(f"real corpus run not present under {dataset_root}")

    result = truth_for_dump(run_dir, dump_path)

    assert result.keylog_status == KEYLOG_STATUS_OK
    assert result.truth_is_known
    assert result.secrets_available > 0
    hit = {t.secret_type: t for t in result.intervals}["CLIENT_TRAFFIC_SECRET_0"]
    assert hit.start == REAL_CLIENT_TRAFFIC_SECRET_0_OFFSET
    assert hit.key_hex == REAL_CLIENT_TRAFFIC_SECRET_0

    with open_dump(dump_path) as source:
        assert locate_keylog_truth(source, result.secrets) == result.intervals
