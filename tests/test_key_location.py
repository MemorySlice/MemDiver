"""Tests for engine/key_location.py — the honest N-dump key-location compute.

The module's whole reason to exist is the THREE-VALUED per-dump answer, so
these tests pin the model and not just the happy path:

* every ``__post_init__`` invariant of :class:`DumpKeyLocation`, constructed
  directly (mirroring ``tests/test_survival_scan.py``'s style), because each
  guard catches a WRITER bug that would otherwise reach a UI as a confident
  red cell;
* the headline claim: an ALL-UNREADABLE set reports ``not_searched`` and NEVER
  ``absent``;
* the empty-needle guard, without which an empty secret reads as "absent
  everywhere" — the exact silent zero the module prevents;
* that ``EncryptedDumpLockedError`` PROPAGATES rather than degrading to one
  ``unreadable`` row, since a forgotten key poisons every answer in the set
  while a bad file poisons only its own;
* the occurrence CENSUS (a TLS library keeps copies of one secret in its
  key-schedule and record-layer structs, so 2+ hits is ordinary) and its
  truncation, where ``hit_count`` stays the true total;
* :func:`app.export_service.located_export_pattern`'s per-dump windows and its
  refusal to build a single-dump "100% static" pattern.

The functional fixtures are a miniature of the real corpus: four dumps sharing
a low-entropy background, with a high-entropy 48-byte secret planted at offset
2048 in the first two only.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import memdiver.engine.key_location as key_location  # noqa: E402
from memdiver.app.export_service import (  # noqa: E402
    TooFewDumpsError,
    located_export_pattern,
)
from memdiver.core.service_errors import EncryptedDumpLockedError  # noqa: E402
from memdiver.engine.key_location import (  # noqa: E402
    KEY_LOCATION_SEARCHED,
    KEY_LOCATION_TOO_SMALL,
    KEY_LOCATION_UNREADABLE,
    VERDICT_ABSENT,
    VERDICT_FOUND,
    VERDICT_NOT_SEARCHED,
    DumpKeyLocation,
    KeyLocationResult,
    locate_key_across_dumps,
)

SECRET_OFFSET = 2048
SECRET = bytes(range(0x80, 0x80 + 48))
DUMP_SIZE = 4096


def _background(seed: int) -> bytearray:
    """Shared low-entropy background — the same in every dump."""
    return bytearray((i * 3 + seed) % 11 for i in range(DUMP_SIZE))


def _write_dump(path: Path, *, plant_at: "list[int] | None" = None) -> Path:
    data = _background(0)
    for offset in plant_at or []:
        data[offset:offset + len(SECRET)] = SECRET
    path.write_bytes(bytes(data))
    return path


@pytest.fixture()
def corpus(tmp_path: Path) -> "list[Path]":
    """Four dumps; the secret sits at 2048 in the first two only."""
    return [
        _write_dump(tmp_path / "d0.dump", plant_at=[SECRET_OFFSET]),
        _write_dump(tmp_path / "d1.dump", plant_at=[SECRET_OFFSET]),
        _write_dump(tmp_path / "d2.dump"),
        _write_dump(tmp_path / "d3.dump"),
    ]


# ---------------------------------------------------------------------------
# DumpKeyLocation invariants — direct construction
# ---------------------------------------------------------------------------


def test_unknown_status_is_rejected():
    with pytest.raises(ValueError):
        DumpKeyLocation(status="skipped", present=None)


def test_non_searched_row_may_not_claim_presence():
    """A non-NULL ``present`` on an unreadable dump is an absence claim over
    bytes that were never read."""
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_UNREADABLE, present=True)
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_UNREADABLE, present=False)
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_TOO_SMALL, present=False)


def test_searched_row_must_claim_something():
    """A NULL ``present`` on a searched row contributes to neither the found
    nor the absent bucket in the consumer."""
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_SEARCHED, present=None)


def test_present_must_agree_with_first_offset():
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_SEARCHED, present=True,
                        first_offset=None, hit_count=1)


def test_present_must_agree_with_hit_count():
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_SEARCHED, present=False,
                        hit_count=1)


def test_offsets_head_must_equal_first_offset():
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_SEARCHED, present=True,
                        first_offset=3, hit_count=1, offsets=(5,))


def test_offsets_must_be_ascending():
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_SEARCHED, present=True,
                        first_offset=9, hit_count=2, offsets=(9, 5))


def test_offsets_may_never_exceed_hit_count():
    """``hit_count`` is the TRUE total, so it can never be the smaller value."""
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_SEARCHED, present=True,
                        first_offset=1, hit_count=1, offsets=(1, 2))


def test_truncation_flag_must_match_the_offsets_actually_returned():
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_SEARCHED, present=True,
                        first_offset=1, hit_count=3, offsets=(1,),
                        offsets_truncated=False)


def test_absent_row_carries_no_offsets():
    with pytest.raises(ValueError):
        DumpKeyLocation(status=KEY_LOCATION_SEARCHED, present=False,
                        offsets=(4,))


def test_a_valid_searched_row_is_accepted():
    row = DumpKeyLocation(status=KEY_LOCATION_SEARCHED, present=True,
                          first_offset=1, hit_count=3, offsets=(1, 7),
                          offsets_truncated=True)
    assert row.searched
    assert row.to_dict()["hit_count"] == 3


# ---------------------------------------------------------------------------
# KeyLocationResult — derived verdict
# ---------------------------------------------------------------------------


def _searched(present: bool, path: str, offset: int = SECRET_OFFSET,
              hits: int = 1) -> DumpKeyLocation:
    return DumpKeyLocation(
        dump_path=path,
        status=KEY_LOCATION_SEARCHED,
        present=present,
        first_offset=offset if present else None,
        hit_count=hits if present else 0,
        offsets=(offset,) if present else (),
        offsets_truncated=present and hits > 1,
    )


def _unreadable(path: str) -> DumpKeyLocation:
    return DumpKeyLocation(dump_path=path, status=KEY_LOCATION_UNREADABLE,
                           present=None, detail="boom")


def test_verdict_is_not_searched_and_never_absent_when_nothing_was_searched():
    result = KeyLocationResult(dumps=(_unreadable("a"), _unreadable("b")))
    assert result.verdict == VERDICT_NOT_SEARCHED
    assert result.verdict != VERDICT_ABSENT
    assert result.dumps_searched == 0
    assert result.unanimous is False


def test_verdict_absent_requires_at_least_one_searched_dump():
    result = KeyLocationResult(dumps=(_searched(False, "a"), _unreadable("b")))
    assert result.verdict == VERDICT_ABSENT
    assert result.dumps_searched >= 1


def test_absent_cannot_be_claimed_even_from_an_illegally_forced_row():
    """``verdict`` is DERIVED, so ``absent`` over nothing searched is not
    merely rejected — it is unreachable.

    This forces a row past ``DumpKeyLocation.__post_init__`` into the state the
    invariant forbids (``present=False`` on an unreadable row) and shows the
    result still refuses to call it an absence, because ``searched`` keys off
    ``status`` while ``absent`` keys off ``present``.
    """
    bogus = DumpKeyLocation.__new__(DumpKeyLocation)
    for field, value in (
        ("dump_path", "a"), ("name", ""), ("format_name", ""),
        ("size_for_view", 0), ("status", KEY_LOCATION_UNREADABLE),
        ("present", False),  # illegal, forced past the guard
        ("first_offset", None), ("hit_count", 0), ("offsets", ()),
        ("offsets_truncated", False), ("detail", ""),
    ):
        object.__setattr__(bogus, field, value)

    result = KeyLocationResult(dumps=(bogus,))
    assert result.dumps_searched == 0
    assert result.verdict == VERDICT_NOT_SEARCHED
    assert result.verdict != VERDICT_ABSENT


def test_unanimous_is_false_on_a_two_of_eight_result():
    dumps = tuple(
        _searched(i < 2, "d{}".format(i)) for i in range(8)
    )
    result = KeyLocationResult(dumps=dumps)
    assert result.verdict == VERDICT_FOUND
    assert result.dumps_present == 2
    assert result.dumps_absent == 6
    assert result.unanimous is False


def test_unanimous_is_true_when_every_searched_dump_agrees():
    assert KeyLocationResult(
        dumps=(_searched(True, "a"), _searched(True, "b"))).unanimous is True
    assert KeyLocationResult(
        dumps=(_searched(False, "a"), _searched(False, "b"))).unanimous is True


# ---------------------------------------------------------------------------
# locate_key_across_dumps — functional
# ---------------------------------------------------------------------------


def test_found_in_two_of_four_dumps(corpus):
    result = locate_key_across_dumps(corpus, SECRET)

    assert result.verdict == VERDICT_FOUND
    assert [d.dump_path for d in result.dumps] == [str(p) for p in corpus]
    assert result.dumps_searched == 4
    assert result.dumps_present == 2
    assert result.dumps_absent == 2
    assert [d.first_offset for d in result.dumps[:2]] == [SECRET_OFFSET] * 2
    for row in result.dumps[2:]:
        assert row.present is False
        assert row.first_offset is None
        assert row.hit_count == 0
    assert result.offsets_agree is True
    assert result.common_offset == SECRET_OFFSET
    assert result.first_offset == SECRET_OFFSET
    assert result.unanimous is False
    assert result.needle_length == len(SECRET)
    assert set(result.anchor_offsets) == {str(corpus[0]), str(corpus[1])}


def test_absent_everywhere_is_a_real_searched_absence(corpus):
    unrelated = bytes(range(0xC0, 0xC0 + 48))
    result = locate_key_across_dumps(corpus, unrelated)

    assert result.verdict == VERDICT_ABSENT
    assert result.dumps_searched == 4
    assert all(d.status == KEY_LOCATION_SEARCHED for d in result.dumps)
    assert all(d.present is False for d in result.dumps)
    assert result.common_offset is None
    assert result.offsets_agree is False
    assert result.unanimous is True


def test_empty_needle_is_rejected(corpus):
    with pytest.raises(ValueError):
        locate_key_across_dumps(corpus, b"")


def test_one_unreadable_dump_claims_nothing_and_does_not_break_the_verdict(
        corpus, monkeypatch):
    real_open = key_location.open_dump
    doomed = str(corpus[2])

    def fake_open(path, **kwargs):
        if str(path) == doomed:
            raise OSError("permission denied")
        return real_open(path, **kwargs)

    monkeypatch.setattr(key_location, "open_dump", fake_open)
    result = locate_key_across_dumps(corpus, SECRET)

    row = result.dumps[2]
    assert row.status == KEY_LOCATION_UNREADABLE
    assert row.present is None
    assert "permission denied" in row.detail
    assert result.dumps_unreadable == 1
    assert result.dumps_searched == 3
    assert result.verdict == VERDICT_FOUND


def test_all_unreadable_is_not_searched_and_never_absent(corpus, monkeypatch):
    """THE headline assertion: nothing was read, so nothing may be claimed."""
    def fake_open(path, **kwargs):
        raise OSError("disk on fire")

    monkeypatch.setattr(key_location, "open_dump", fake_open)
    result = locate_key_across_dumps(corpus, SECRET)

    assert result.verdict == VERDICT_NOT_SEARCHED
    assert result.dumps_searched == 0
    assert result.verdict != VERDICT_ABSENT
    assert result.dumps_unreadable == 4
    assert all(d.present is None for d in result.dumps)


def test_a_view_shorter_than_the_needle_claims_nothing(corpus, tmp_path):
    tiny = tmp_path / "tiny.dump"
    tiny.write_bytes(b"0123456789")
    result = locate_key_across_dumps([corpus[0], tiny], SECRET)

    row = result.dumps[1]
    assert row.status == KEY_LOCATION_TOO_SMALL
    assert row.present is None
    assert row.size_for_view == 10
    assert "10" in row.detail and str(len(SECRET)) in row.detail
    assert result.dumps_too_small == 1
    assert result.verdict == VERDICT_FOUND


def test_every_occurrence_is_counted(tmp_path):
    """A TLS library keeps copies of one secret in several structs, so a
    two-hit dump is ordinary — not a bug to be collapsed to the first hit."""
    second = SECRET_OFFSET + 512
    path = _write_dump(tmp_path / "twice.dump",
                       plant_at=[SECRET_OFFSET, second])
    result = locate_key_across_dumps([path], SECRET)

    row = result.dumps[0]
    assert row.hit_count == 2
    assert row.offsets == (SECRET_OFFSET, second)
    assert row.first_offset == row.offsets[0]
    assert row.offsets_truncated is False
    assert result.total_hits == 2


def test_truncated_offsets_keep_the_true_hit_count(tmp_path):
    second = SECRET_OFFSET + 512
    path = _write_dump(tmp_path / "twice.dump",
                       plant_at=[SECRET_OFFSET, second])
    result = locate_key_across_dumps([path], SECRET, max_offsets=1)

    row = result.dumps[0]
    assert len(row.offsets) == 1
    assert row.offsets_truncated is True
    assert row.hit_count == 2


def test_on_source_runs_before_any_read(corpus):
    seen = []
    locate_key_across_dumps(corpus[:2], SECRET,
                            on_source=lambda s: seen.append(s.name))
    assert seen == [corpus[0].name, corpus[1].name]


def test_a_locked_container_propagates_instead_of_becoming_unreadable(corpus):
    """A forgotten key poisons EVERY answer in the set, so it must not be
    absorbed into one ``unreadable`` row. ``EncryptedDumpLockedError`` is a
    ``CapabilityError``, not a ``ValueError``, which is what lets it through
    the narrow ``except (OSError, ValueError)``."""
    def locked(_source):
        raise EncryptedDumpLockedError("no key supplied")

    with pytest.raises(EncryptedDumpLockedError):
        locate_key_across_dumps(corpus, SECRET, on_source=locked)


# ---------------------------------------------------------------------------
# located_export_pattern — per-dump windows
# ---------------------------------------------------------------------------

WINDOW_LEN = 128
KEY_OFFSET_IN_WINDOW = 40
KEY_LEN = 48


def _write_windowed_dump(path: Path, *, lead: int, key_byte: int) -> Path:
    prefix = bytes(range(KEY_OFFSET_IN_WINDOW))
    key = bytes([key_byte]) * KEY_LEN
    suffix = bytes(range(KEY_OFFSET_IN_WINDOW + KEY_LEN, WINDOW_LEN))
    window = prefix + key + suffix
    assert len(window) == WINDOW_LEN
    path.write_bytes(bytes([0x5A]) * lead + window + bytes(64))
    return path


def test_located_export_wildcards_land_on_the_key_span(tmp_path):
    a = _write_windowed_dump(tmp_path / "a.dump", lead=1000, key_byte=0xAA)
    b = _write_windowed_dump(tmp_path / "b.dump", lead=1500, key_byte=0xBB)

    out = located_export_pattern(
        [(a, 1000), (b, 1500)],
        WINDOW_LEN,
        key_offset=KEY_OFFSET_IN_WINDOW,
        key_length=KEY_LEN,
        fmt="json",
        return_regions=True,
    )

    tokens = out["pattern"]["wildcard_pattern"].split()
    assert len(tokens) == WINDOW_LEN
    key_span = tokens[KEY_OFFSET_IN_WINDOW:KEY_OFFSET_IN_WINDOW + KEY_LEN]
    assert set(key_span) == {"??"}
    assert "??" not in tokens[:KEY_OFFSET_IN_WINDOW]
    assert "??" not in tokens[KEY_OFFSET_IN_WINDOW + KEY_LEN:]

    assert out["region"] == {
        "offset": 1000,
        "length": WINDOW_LEN,
        "key_start": 1040,
        "key_end": 1088,
    }
    assert out["static_mask"][:KEY_OFFSET_IN_WINDOW] == [True] * 40
    assert len(out["regions"]) == 2
    assert out["regions"][0] != out["regions"][1]


def test_located_export_refuses_a_single_window(tmp_path):
    """``StaticChecker.check_regions([one])`` never enters its comparison loop
    and returns an all-True mask, i.e. a silent ``static_ratio == 1.0``."""
    a = _write_windowed_dump(tmp_path / "a.dump", lead=1000, key_byte=0xAA)
    with pytest.raises(TooFewDumpsError):
        located_export_pattern(
            [(a, 1000)], WINDOW_LEN,
            key_offset=KEY_OFFSET_IN_WINDOW, key_length=KEY_LEN,
        )


def test_located_export_rejects_a_key_span_outside_the_window(tmp_path):
    a = _write_windowed_dump(tmp_path / "a.dump", lead=1000, key_byte=0xAA)
    b = _write_windowed_dump(tmp_path / "b.dump", lead=1500, key_byte=0xBB)
    with pytest.raises(ValueError):
        located_export_pattern(
            [(a, 1000), (b, 1500)], WINDOW_LEN,
            key_offset=WINDOW_LEN - 8, key_length=KEY_LEN,
        )
