"""Store semantics of the analysis record (plan T1.5): append-only JSONL per capture."""
from __future__ import annotations

import json
import threading

import pytest

from memdiver.analysis.record import (ANNOTATION, KEY_HIT, RETRACTION,
                                      AnalysisEntry, retraction_of)
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.core.location import AddressSpace, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory

CAP = "a" * 64


def _entry(label="x", capture=CAP, **kw) -> AnalysisEntry:
    kw.setdefault("kind", ANNOTATION)
    kw.setdefault("author", "human")
    return AnalysisEntry(capture_id=capture, label=label, **kw)


@pytest.fixture
def record(tmp_path):
    return AnalysisRecord(tmp_path / "case")


def test_append_creates_dirs_and_one_line_per_entry(record, tmp_path):
    a = record.append(_entry("a"))
    record.append(_entry("b"))
    path = tmp_path / "case" / "annotations" / f"{CAP}.jsonl"
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["id"] == a.id
    assert path.read_text().endswith("\n")


def test_entries_preserve_order_and_filter_by_kind(record):
    record.append(_entry("a"))
    record.append(_entry("b", kind=KEY_HIT))
    assert [e.label for e in record.entries(CAP)] == ["a", "b"]
    assert [e.label for e in record.entries(CAP, KEY_HIT)] == ["b"]
    assert record.entries("never-written") == []


def test_roundtrip_keeps_locations(record):
    loc = Location(AddressSpace.PROCESS_VA, 0x7F00, pid=42)
    record.append(_entry(locations=(loc,), length=16))
    got = record.entries(CAP)[0]
    assert got.locations == (loc,) and got.length == 16


def test_latest_follows_supersede_chain(record):
    first = record.append(_entry("v1"))
    second = record.append(_entry("v2", supersedes=first.id))
    third = record.append(_entry("v3", supersedes=second.id))
    assert [e.id for e in record.latest(CAP)] == [third.id]
    assert [e.id for e in record.history(CAP, first.id)] == [first.id, second.id, third.id]
    assert [e.id for e in record.history(CAP, third.id)] == [first.id, second.id, third.id]


def test_branch_yields_two_tips_and_history_follows_last_writer(record):
    root = record.append(_entry("root"))
    left = record.append(_entry("left", supersedes=root.id))
    right = record.append(_entry("right", supersedes=root.id))
    assert {e.id for e in record.latest(CAP)} == {left.id, right.id}
    assert [e.id for e in record.history(CAP, root.id)] == [root.id, right.id]


def test_retraction_hides_entry_and_itself(record):
    keep = record.append(_entry("keep"))
    gone = record.append(_entry("gone"))
    record.append(retraction_of(gone, "human", "wrong"))
    assert [e.id for e in record.latest(CAP)] == [keep.id]
    assert [e.kind for e in record.entries(CAP)].count(RETRACTION) == 1
    assert len(record.entries(CAP)) == 3  # nothing deleted


def test_latest_kind_filter(record):
    record.append(_entry("a"))
    hit = record.append(_entry("b", kind=KEY_HIT))
    assert [e.id for e in record.latest(CAP, KEY_HIT)] == [hit.id]


def test_unknown_supersedes_is_refused_and_writes_nothing(record, tmp_path):
    with pytest.raises(CapabilityError) as err:
        record.append(_entry(supersedes="deadbeef"))
    assert err.value.category is ErrorCategory.INVALID_INPUT
    assert not (tmp_path / "case" / "annotations").exists()


def test_supersedes_must_exist_in_the_same_capture(record):
    other = record.append(_entry(capture="other"))
    with pytest.raises(CapabilityError):
        record.append(_entry(supersedes=other.id))


def test_duplicate_id_refused(record):
    first = record.append(_entry())
    with pytest.raises(CapabilityError):
        record.append(first)


def test_get_unknown_is_not_found(record):
    record.append(_entry())
    with pytest.raises(CapabilityError) as err:
        record.get(CAP, "nope")
    assert err.value.category is ErrorCategory.NOT_FOUND


def test_corrupt_line_names_file_and_line(record, tmp_path):
    record.append(_entry())
    path = tmp_path / "case" / "annotations" / f"{CAP}.jsonl"
    with open(path, "a") as handle:
        handle.write("{not json\n")
    with pytest.raises(CapabilityError) as err:
        record.entries(CAP)
    assert f"{CAP}.jsonl" in str(err.value) and "line 2" in str(err.value)
    assert err.value.details["line"] == 2
    with pytest.raises(CapabilityError):
        record.append(_entry())  # appends never build on a corrupt file


def test_wrong_schema_version_is_corrupt(record, tmp_path):
    path = tmp_path / "case" / "annotations" / f"{CAP}.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text('{"v": 99}\n')
    with pytest.raises(CapabilityError, match="line 1"):
        record.entries(CAP)


def test_per_capture_files_and_captures_listing(record):
    record.append(_entry(capture="cap-b"))
    record.append(_entry(capture="cap-a"))
    assert record.captures() == ["cap-a", "cap-b"]
    assert [e.capture_id for e in record.entries("cap-a")] == ["cap-a"]
    assert AnalysisRecord(record.case_dir / "empty").captures() == []


def test_invalid_capture_id_is_input_error(record):
    with pytest.raises(CapabilityError) as err:
        record.entries("../evil")
    assert err.value.category is ErrorCategory.INVALID_INPUT


def test_concurrent_appends_produce_valid_lines(record, tmp_path):
    def worker(n):
        for i in range(50):
            record.append(_entry(f"{n}-{i}"))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    path = tmp_path / "case" / "annotations" / f"{CAP}.jsonl"
    lines = path.read_text().splitlines()
    assert len(lines) == 400
    ids = {json.loads(line)["id"] for line in lines}
    assert len(ids) == 400
    assert len(record.entries(CAP)) == 400
