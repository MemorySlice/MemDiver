"""container_of join: accesses relative to a list link resolve to the containing struct."""

from __future__ import annotations

from memdiver.app import tools_code_evidence as tce
from memdiver.engine.code_evidence import FieldAccess

_LIST_HEAD = {"kind": "struct", "name": "list_head"}


def _types(sibling_offset=1400, with_sibling=True):
    fields = {
        "children": {"offset": 0x568, "type": _LIST_HEAD},
        "sibling": {"offset": sibling_offset, "type": _LIST_HEAD},
        "signal": {"offset": 2008, "type": {"kind": "base", "name": "long"}},
        "exit_state": {"offset": 1244, "type": {"kind": "base", "name": "int"}},
    }
    if not with_sibling:
        del fields["sibling"]
    return {"task_struct": {"size": 3000, "fields": fields},
            "list_head": {"size": 16, "fields": {
                "next": {"offset": 0, "type": {"kind": "base", "name": "long"}},
                "prev": {"offset": 8, "type": {"kind": "base", "name": "long"}}}},
            tce._BASES_KEY: {"long": {"size": 8}, "int": {"size": 4}}}


def _access(offset, delta, base="deref(current+0x568)"):
    return FieldAccess(1, base, offset, 8, "read", base_delta=delta)


def test_container_of_match():
    row = tce._access_row(_access(608, -1400), "c", _types())
    assert row["resolution"] == "container_of"
    assert row["isf_member"]["member"] == "signal" and row["isf_member"]["struct"] == "task_struct"
    assert row["inferred_via"] == "task_struct.children -> task_struct.sibling (static list table)"
    assert tce._access_row(_access(-156, -1400), "c", _types())["isf_member"]["member"] == "exit_state"


def test_delta_mismatch_stays_unresolved():
    row = tce._access_row(_access(608, -1000), "c", _types())
    assert row["resolution"] is None and row["isf_member"] is None
    assert "inferred_via" not in row


def test_delta_must_match_this_images_isf():
    row = tce._access_row(_access(608, -1400), "c", _types(sibling_offset=1384))
    assert row["resolution"] is None


def test_missing_isf_member_stays_unresolved():
    assert tce._access_row(_access(608, -1400), "c", _types(with_sibling=False))["resolution"] is None


def test_unlisted_list_member_stays_unresolved():
    row = tce._access_row(_access(608, -1400, "deref(current+0x4dc)"), "c", _types())
    assert row["resolution"] is None


def test_exact_rows_untouched_and_summary_counts():
    cur = FieldAccess(2, "current", 2008, 8, "read")
    accesses = [cur, _access(608, -1400), _access(608, -1000)]
    row = tce._access_row(cur, "c", _types())
    assert row["resolution"] == "exact" and "inferred_via" not in row

    class Ev:
        pass
    ev = Ev()
    ev.accesses = accesses
    summary = tce._isf_summary(ev, _types())
    assert (summary["checked"], summary["exact"], summary["container_of"],
            summary["unresolved"]) == (3, 1, 1, 1)
