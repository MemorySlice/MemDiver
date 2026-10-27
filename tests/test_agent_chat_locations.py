"""extract_locations: navigable {dump_path, va|offset} dicts from a tool's JSON result."""

from __future__ import annotations

import json

from memdiver.app.agent_chat.locations import MAX_LOCATIONS, extract_locations


def test_nested_dicts_are_normalised():
    body = {"hits": [{"dump_path": "/d/a.msl", "va": 4096, "score": 1},
                     {"path": "/d/b.raw", "offset": 12, "extra": "x"}],
            "meta": {"inner": {"dump_path": "/d/c", "offset": 0}}}
    assert extract_locations(json.dumps(body)) == [
        {"dump_path": "/d/a.msl", "va": 4096},
        {"dump_path": "/d/b.raw", "offset": 12},
        {"dump_path": "/d/c", "offset": 0}]


def test_va_and_offset_both_kept_and_incomplete_dicts_are_skipped():
    body = [{"dump_path": "/d", "va": 1, "offset": 2}, {"dump_path": "/d"},
            {"va": 5}, {"dump_path": "/d", "va": True}, {"dump_path": "/d", "va": "0x10"}]
    assert extract_locations(json.dumps(body)) == [{"dump_path": "/d", "va": 1, "offset": 2}]


def test_offset_carries_its_view_but_a_bare_va_does_not():
    # An anchor's offset is relative to its view (span-relative for "va"): dropping the
    # view would make the browser scroll the wrong bytes.
    body = [{"dump_path": "/d", "offset": 4096, "view": "va", "va": None},
            {"dump_path": "/e", "va": 7, "view": "va"},
            {"dump_path": "/f", "offset": 3, "view": 9}]
    assert extract_locations(json.dumps(body)) == [
        {"dump_path": "/d", "offset": 4096, "view": "va"},
        {"dump_path": "/e", "va": 7},
        {"dump_path": "/f", "offset": 3}]


def test_capped_and_non_json_yield_nothing():
    many = [{"dump_path": "/d", "offset": i} for i in range(MAX_LOCATIONS + 5)]
    assert len(extract_locations(json.dumps(many))) == MAX_LOCATIONS
    assert extract_locations("not json") == [] and extract_locations("") == []
    assert extract_locations('{"truncated": ') == []
