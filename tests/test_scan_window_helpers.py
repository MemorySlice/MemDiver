"""Shared window / view / IOC helpers of the key-finder, strings and YARA producers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from memdiver.app import scan_plan
from memdiver.app import tools_keyfinders as tk
from memdiver.app import tools_strings as ts
from memdiver.core.service_errors import CapabilityError


class _Source:
    """A flat byte source that records every ``read_range`` and can short-read."""

    def __init__(self, data: bytes, short_at: int = -1) -> None:
        self.data, self.reads, self.short_at = data, [], short_at

    def read_range(self, offset: int, length: int, view: str) -> bytes:
        self.reads.append((offset, length))
        cut = length // 2 if offset == self.short_at else length
        return self.data[offset:offset + cut]


def _plan(source: _Source, *lengths: int) -> SimpleNamespace:
    segments, vas = [], 0
    for length in lengths:
        segments.append(scan_plan.Segment(vas, length, vas, None))
        vas += length
    return SimpleNamespace(source=source, read_view="raw", segments=segments)


@pytest.fixture
def small_windows(monkeypatch):
    monkeypatch.setattr(scan_plan, "WINDOW_BYTES", 100)
    monkeypatch.setattr(scan_plan, "WINDOW_OVERLAP", 20)


def test_window_want_and_owned_bytes(small_windows):
    seg = scan_plan.Segment(0, 230, 0, None)
    assert [scan_plan.window_want(seg, w) for w in scan_plan.windows(seg)] == [
        (100, False), (100, False), (70, True)]
    assert scan_plan.owned_bytes(100, False) == 80
    assert scan_plan.owned_bytes(50, False) == 50
    assert scan_plan.owned_bytes(70, True) == 70


def test_read_windows_matches_the_window_grid(small_windows):
    source = _Source(bytes(range(230)), short_at=80)
    plan = _plan(source, 230)
    wins = list(scan_plan.read_windows(plan, plan.segments[0]))
    assert [(w.offset, len(w.data), w.last, w.short) for w in wins] == [
        (0, 100, False, False), (80, 50, False, True), (160, 70, True, False)]
    assert wins[2].data == bytes(range(160, 230))


def test_read_windows_is_lazy(small_windows):
    source = _Source(bytes(250))
    plan = _plan(source, 250)
    next(iter(scan_plan.read_windows(plan, plan.segments[0])))
    assert len(source.reads) == 1


def _fake_collect(monkeypatch, per_window):
    from memdiver.algorithms.keyfinders import rsa_factor as rf

    calls = iter(per_window)
    monkeypatch.setattr(rf, "collect_moduli", lambda *a, **k: dict(next(calls)))


@pytest.mark.parametrize("cap", [0, 1, 2, 3, 10, -1])
def test_harvest_moduli_early_stop_keeps_first_seen_order(small_windows, monkeypatch, cap):
    per_window = [{1: {"k": "a"}, 2: {"k": "a"}}, {2: {"k": "b"}, 3: {"k": "b"}},
                  {4: {"k": "c"}}, {5: {"k": "d"}}]
    seen = {}
    for found in per_window:
        for n, info in found.items():
            seen.setdefault(n, {**info, "offset": None})
    expected = dict(list(seen.items())[:cap])
    _fake_collect(monkeypatch, per_window)
    source = _Source(bytes(400))
    plan = _plan(source, 150, 150)     # 2 windows per run, 4 in all
    assert tk._harvest_moduli(plan, {"rsa_max_moduli": cap}) == expected


def test_harvest_moduli_stops_reading_once_the_cap_is_met(small_windows, monkeypatch):
    _fake_collect(monkeypatch, [{1: {}, 2: {}}, {3: {}}, {4: {}}, {5: {}}])
    source = _Source(bytes(400))
    tk._harvest_moduli(_plan(source, 150, 150), {"rsa_max_moduli": 2})
    assert len(source.reads) == 1


def _source_of(fmt: str, packed: bool = True) -> SimpleNamespace:
    source = SimpleNamespace(format_name=fmt)
    if packed:
        source.captured_runs = lambda: []
    return source


@pytest.mark.parametrize("check, noun, usable, prefix", [
    (scan_plan.check_view, "key finders", "scannable", "keyfinders"),
    (ts._check_view, "strings", "available", "strings"),
])
def test_check_view_keeps_each_producers_wording(check, noun, usable, prefix):
    assert check(_source_of("msl"), None) == "va"
    assert check(_source_of("raw", packed=False), None) == "raw"
    with pytest.raises(CapabilityError) as bad_view:
        check(_source_of("image_view"), "vas")
    assert bad_view.value.code == f"{prefix}.bad_view"
    assert str(bad_view.value).startswith(
        f"view 'vas' is not {usable} for a 'image_view' dump; choose one of: va")
    with pytest.raises(CapabilityError) as bad_format:
        check(_source_of("elf_core"), None)
    assert bad_format.value.code == f"{prefix}.unsupported_format"
    assert str(bad_format.value).startswith(f"{noun} do not support 'elf_core' dumps")


@pytest.mark.parametrize("value", [
    "", "hello world", "peer 8.8.8.8 oid 1.3.6.1", "oid 1.3.6.1.4.1 and 2.5.4.3",
    "1.3.6.1", "see https://example.com/x and 10.0.0.1", "/etc/passwd 2.5.29.17",
])
def test_ioc_fields_match_the_analysis_helpers(value):
    from memdiver.analysis.queries.strings import ioc_ambiguity, ioc_kinds, oid_like_values

    ambiguity, oid_prefix = ioc_ambiguity(value) or (None, None)
    assert ts._ioc_fields(value) == {
        "iocs": ioc_kinds(value), "ambiguity": ambiguity, "oid_prefix": oid_prefix,
        "oid_like_values": [{"value": v, "oid_prefix": p} for v, p in oid_like_values(value)]}


# -- the shared planner module and its legacy aliases ----------------------------


@pytest.mark.parametrize("name", [
    "_Segment", "_Plan", "_Regions", "_Window", "_invalid", "_merged", "_check_view",
    "_clipped", "_segments_of", "_heap_view_of", "_build_plan", "_perms", "_msl_regions",
    "_vma_regions", "_regions_of", "_windows", "_window_want", "_owned_bytes",
    "_read_windows", "_owns", "_gap_stats", "_coverage", "_incomplete_reason",
    "_dump_file", "_scan_size", "WINDOW_BYTES", "WINDOW_OVERLAP",
])
def test_keyfinders_no_longer_re_exports_the_planner(name):
    """The planner lives in scan_plan only; a stale snapshot here would be a no-op patch."""
    assert not hasattr(tk, name)


def test_window_constants_are_read_from_scan_plan(small_windows):
    seg = scan_plan.Segment(0, 230, 0, None)
    assert scan_plan.windows(seg) == [0, 80, 160]
    assert scan_plan.owns(10, 0, False) and not scan_plan.owns(95, 0, False)


def test_scan_size_and_build_plan_word_errors_with_the_given_check(tmp_path):
    dump = tmp_path / "flat.raw"
    dump.write_bytes(bytes(64))
    assert scan_plan.scan_size(str(dump)) == 64
    assert ts._scan_size(str(dump), region=(8, 16)) == 16
    with pytest.raises(CapabilityError) as kf:
        scan_plan.scan_size(str(dump), "va")
    assert kf.value.code == "keyfinders.bad_view"
    with pytest.raises(CapabilityError) as st:
        ts._scan_size(str(dump), "va")
    assert st.value.code == "strings.bad_view"


def test_open_end_is_not_the_same_as_no_length_for_high_addresses():
    """Why strings keeps its ``(offset, OPEN_END)`` region: it cuts addresses >= 2**62."""
    low, high = scan_plan.Segment(0x1000, 16, 0, 0x1000), scan_plan.Segment(1 << 63, 16, 16, 1 << 63)
    assert scan_plan.clipped([low], 0, ts.OPEN_END) == scan_plan.clipped([low], None, None)
    assert scan_plan.clipped([high], 0, ts.OPEN_END) == []
    assert scan_plan.clipped([high], None, None) == [high]
