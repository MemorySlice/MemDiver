"""Read windows tile a captured run exactly; a tail hit is reported once (all producers).

Regression for ``scan_plan.windows`` emitting one window too many whenever a run's
tail fell inside the overlap band: the tail was re-read, ``bytes_scanned`` exceeded
the captured bytes and a hit there was reported twice. Also YARA's own error
wording / codes and its documented seam rule.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from memdiver.algorithms.keyfinders.aes_tables import expand_key
from memdiver.app import scan_plan
from memdiver.app import tools_keyfinders as tk
from memdiver.app import tools_strings as ts
from memdiver.app import tools_yara as ty
from memdiver.core.service_errors import CapabilityError

W, O = 1024, 256
STEP = W - O
NEEDLE = b"SSLKEYLOGFILE"
RULE = 'rule keylog { strings: $a = "SSLKEYLOGFILE" condition: $a }'
SCHEDULE = expand_key(bytes(range(16, 32)))
#: Run lengths around every window boundary: one byte, < / == / just past a window,
#: inside the overlap band, on a step multiple, and several windows long.
LENGTHS = [1, 2, O - 1, O, O + 1, STEP - 1, STEP, STEP + 1, 900, W - 1, W, W + 1,
           2 * STEP, 2 * STEP + 1, STEP + W, STEP + W + 1, 3 * STEP + 100, 5 * W + 7]


@pytest.fixture
def small_windows(monkeypatch):
    monkeypatch.setattr(scan_plan, "WINDOW_BYTES", W)
    monkeypatch.setattr(scan_plan, "WINDOW_OVERLAP", O)


def _seg(length: int) -> scan_plan.Segment:
    return scan_plan.Segment(0, length, 0, None)


def _filler(length: int) -> bytes:
    return bytes(((1 + i * 7) % 251) + 1 for i in range(length))     # never a zero byte


def _raw(tmp_path, buf: bytes, name: str = "d.raw") -> str:
    path = tmp_path / name
    path.write_bytes(bytes(buf))
    return str(path)


# -- the planner -------------------------------------------------------------------


@pytest.mark.parametrize("length", [0] + LENGTHS)
def test_windows_tile_the_run_exactly(small_windows, length):
    seg = _seg(length)
    starts = scan_plan.windows(seg)
    wants = [scan_plan.window_want(seg, w) for w in starts]
    if length == 0:
        assert starts == []
        return
    assert [last for _, last in wants] == [False] * (len(starts) - 1) + [True]
    assert starts[-1] + wants[-1][0] == length          # the last window ends the run
    assert sum(scan_plan.owned_bytes(want, last) for want, last in wants) == length


@pytest.mark.parametrize("length, starts", [
    (90, [0]), (100, [0]), (101, [0, 80]), (180, [0, 80]), (181, [0, 80, 160]),
    (160, [0, 80]), (240, [0, 80, 160]), (241, [0, 80, 160])])
def test_reported_repro_lengths(monkeypatch, length, starts):
    monkeypatch.setattr(scan_plan, "WINDOW_BYTES", 100)
    monkeypatch.setattr(scan_plan, "WINDOW_OVERLAP", 20)
    assert scan_plan.windows(_seg(length)) == starts


@pytest.mark.parametrize("length", LENGTHS)
def test_every_offset_is_owned_by_exactly_one_window(small_windows, length):
    """Both seam rules (the shared one and YARA's) assign each start to one window."""
    seg = _seg(length)
    shared, yara = [0] * length, [0] * length
    for w in scan_plan.windows(seg):
        want, last = scan_plan.window_want(seg, w)
        for off in range(want):
            shared[w + off] += scan_plan.owns(off, w, last)
            yara[w + off] += ty._owns(off, last)
    assert set(shared) == {1} and set(yara) == {1}


def test_read_windows_runs_before_read_ahead_of_each_read(small_windows):
    events = []
    source = SimpleNamespace(read_range=lambda o, n, v: events.append(("read", o)) or bytes(n))
    plan = SimpleNamespace(source=source, read_view="raw")
    list(scan_plan.read_windows(plan, _seg(STEP + W + 1),
                                before_read=lambda: events.append(("poll", None))))
    assert events == [("poll", None), ("read", 0), ("poll", None), ("read", STEP),
                      ("poll", None), ("read", 2 * STEP)]


# -- the producers: a tail hit in the overlap band is reported once ----------------


TAIL_LENGTH = 1000                 # in (STEP, W]: one window, which the old grid doubled


def test_keyfinders_tail_hit_is_reported_once(tmp_path, small_windows):
    buf = bytearray(_filler(TAIL_LENGTH))
    buf[800:800 + len(SCHEDULE)] = SCHEDULE
    out = tk.keyfinders_scan_result(_raw(tmp_path, buf), finders=("aes_schedule",)).payload
    assert [r["addr"] for r in out["rows"]] == [800]
    assert out["coverage"]["bytes_scanned"] == TAIL_LENGTH


def test_strings_tail_hit_is_reported_once(tmp_path, small_windows):
    buf = bytearray(TAIL_LENGTH)
    buf[900:920] = b"S" * 20
    out = ts.strings_table_result(_raw(tmp_path, buf), encodings=("ascii",)).payload
    assert [(r["addr"], r["length"]) for r in out["rows"]] == [(900, 20)]
    assert out["coverage"]["bytes_scanned"] == TAIL_LENGTH


def test_yara_tail_hit_is_reported_once(tmp_path, small_windows):
    buf = bytearray(_filler(TAIL_LENGTH))
    buf[900:900 + len(NEEDLE)] = NEEDLE
    out = ty.yara_scan_dump_result(_raw(tmp_path, buf), RULE).payload
    assert [r["addr"] for r in out["rows"]] == [900]
    assert out["coverage"]["bytes_scanned"] == TAIL_LENGTH


@pytest.mark.parametrize("length", LENGTHS)
def test_bytes_scanned_equals_captured_bytes_for_every_producer(tmp_path, small_windows,
                                                                length):
    path = _raw(tmp_path, _filler(length))
    outs = [tk.keyfinders_scan_result(path, finders=("aes_schedule",)).payload,
            ts.strings_table_result(path, encodings=("ascii",)).payload,
            ty.yara_scan_dump_result(path, RULE).payload]
    for out in outs:
        cov = out["coverage"]
        assert cov["bytes_scanned"] == cov["captured_bytes"] == length


def test_yara_finds_a_needle_at_every_seam_position_exactly_once(tmp_path, small_windows):
    """Needles across the seam band of a multi-window run: each found once, none lost."""
    length = 4 * STEP + 50
    buf = bytearray(_filler(length))
    starts = list(range(STEP - 2 * len(NEEDLE), STEP + O, 37))
    starts = [s for s in starts if s + len(NEEDLE) <= length]
    for at in starts:
        buf[at:at + len(NEEDLE)] = NEEDLE
    out = ty.yara_scan_dump_result(_raw(tmp_path, buf), RULE).payload
    assert [r["addr"] for r in out["rows"]] == starts


# -- YARA words its own errors ------------------------------------------------------


def _source_of(fmt: str, packed: bool = True) -> SimpleNamespace:
    source = SimpleNamespace(format_name=fmt)
    if packed:
        source.captured_runs = lambda: []
    return source


def test_yara_check_view_uses_yara_wording_and_codes():
    with pytest.raises(CapabilityError) as bad_view:
        ty._check_view(_source_of("image_view"), "vas")
    assert bad_view.value.code == "yara.bad_view"
    with pytest.raises(CapabilityError) as bad_format:
        ty._check_view(_source_of("elf_core"), None)
    assert bad_format.value.code == "yara.unsupported_format"
    assert str(bad_format.value).startswith("YARA scans do not support 'elf_core' dumps")
    assert "key finders" not in str(bad_format.value)


def test_yara_producer_and_router_sizing_raise_yara_codes(tmp_path):
    path = _raw(tmp_path, bytes(64))
    with pytest.raises(CapabilityError) as producer:
        ty.yara_scan_dump_result(path, RULE, view="va")
    assert producer.value.code == "yara.bad_view"
    with pytest.raises(CapabilityError) as sizing:
        scan_plan.scan_size(path, "va", check=ty._check_view)
    assert sizing.value.code == "yara.bad_view"


def test_yara_rest_bad_view_carries_the_yara_code(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app

    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    try:
        r = TestClient(create_app()).post("/api/yara/scan", json={
            "dump_path": _raw(tmp_path, bytes(64)), "rule_source": RULE, "view": "va"})
    finally:
        get_settings.cache_clear()
    assert r.status_code == 400
    assert "yara.bad_view" in r.text and "keyfinders" not in r.text


# -- msl regions come from the open source ------------------------------------------


def test_msl_regions_match_the_inspect_vas_map(tmp_path):
    from memdiver.app.session import ToolSession
    from memdiver.app.tools_inspect import vas_regions_result
    from memdiver.core.dump_source import open_dump
    from memdiver.msl.enums import ArchType, OSType
    from memdiver.msl.types import MslVasEntry
    from memdiver.msl.writer import MslWriter

    path = tmp_path / "r.msl"
    writer = MslWriter(str(path), os_type=OSType.LINUX, arch_type=ArchType.X86_64, imported=True)
    writer.add_memory_region(0x400000, _filler(0x1000), protection=0x05)
    writer.add_vas_map([MslVasEntry(0x400000, 0x1000, 0x05, 0, "/bin/x"),
                        MslVasEntry(0x500000, 0x2000, 0x03, 0, "")])
    writer.add_end_of_capture()
    writer.write()
    entries = vas_regions_result(ToolSession(), str(path)).payload["vas_entries"]
    expected = [{"start": e["base_addr"], "end": e["base_addr"] + e["region_size"],
                 "perms": scan_plan.perms(e.get("protection")),
                 "path": e.get("mapped_path") or None, "type": e.get("region_type")}
                for e in entries]
    with open_dump(path) as source:
        assert scan_plan.msl_regions(source, path) == expected
    assert len(expected) == 2
