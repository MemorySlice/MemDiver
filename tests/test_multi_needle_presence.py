"""One-pass multi-needle presence == the old per-needle ``search_needles`` loop.

``present_needles`` replaced a full dump pass PER candidate secret in
``engine.keylog_anchors`` and ``app.tools_semantic``. These tests pin that the
answer did not change: same needles present, for every view/source strategy,
including needles straddling a window boundary, absent needles, needles that
occur twice, mixed needle lengths and an encrypted ``.msl``.
"""

from __future__ import annotations

import hashlib
import random
from pathlib import Path
from typing import List

import pytest

from memdiver.core import dump_search, dump_source
from memdiver.core.dump_search import present_needles
from memdiver.core.dump_source import MslDumpSource, RawDumpSource
from memdiver.engine.anchor_consensus import search_needles
from memdiver.msl.enums import RegionType
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

PAGE = 0x1000
WINDOW = 64  # tiny windows so boundaries are easy to straddle


def _rand(tag: str, n: int) -> bytes:
    out = b""
    k = 0
    while len(out) < n:
        out += hashlib.sha256(f"{tag}{k}".encode()).digest()
        k += 1
    return out[:n]


def _old_present(source, view: str, needle: bytes) -> bool:
    """The exact per-needle query the callers used before the refactor."""
    return bool(search_needles({"d": source}, {"d": needle}, view=view,
                               max_hits=1)["d"].anchors)


def _no_fallback(_needle: bytes) -> bool:
    raise AssertionError("a known source/view must not fall back to per-needle")


def _assert_equivalent(source, view: str, needles: List[bytes],
                       fallback_expected: bool = False) -> set:
    old = {n for n in needles if _old_present(source, view, n)}
    fallback = (lambda n: _old_present(source, view, n)) if fallback_expected else _no_fallback
    new = present_needles(source, needles, view, fallback)
    assert new == old
    return new


@pytest.fixture(autouse=True)
def _small_windows(monkeypatch):
    monkeypatch.setattr(dump_search, "_PRESENCE_WINDOW", WINDOW)
    monkeypatch.setattr(dump_source, "_VA_SEARCH_CHUNK", WINDOW)


# -- raw (contiguous mmap) strategy -------------------------------------------

def _raw_dump(tmp_path: Path, size: int, plants) -> Path:
    data = bytearray(_rand("fill", size))
    for at, needle in plants:
        data[at:at + len(needle)] = needle
    path = tmp_path / "flat.dump"
    path.write_bytes(bytes(data))
    return path


def test_raw_boundary_absent_twice_and_mixed_lengths(tmp_path):
    straddle = _rand("straddle", 32)          # starts 10 bytes before a boundary
    twice = _rand("twice", 16)
    long_one = _rand("long", 48)
    edge = _rand("edge", 32)                  # ends exactly at EOF
    absent = [_rand("absent", 32), _rand("absent2", 48)]
    size = 20 * WINDOW
    path = _raw_dump(tmp_path, size, [
        (3 * WINDOW - 10, straddle), (5, twice), (9 * WINDOW + 7, twice),
        (6 * WINDOW - 47, long_one), (size - 32, edge)])
    with RawDumpSource(path) as src:
        needles = [straddle, twice, long_one, edge, *absent, twice]  # dup input
        found = _assert_equivalent(src, "raw", needles)
    assert found == {straddle, twice, long_one, edge}


def test_raw_fuzz_matches_per_needle(tmp_path):
    rng = random.Random(1234)
    size = 13 * WINDOW + 5
    pool = [_rand(f"n{k}", rng.choice((16, 32, 48))) for k in range(24)]
    plants = [(rng.randrange(0, size - len(n)), n) for n in pool[:12]]
    path = _raw_dump(tmp_path, size, plants)
    with RawDumpSource(path) as src:
        # Some planted needles may be partially overwritten by later plants;
        # the comparison is against the old query, not against the plan.
        _assert_equivalent(src, "raw", pool)


def test_empty_file_and_no_needles(tmp_path):
    path = tmp_path / "empty.dump"
    path.write_bytes(b"")
    with RawDumpSource(path) as src:
        assert _assert_equivalent(src, "raw", [_rand("x", 32)]) == set()
        assert present_needles(src, [], "raw", lambda n: True) == set()


# -- .msl "va" and "raw" strategies -------------------------------------------

def _msl(tmp_path: Path, name: str, plants, encryption=None) -> Path:
    """Two ABUTTING regions (a straddle across the joint is real) and one
    behind a GAP; the second region has a FAILED page (never searched)."""
    a = bytearray(_rand("a", 2 * PAGE))
    b = bytearray(_rand("b", 2 * PAGE))
    c = bytearray(_rand("c", PAGE))
    regions = {"a": a, "b": b, "c": c}
    for region, at, needle in plants:
        regions[region][at:at + len(needle)] = needle
    w = MslWriter(tmp_path / name, pid=3, imported=False, encryption=encryption)
    w.add_memory_region(0x10000000, bytes(a), region_type=RegionType.HEAP)
    w.add_memory_region(0x10000000 + 2 * PAGE, bytes(b[:PAGE]), region_type=RegionType.HEAP,
                        page_states=[0, 2])
    w.add_memory_region(0x20000000, bytes(c), region_type=RegionType.ANONYMOUS)
    w.add_end_of_capture()
    w.write()
    return tmp_path / name


def _msl_needles():
    joint, window_edge, twice = _rand("joint", 32), _rand("wedge", 48), _rand("twice", 32)
    short = _rand("short", 16)
    plants = [("a", 2 * PAGE - 12, joint[:12]), ("b", 0, joint[12:]),
              ("a", 5 * WINDOW - 20, window_edge), ("a", 100, twice), ("c", 300, twice),
              ("c", PAGE - 16, short)]
    absent = [_rand("absent", 32), _rand("absent", 48), _rand("absent", 16)]
    return plants, [joint, window_edge, twice, short, *absent], {joint, window_edge, twice, short}


@pytest.mark.parametrize("encrypted", [False, True])
def test_msl_va_matches_per_needle(tmp_path, encrypted):
    plants, needles, expected = _msl_needles()
    key = bytes(range(32))
    enc = MslEncryptionConfig(raw_key=key) if encrypted else None
    path = _msl(tmp_path, f"cap{int(encrypted)}.msl", plants, enc)
    with MslDumpSource(path, key=key if encrypted else None) as src:
        assert _assert_equivalent(src, "va", needles) == expected
        _assert_equivalent(src, "raw", needles)  # container bytes, same answer


def test_msl_va_one_walk_per_length_not_per_needle(tmp_path, monkeypatch):
    plants, _needles, _ = _msl_needles()
    path = _msl(tmp_path, "count.msl", plants)
    needles = [_rand(f"miss{k}", 32) for k in range(10)]  # all absent: worst case
    with MslDumpSource(path) as src:
        calls = {"n": 0}
        real = src.read_range_valid

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(src, "read_range_valid", counting)
        for n in needles:
            _old_present(src, "va", n)
        old_reads = calls["n"]
        calls["n"] = 0
        present_needles(src, needles, "va", lambda n: pytest.fail("no fallback"))
        assert calls["n"] * len(needles) == old_reads


# -- fallback -----------------------------------------------------------------

class _FakeSource:
    def __init__(self, blob: bytes):
        self.blob, self.asked = blob, []

    def find_all(self, needle, view="raw", limit=0):
        self.asked.append(needle)
        return [i for i in range(len(self.blob)) if self.blob.startswith(needle, i)][:limit or None]


def test_unknown_source_uses_the_callers_per_needle_query():
    src = _FakeSource(b"xx" + _rand("hit", 16) + b"yy")
    needles = [_rand("hit", 16), _rand("miss", 16)]
    assert _assert_equivalent(src, "raw", needles, fallback_expected=True) == {needles[0]}
    assert src.asked == needles + needles  # old loop, then the same per-needle fallback


def test_unopened_msl_va_still_refuses(tmp_path):
    """The callers keep search_needles' refusal of an unopened VA view."""
    from memdiver.engine.keylog_anchors import _present_set

    plants, needles, _ = _msl_needles()
    src = MslDumpSource(_msl(tmp_path, "closed.msl", plants))
    with pytest.raises(ValueError, match="no open VA view"):
        _present_set(src, "closed.msl", needles, "va")
