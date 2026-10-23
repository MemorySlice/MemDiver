"""Scudo primary-region parser (heap/allocators/scudo.py) vs synth fixtures."""
from __future__ import annotations

import random
import struct
from typing import Iterable, Optional

import pytest

from memdiver.heap.allocators import scudo
from memdiver.heap.model import AllocatorKind, ChunkState, HeapRole
from memdiver.heap.platform import MappedRegion, TargetPlatform
from memdiver.heap.registry import DetectContext, ParseOptions
from tests.fixtures import synth_heap as sh

ARM64 = TargetPlatform("android", "arm64", 8, "little", "test")
PRIMARY = "[anon:scudo:primary]"


class FakeMemory:
    """In-memory VaMemory stand-in; pages in *missing* read as uncaptured."""

    def __init__(self, heap: sh.SynthHeap, missing: Iterable[int] = ()):
        self.heap = heap
        self.platform = ARM64
        self.missing = set(missing)

    def read(self, va: int, n: int) -> Optional[bytes]:
        first, last = va // sh.PAGE, (va + n - 1) // sh.PAGE
        if any(page * sh.PAGE in self.missing for page in range(first, last + 1)):
            return None
        try:
            return self.heap.read(va, n)
        except ValueError:
            return None


def _regions(heap: sh.SynthHeap, name: Optional[str] = None):
    return [MappedRegion(va, size, "rw-p", name if name is not None else n,
                         None, True) for va, size, n in heap.regions]


def _ctx(heap: sh.SynthHeap, memory=None, name: Optional[str] = None):
    ctx = DetectContext(None, platform=ARM64, regions=_regions(heap, name),
                        modules=[])
    ctx.__dict__["memory"] = memory or FakeMemory(heap)
    return ctx


def _parse(heap: sh.SynthHeap, opts: ParseOptions = ParseOptions(), **kw):
    ctx = _ctx(heap, **kw)
    return scudo.parse_scudo(ctx.memory, ctx, opts)


def _assert_matches(layout, expected):
    got = [(c.va, c.size, c.state, c.header_len, c.user_len, c.bin)
           for c in layout.chunks]
    want = [(e.va, e.size, e.state, e.header_len, e.user_len, e.bin)
            for e in expected]
    assert got == want


# -- header decode ---------------------------------------------------------------


def test_header_decode_matches_fixture_packer():
    rng = random.Random(7)
    for _ in range(500):
        word = rng.getrandbits(64)
        header = scudo.ScudoHeader.decode(word)
        unpacked = sh.scudo_unpack_header(word)
        assert header.extra() == {
            "class_id": unpacked["class_id"], "origin": unpacked["origin"],
            "size_or_unused": unpacked["size"], "offset": unpacked["offset"],
            "checksum": unpacked["checksum"]}
        assert header.state == unpacked["state"]


def test_structural_score_components():
    good = scudo.ScudoHeader.decode(sh.scudo_pack_header(10, 1, 0x100))
    assert scudo.structural_score(good, 10, 0x200, True) == 1.0
    assert scudo.structural_score(good, 10, 0x200, False) == 0.8
    assert scudo.structural_score(good, 11, 0x200, True) < 0.2
    too_big = scudo.ScudoHeader.decode(sh.scudo_pack_header(10, 1, 0x1F8))
    assert scudo.structural_score(too_big, 10, 0x200, True) == 0.8
    bad_state = scudo.ScudoHeader.decode(sh.scudo_pack_header(10, 3, 0x100))
    assert scudo.structural_score(bad_state, 10, 0x200, True) < 0.2


# -- parse ------------------------------------------------------------------------


def test_parse_regioned_fixture_exact(tmp_path):
    heap = sh.scudo_primary()
    source = sh.open_regioned(sh.as_regioned_raw(tmp_path, [heap]))
    try:
        ctx = DetectContext(source)
        layout = scudo.parse_scudo(ctx.memory, ctx, ParseOptions())
    finally:
        source.close()
    assert layout.allocator is AllocatorKind.SCUDO
    _assert_matches(layout, heap.chunks)
    assert {c.extra["class_id"] for c in layout.chunks} == {10}
    assert all(c.confidence == 1.0 for c in layout.chunks)
    assert layout.confidence == 1.0
    assert layout.coverage["uncaptured_pages"] == 0
    assert [r.kind for r in layout.regions] == ["primary"]


def test_extra_fields_and_states():
    heap = sh.scudo_primary()
    layout = _parse(heap)
    states = [c.state for c in layout.chunks]
    assert ChunkState.QUARANTINED in states and ChunkState.FREE in states
    first = layout.chunks[0]
    assert first.extra["checksum"] == 0xBEEF
    assert first.extra["offset"] == 0 and first.extra["origin"] == 0
    assert first.extra["size_or_unused"] == first.user_len


def test_free_chunk_roles():
    layout = _parse(sh.scudo_primary())
    free = next(c for c in layout.chunks if c.state is ChunkState.FREE)
    runs = list(layout.role_runs(free.va, free.end))
    assert runs[0] == (free.va, 16, HeapRole.CHUNK_HEADER)
    assert runs[1] == (free.user_va, free.user_len, HeapRole.FREE_DATA)


def test_corrupt_header_becomes_unknown():
    heap = sh.scudo_primary()
    data = bytearray(heap.data)
    for slot in (3, 5):
        struct.pack_into("<Q", data, slot * 0x200, 0x4141_4141_4141_4141)
    heap.data = bytes(data)
    layout = _parse(heap)
    assert len(layout.chunks) == len(heap.chunks)
    for slot in (3, 5):
        bad = layout.chunks[slot]
        assert bad.state is ChunkState.UNKNOWN and bad.confidence < 0.6
        assert bad.user_len == 0x200 - scudo.HEADER_LEN
    assert layout.chunks[2].confidence == 1.0   # slot 1 still agrees
    isolated = layout.chunks[4]                 # both neighbours corrupt
    assert isolated.confidence == 0.8
    assert isolated.state is ChunkState.QUARANTINED
    assert 0.5 < layout.confidence < 1.0


def test_two_classes_in_one_region():
    small = sh.scudo_primary(class_id=3, block_size=0x40)
    large = sh.scudo_primary(base_va=small.base_va + sh.PAGE, class_id=12,
                             block_size=0x400)
    va = small.base_va
    heap = sh.SynthHeap(small.data + large.data, va, "scudo", 8,
                        [(va, 2 * sh.PAGE, PRIMARY)],
                        small.chunks + large.chunks)
    layout = _parse(heap)
    _assert_matches(layout, heap.chunks)


def test_unnamed_region_is_walked_when_plausible():
    layout = _parse(sh.scudo_primary(), name="")
    assert len(layout.chunks) == 8
    assert any("no [anon:scudo:primary]" in d for d in layout.diagnostics)


def test_partial_capture_skips_missing_page():
    heap = sh.scudo_primary(region_size=2 * sh.PAGE)
    missing = heap.base_va
    layout = _parse(heap, memory=FakeMemory(heap, [missing]))
    _assert_matches(layout, heap.chunks[8:])
    assert layout.coverage["uncaptured_pages"] == 1
    assert layout.coverage["bytes_captured"] == sh.PAGE
    assert any("uncaptured" in d for d in layout.diagnostics)


def test_uncaptured_region_yields_no_chunks():
    heap = sh.scudo_primary()
    layout = _parse(heap, memory=FakeMemory(heap, [heap.base_va]))
    assert layout.chunks == () and layout.confidence == 0.0


def test_max_chunks_cap():
    layout = _parse(sh.scudo_primary(), ParseOptions(max_chunks=3))
    assert len(layout.chunks) == 3
    assert layout.coverage["truncated"] is True
    assert any("max_chunks" in d for d in layout.diagnostics)


def test_region_filter_excludes():
    layout = _parse(sh.scudo_primary(), ParseOptions(regions=("[heap]",)))
    assert layout.chunks == ()


def test_secondary_region_listed_with_diagnostic():
    heap = sh.scudo_primary()
    secondary = sh.SynthHeap(bytes(sh.PAGE), 0x7B00_0000_0000, "scudo", 8,
                             [(0x7B00_0000_0000, sh.PAGE,
                               "[anon:scudo:secondary]")], [])
    ctx = DetectContext(None, platform=ARM64,
                        regions=_regions(heap) + _regions(secondary),
                        modules=[])
    layout = scudo.parse_scudo(FakeMemory(heap), ctx, ParseOptions())
    assert [r.kind for r in layout.regions] == ["primary", "secondary"]
    assert any("LargeBlock" in d for d in layout.diagnostics)
    assert len(layout.chunks) == 8


# -- probe ------------------------------------------------------------------------


def test_probe_high_on_fixture(tmp_path):
    heap = sh.scudo_primary()
    source = sh.open_regioned(sh.as_regioned_raw(tmp_path, [heap]))
    try:
        result = scudo.probe_scudo(DetectContext(source))
    finally:
        source.close()
    assert result.score >= 0.8
    assert result.evidence and result.evidence[0].source == "content"


def test_probe_low_on_random_region(tmp_path):
    heap = sh.random_region()
    source = sh.open_regioned(sh.as_regioned_raw(tmp_path, [heap]))
    try:
        assert scudo.probe_scudo(DetectContext(source)).score < 0.2
    finally:
        source.close()


def test_random_false_positive_rate_below_one_percent():
    seeds = range(200)
    hits = sum(scudo.probe_scudo(_ctx(sh.random_region(seed=s), name=PRIMARY))
               .score >= 0.2 for s in seeds)
    assert hits / len(seeds) < 0.01


@pytest.mark.parametrize("seed", range(5))
def test_random_named_region_parses_to_no_chunks(seed):
    layout = _parse(sh.random_region(seed=seed, region_size=4 * sh.PAGE),
                    name=PRIMARY)
    assert layout.chunks == ()


def test_descriptor_overrides():
    probe, parse = scudo.DESCRIPTOR_OVERRIDES[AllocatorKind.SCUDO]
    assert probe is scudo.probe_scudo and parse is scudo.parse_scudo
