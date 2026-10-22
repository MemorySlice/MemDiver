"""Bounded-memory ``"vas"`` search for .msl and gcore sources (W5).

Every new in-place search path is checked HIT-FOR-HIT against a frozen copy of
the copying implementation it replaced, over fixtures that put needles at run
starts/ends, across run boundaries, under a limit and nowhere at all — for
plaintext, compressed-free encrypted (seekable and one-shot) containers — plus
a tracemalloc bound on a multi-hundred-MiB container.
"""

from __future__ import annotations

import os
import random
import struct
import tracemalloc
from pathlib import Path
from typing import List, Optional
from uuid import UUID, uuid4

import pytest

from memdiver.core.binary_formats.elf_core_reader import (
    ELF_MAGIC, ELFCLASS64, ELFDATA2LSB, ET_CORE, PF_R, PT_LOAD, _EHDR64_SIZE,
    _PHDR64_FMT, _PHDR64_SIZE,
)
from memdiver.core.dump_io import find_all_offsets
from memdiver.core.dump_source import MslDumpSource, open_dump
from memdiver.core.dump_sources.gcore import GCoreDumpSource
from memdiver.msl import reader as reader_module
from memdiver.msl.aead_seek import ONESHOT_ENV, DecryptedView
from memdiver.msl.block_iter import merge_continuations
from memdiver.msl.decoders import decode_memory_region
from memdiver.msl.enums import BlockFlag, BlockType, EncAlgo, PageState
from memdiver.msl.reader import (CapturedRun, CapturedRunIndex, MslReader,
                                 _captured_page_runs, _iter_find_windowed)
from memdiver.msl.types import MslBlockHeader
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

PAGE = 4096
C, F, U = PageState.CAPTURED, PageState.FAILED, PageState.UNMAPPED
NEEDLE = b"KEY!SECRET"


# ------------------------------------------------- frozen old implementations

def old_msl_find_all(src: MslDumpSource, needle: bytes, limit: int = 0) -> List[int]:
    """The pre-W5 ``MslDumpSource.find_all(view='vas')`` (copies each run)."""
    offsets: List[int] = []
    flat_offset = 0
    for _vaddr, _length, chunk in src.iter_ranges():
        for idx in find_all_offsets(chunk, needle):
            offsets.append(flat_offset + idx)
            if limit and len(offsets) >= limit:
                return offsets
        flat_offset += len(chunk)
    return offsets


def old_msl_find_first(src: MslDumpSource, needle: bytes) -> Optional[int]:
    """The pre-W5 ``MslDumpSource.find_first(view='vas')``."""
    flat_offset = 0
    for _vaddr, _length, chunk in src.iter_ranges():
        idx = chunk.find(needle) if needle else -1
        if idx >= 0:
            return flat_offset + idx
        flat_offset += len(chunk)
    return None


def old_collect_regions(reader: MslReader):
    """The pre-W5 ``collect_regions``: decode every MERGED full payload."""
    out = []
    for h, p in reader.iter_blocks():
        if h.block_type == BlockType.MEMORY_REGION:
            try:
                out.append(decode_memory_region(h, p, reader._byte_order))
            except Exception:  # noqa: BLE001 — mirror _collect's skip
                pass
    return out


def old_captured_run_index(reader: MslReader) -> CapturedRunIndex:
    """The pre-W5 ``captured_run_index``, built from :func:`old_collect_regions`."""
    from memdiver.msl.page_map import count_captured_pages
    buf_len = reader.buffer_length
    runs = []
    vas_offset = 0
    for region in sorted(old_collect_regions(reader), key=lambda r: r.base_addr):
        page_size = int(region.page_size)
        map_bytes = ((int(region.num_pages) + 3) // 4 + 7) & ~7
        base = int(region.block_header.payload_offset) + 0x20 + map_bytes
        region_avail = max(0, min(count_captured_pages(region.page_states) * page_size,
                                  buf_len - base))
        data_offset = 0
        for start_page, page_count in _captured_page_runs(region):
            length = page_count * page_size
            runs.append(CapturedRun(
                va_start=int(region.base_addr) + start_page * page_size,
                length=length, buf_offset=base + data_offset,
                avail=max(0, min(length, region_avail - data_offset)),
                vas_offset=vas_offset))
            data_offset += length
            vas_offset += length
    by_va = tuple(sorted(runs, key=lambda r: r.va_start))
    return CapturedRunIndex(tuple(runs), by_va, tuple(r.va_start for r in by_va),
                            tuple(r.vas_offset for r in runs))


def old_gcore_find_all(src: GCoreDumpSource, needle: bytes) -> List[int]:
    """The pre-W5 ``GCoreDumpSource._find_all_vas`` (``mm[a:b] + tail``)."""
    hits: List[int] = []
    mm = src._reader._mmap
    if not needle or not src._vas_segments or mm is None:
        return hits
    overlap = len(needle) - 1
    for idx, seg in enumerate(src._vas_segments):
        seg_bytes = mm[seg.file_offset:seg.file_offset + seg.filesz]
        vas_base = src._vas_cum[idx]
        window = seg_bytes
        if overlap > 0:
            tail = src._read_vas_range(vas_base + seg.filesz, overlap)
            if tail:
                window = seg_bytes + tail
        start = 0
        while True:
            at = window.find(needle, start)
            if at == -1 or at >= seg.filesz:
                break
            hits.append(vas_base + at)
            start = at + 1
    return hits


def old_gcore_find_first(src: GCoreDumpSource, needle: bytes) -> Optional[int]:
    """The pre-W5 ``GCoreDumpSource._find_first_vas``."""
    mm = src._reader._mmap
    if not needle or not src._vas_segments or mm is None:
        return None
    overlap = len(needle) - 1
    for idx, seg in enumerate(src._vas_segments):
        seg_bytes = mm[seg.file_offset:seg.file_offset + seg.filesz]
        vas_base = src._vas_cum[idx]
        window = seg_bytes
        if overlap > 0:
            tail = src._read_vas_range(vas_base + seg.filesz, overlap)
            if tail:
                window = seg_bytes + tail
        at = window.find(needle, 0)
        if at != -1 and at < seg.filesz:
            return vas_base + at
    return None


# ------------------------------------------------------------------ fixtures

def _region_specs(seed: int = 7):
    """Regions with FAILED/UNMAPPED gaps (several runs each) and planted needles.

    Needles sit at run starts, run ends, straddling a run boundary (inside one
    region, across a FAILED gap), straddling two regions, and overlapping
    (``AAAA`` in ``AAAAAA``) so overlap counting is exercised.
    """
    rng = random.Random(seed)
    specs = []
    layouts = [
        [C, C, F, C, C, C, U, C],
        [C] * 5,
        [F, C, C, U, U, C],
        [C, F, C, F, C],
    ]
    base = 0x10000
    for li, states in enumerate(layouts):
        captured = sum(1 for s in states if s == C)
        data = bytearray(rng.randbytes(captured * PAGE))
        n = len(NEEDLE)
        data[0:n] = NEEDLE                                  # region/run start
        data[len(data) - n:] = NEEDLE                       # region/run end
        data[2 * PAGE - 4:2 * PAGE - 4 + n] = NEEDLE        # straddles page 1/2
        data[PAGE + 100:PAGE + 106] = b"AAAAAA"             # overlapping hits
        specs.append((base, bytes(data), [int(s) for s in states]))
        base += (len(states) + 3 + li) * PAGE
    # Two VA-adjacent regions with a needle split across them.
    left = bytearray(rng.randbytes(2 * PAGE))
    right = bytearray(rng.randbytes(2 * PAGE))
    left[-5:] = NEEDLE[:5]
    right[:5] = NEEDLE[5:]
    specs.append((base, bytes(left), None))
    specs.append((base + 2 * PAGE, bytes(right), None))
    return specs


def _write_msl(path: Path, encryption=None, specs=None) -> Path:
    w = MslWriter(path, pid=1, encryption=encryption)
    for base, data, states in (specs or _region_specs()):
        w.add_memory_region(base, data, page_states=states)
    w.add_end_of_capture()
    w.write()
    return path


@pytest.fixture
def plain_msl(tmp_path):
    return _write_msl(tmp_path / "plain.msl")


@pytest.fixture
def enc_msl(tmp_path, monkeypatch):
    monkeypatch.delenv(ONESHOT_ENV, raising=False)
    key = os.urandom(32)
    path = _write_msl(tmp_path / "enc.msl", MslEncryptionConfig(
        enc_algo=EncAlgo.AES_256_GCM, raw_key=key))
    return path, key


NEEDLES = [NEEDLE, b"AAAA", b"AA", b"A", NEEDLE[:5], NEEDLE[5:],
           b"\x00\x01\x02-not-present-\xff", b""]


def _assert_msl_equivalent(src: MslDumpSource):
    for needle in NEEDLES:
        assert src.find_all(needle, view="vas") == old_msl_find_all(src, needle), needle
        assert src.find_first(needle, view="vas") == old_msl_find_first(src, needle), needle
        for limit in (1, 2, 3, 7):
            assert (src.find_all(needle, view="vas", limit=limit)
                    == old_msl_find_all(src, needle, limit)), (needle, limit)


# --------------------------------------------------- msl equivalence tests

def test_msl_vas_hits_match_frozen_copying_search(plain_msl):
    with open_dump(plain_msl) as src:
        assert len(src.find_all(NEEDLE, view="vas")) >= 4
        _assert_msl_equivalent(src)


def test_msl_cross_run_needle_still_not_a_vas_match(plain_msl):
    """Per-run semantics kept: the needle split over two adjacent regions is
    found by ``"va"`` but not by ``"vas"``."""
    with open_dump(plain_msl) as src:
        vas_hits = src.find_all(NEEDLE, view="vas")
        va_hits = src.find_all(NEEDLE, view="va")
        assert len(va_hits) > len(vas_hits)
        for off in vas_hits:
            assert src.read_range(off, len(NEEDLE), view="vas") == NEEDLE


def test_msl_encrypted_seekable_matches_frozen(enc_msl, monkeypatch):
    path, key = enc_msl
    monkeypatch.setattr(reader_module, "FIND_WINDOW", 64)  # force many windows
    with open_dump(path, key=key) as src:
        assert isinstance(src.get_reader()._buf, DecryptedView)
        _assert_msl_equivalent(src)


def test_msl_encrypted_default_window_matches_frozen(enc_msl):
    path, key = enc_msl
    with open_dump(path, key=key) as src:
        _assert_msl_equivalent(src)


def test_msl_encrypted_oneshot_matches_frozen(enc_msl, monkeypatch):
    path, key = enc_msl
    monkeypatch.setenv(ONESHOT_ENV, "1")
    with open_dump(path, key=key) as src:
        assert isinstance(src.get_reader()._buf, bytes)
        _assert_msl_equivalent(src)


def test_msl_encrypted_without_key_finds_nothing(enc_msl):
    path, _key = enc_msl
    with open_dump(path) as src:
        assert src.find_all(NEEDLE, view="vas") == []
        assert src.find_first(NEEDLE, view="vas") is None


def test_msl_filtered_view_matches_frozen(plain_msl):
    with open_dump(plain_msl) as src:
        src.set_region_filter("heap")
        _assert_msl_equivalent(src)


def test_msl_unopened_source_returns_empty(plain_msl):
    src = MslDumpSource(plain_msl)
    assert src.find_all(NEEDLE, view="vas") == []
    assert src.find_first(NEEDLE, view="vas") is None


def test_iter_vas_search_spans_match_iter_ranges(plain_msl):
    with open_dump(plain_msl) as src:
        reader = src.get_reader()
        spans = list(src._iter_vas_search_spans())
        chunks = [c for _, _, c in src.iter_ranges()]
        assert [reader.run_span(r) for _, r in spans] == [len(c) for c in chunks]
        flat = 0
        for (f, run), chunk in zip(spans, chunks):
            assert f == flat
            flat += len(chunk)


def test_iter_vas_hits_yields_run_relative_offsets(plain_msl):
    with open_dump(plain_msl) as src:
        hits = list(src._iter_vas_hits(NEEDLE))
        assert hits
        for flat, rel in hits:
            assert src.read_range(flat, len(NEEDLE), view="vas") == NEEDLE
            assert 0 <= rel <= flat


# ------------------------------------------------------ reader-level tests

@pytest.mark.parametrize("window", [20, 21, 33, 64, 1 << 20])
def test_iter_find_windowed_matches_bytes_find(window):
    rng = random.Random(window)
    data = bytearray(rng.randbytes(5000))
    for at in (0, 19, 20, 21, 1000, 4990):
        data[at:at + 10] = NEEDLE
    data[3000:3012] = b"AAAAAAAAAAAA"
    data = bytes(data)
    reads = []

    def read(off, length):
        reads.append(length)
        return data[off:off + length]

    for needle in (NEEDLE, b"AAAA", b"A"):
        for lo, hi in ((0, len(data)), (19, 4995), (21, 1009), (5, 6)):
            got = list(_iter_find_windowed(read, needle, lo, hi, window))
            want = [lo + i for i in find_all_offsets(data[lo:hi], needle)]
            assert got == want, (needle, lo, hi, window)
    assert max(reads) <= max(window, 2 * len(NEEDLE))


def test_iter_find_windowed_empty_inputs():
    assert list(_iter_find_windowed(lambda o, n: b"", b"", 0, 10)) == []
    assert list(_iter_find_windowed(lambda o, n: b"xx", b"x", 5, 5)) == []


def test_reader_iter_find_matches_copy(plain_msl):
    with MslReader(plain_msl) as r:
        n = r.buffer_length
        whole = r.read_bytes(0, n)
        for needle in (NEEDLE, b"AA"):
            for lo, length in ((0, n), (100, 5000), (n - 50, 1000), (n + 5, 10)):
                got = list(r.iter_find(needle, lo, length))
                chunk = r.read_bytes(lo, length) if lo < n else b""
                assert got == [lo + i for i in find_all_offsets(chunk, needle)]
                assert all(whole[g:g + len(needle)] == needle for g in got)
        assert list(r.iter_find(b"", 0, n)) == []
        assert list(r.iter_find(NEEDLE, 0, 0)) == []


def test_reader_iter_find_closed_reader(plain_msl):
    r = MslReader(plain_msl)
    assert list(r.iter_find(NEEDLE, 0, 100)) == []


def test_collect_regions_matches_full_payload_decode(plain_msl, enc_msl):
    path, key = enc_msl
    for p, kw in ((plain_msl, {}), (path, {"key": key})):
        with MslReader(p, **kw) as r:
            assert r.collect_regions() == old_collect_regions(r)


_REPO_TESTS = Path(__file__).resolve().parent
_COLLECTORS = [
    ("collect_key_hints", BlockType.KEY_HINT),
    ("collect_modules", BlockType.MODULE_ENTRY),
    ("collect_process_identity", BlockType.PROCESS_IDENTITY),
    ("collect_vas_map", BlockType.VAS_MAP),
    ("collect_related_dumps", BlockType.RELATED_DUMP),
    ("collect_end_of_capture", BlockType.END_OF_CAPTURE),
    ("collect_import_provenance", BlockType.IMPORT_PROVENANCE),
]


@pytest.mark.parametrize("fixture", [
    "fixtures/android/memslicer_android.msl",
    "fixtures/real_samples/chrome_min.msl",
    "fixtures/dataset/msl/test_capture.msl",
])
def test_table_collectors_match_full_walk(fixture):
    """``_collect`` reads only its own block type now; the decoded tables
    must equal what the old every-payload ``iter_blocks()`` walk produced."""
    path = _REPO_TESTS / fixture
    if not path.is_file():
        pytest.skip(f"{fixture} not present")
    with MslReader(path) as r:
        assert r.collect_regions() == old_collect_regions(r)
        for name, block_type in _COLLECTORS:
            got = getattr(r, name)()
            want_hdrs = [h for h, _ in r.iter_blocks() if h.block_type == block_type]
            assert [g.block_header for g in got] == want_hdrs, name


def test_table_collectors_skip_region_payloads(tmp_path, monkeypatch):
    path = _write_msl(tmp_path / "t.msl")
    with MslReader(path) as r:
        monkeypatch.setattr(r, "iter_blocks", lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("full payload walk")))
        assert len(r.collect_end_of_capture()) == 1


def test_captured_run_index_matches_frozen(plain_msl, enc_msl):
    path, key = enc_msl
    for p, kw in ((plain_msl, {}), (path, {"key": key})):
        with MslReader(p, **kw) as r:
            assert r.captured_run_index() == old_captured_run_index(r)


def _hdr(flags=0, block_type=0x0001, block_uuid=None, parent_uuid=None, off=0):
    return MslBlockHeader(
        block_type=block_type, flags=flags, block_length=200, payload_version=1,
        block_uuid=block_uuid or uuid4(), parent_uuid=parent_uuid or UUID(int=0),
        prev_hash=b"\x00" * 32, file_offset=off, payload_offset=off + 80)


def test_region_heads_in_merge_order_replays_merge_continuations(monkeypatch):
    """Header-only replay == order ``merge_continuations`` emits regions in,
    including held-back parents, absorbed / orphaned continuations, a reused
    parent uuid and a non-region parent."""
    p1, p2, other = uuid4(), uuid4(), uuid4()
    hc, cont = BlockFlag.HAS_CHILDREN, BlockFlag.CONTINUATION
    headers = [
        _hdr(off=1),
        _hdr(flags=hc, block_uuid=p1, off=2),
        _hdr(flags=cont, parent_uuid=p1, off=3),
        _hdr(off=4),
        _hdr(flags=cont, parent_uuid=uuid4(), off=5),          # orphan
        _hdr(flags=hc, block_type=0x0002, block_uuid=other, off=6),
        _hdr(flags=cont, block_type=0x0002, parent_uuid=other, off=7),
        _hdr(flags=hc, block_uuid=p2, off=8),
        _hdr(flags=hc, block_uuid=p1, off=9),                   # reuse p1
        _hdr(off=10),
    ]
    r = MslReader(Path("unused.msl"))
    monkeypatch.setattr(r, "_iter_raw_block_headers", lambda: iter(headers))
    got = [h.file_offset for h in r._region_heads_in_merge_order()]
    want = [h.file_offset for h, _ in merge_continuations(iter((h, b"") for h in headers))
            if h.block_type == BlockType.MEMORY_REGION]
    assert got == want == [1, 4, 5, 2, 10, 8, 9]


def test_captured_run_index_builds_without_payload_copies(tmp_path, monkeypatch):
    """Building the index never calls the payload walks (``iter_blocks`` /
    ``read_block_payload``) for an uncompressed container."""
    path = _write_msl(tmp_path / "x.msl")
    with MslReader(path) as r:
        def boom(*a, **k):
            raise AssertionError("payload copied")
        monkeypatch.setattr(r, "iter_blocks", boom)
        monkeypatch.setattr(r, "read_block_payload", boom)
        assert r.captured_run_index().runs


# -------------------------------------------------------------- gcore tests

def _build_core(path: Path, bodies, gaps=None, truncate_to=None) -> Path:
    """ELF64 ET_CORE with one PT_LOAD per body; *gaps* adds VA holes."""
    n = len(bodies)
    data_off = _EHDR64_SIZE + n * _PHDR64_SIZE
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ELF_MAGIC + bytes([ELFCLASS64, ELFDATA2LSB, 1]) + b"\x00" * 9,
        ET_CORE, 62, 1, 0, _EHDR64_SIZE, 0, 0, _EHDR64_SIZE, _PHDR64_SIZE, n, 0, 0, 0)
    phdrs = b""
    off, va = data_off, 0x400000
    for i, body in enumerate(bodies):
        phdrs += struct.pack(_PHDR64_FMT, PT_LOAD, PF_R, off, va, va,
                             len(body), len(body), 0x1000)
        off += len(body)
        va += len(body) + ((gaps or [0] * n)[i])
    blob = ehdr + phdrs + b"".join(bodies)
    if truncate_to is not None:
        blob = blob[:truncate_to]
    path.write_bytes(blob)
    return path


def _gcore_bodies():
    rng = random.Random(3)
    a = bytearray(rng.randbytes(3000))
    b = bytearray(rng.randbytes(50))
    c = bytearray(rng.randbytes(2000))
    a[:10] = NEEDLE
    a[-4:] = NEEDLE[:4]
    b[:6] = NEEDLE[4:]       # needle straddles a|b
    b[20:30] = NEEDLE
    b[-2:] = NEEDLE[:2]
    c[:8] = NEEDLE[2:]       # needle straddles b|c
    c[500:506] = b"AAAAAA"
    c[-10:] = NEEDLE
    return [bytes(a), bytes(b), bytes(c), b"Z"]


GCORE_NEEDLES = [NEEDLE, NEEDLE[:4], b"AAAA", b"A", b"Z", b"\x00not-here\x00", b""]


@pytest.mark.parametrize("variant", ["plain", "gaps", "truncated"])
def test_gcore_vas_hits_match_frozen(tmp_path, variant):
    kwargs = {"gaps": [0x1000, 0, 0x2000, 0]} if variant == "gaps" else {}
    if variant == "truncated":
        kwargs["truncate_to"] = _EHDR64_SIZE + 4 * _PHDR64_SIZE + 3000 + 50 + 1500
    path = _build_core(tmp_path / "t.core", _gcore_bodies(), **kwargs)
    with GCoreDumpSource(path) as src:
        assert old_gcore_find_all(src, NEEDLE)  # fixture sanity
        for needle in GCORE_NEEDLES:
            want = old_gcore_find_all(src, needle)
            assert src.find_all(needle, view="vas") == want, needle
            assert src.find_first(needle, view="vas") == old_gcore_find_first(src, needle)
            for limit in (1, 2, 5):
                assert src.find_all(needle, view="vas", limit=limit) == want[:limit]


def test_gcore_segment_hits_are_ascending_and_unique(tmp_path):
    path = _build_core(tmp_path / "t.core", _gcore_bodies())
    with GCoreDumpSource(path) as src:
        mm = src._reader._mmap
        for idx in range(len(src._vas_segments)):
            hits = list(src._iter_segment_hits(mm, idx, NEEDLE))
            assert hits == sorted(set(hits))
            for h in hits:
                assert src.read_range(h, len(NEEDLE), view="vas") == NEEDLE


# ----------------------------------------------------------- memory bounds

BIG = 256 * 1024 * 1024


def _write_big_msl(path: Path) -> Path:
    """A 256 MiB single-region .msl with the needle planted near the end."""
    plant = BIG - 3 * PAGE + 17

    def read_chunk(off, length):
        buf = bytearray(length)
        lo, hi = max(off, plant), min(off + length, plant + len(NEEDLE))
        if lo < hi:
            buf[lo - off:hi - off] = NEEDLE[lo - plant:hi - plant]
        return buf

    w = MslWriter(path, pid=1)
    w.add_memory_region_source(0x7F0000000000, BIG, read_chunk)
    w.add_end_of_capture()
    w.write_streaming()
    return path


@pytest.fixture(scope="module")
def big_msl(tmp_path_factory):
    return _write_big_msl(tmp_path_factory.mktemp("big") / "big.msl")


def _peak(fn):
    tracemalloc.start()
    try:
        result = fn()
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_big_msl_find_first_peak_is_bounded(big_msl):
    def run():
        with open_dump(big_msl) as src:
            return src.find_first(NEEDLE, view="vas"), src.find_all(NEEDLE, view="vas")
    (first, hits), peak = _peak(run)
    assert first == BIG - 3 * PAGE + 17 and hits == [first]
    assert peak < 4 * 1024 * 1024, f"peak {peak} bytes"


def test_big_msl_metadata_paths_peak_is_bounded(big_msl):
    def run():
        with open_dump(big_msl) as src:
            src.metadata()
            return src.size_for("vas"), len(src.get_reader().collect_regions())
    (size, nregions), peak = _peak(run)
    assert size == BIG and nregions == 1
    assert peak < 4 * 1024 * 1024, f"peak {peak} bytes"


def test_big_gcore_find_peak_is_bounded(tmp_path):
    path = tmp_path / "big.core"
    seg = 128 * 1024 * 1024
    _build_core(path, [b"\x00" * 16, b"\x00" * 16])  # header template
    data_off = _EHDR64_SIZE + 2 * _PHDR64_SIZE
    with open(path, "r+b") as fh:  # rewrite phdrs for two big sparse segments
        for i in range(2):
            fh.seek(_EHDR64_SIZE + i * _PHDR64_SIZE)
            fh.write(struct.pack(_PHDR64_FMT, PT_LOAD, PF_R, data_off + i * seg,
                                 0x400000 + i * seg, 0x400000 + i * seg, seg, seg, 0x1000))
        fh.truncate(data_off + 2 * seg)
        fh.seek(data_off + seg - 4)
        fh.write(NEEDLE)  # straddles the segment boundary
    with GCoreDumpSource(path) as src:
        (hits, peak) = _peak(lambda: (src.find_all(NEEDLE, view="vas"),
                                      src.find_first(NEEDLE, view="vas")))
    assert hits == ([seg - 4], seg - 4)
    assert peak < 1024 * 1024, f"peak {peak} bytes"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
