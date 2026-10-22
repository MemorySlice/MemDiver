"""Lazy, slab-streamed aligned consensus is bit-identical to the eager build.

The ``.msl`` (module+offset) and VA (virtual-address) consensus paths used to
copy every captured page of every dump into RAM before computing anything.
They now hold page REFERENCES and stream position slabs. These tests pin the
new paths to the PRE-CHANGE algorithm, reproduced verbatim below as
``_ref_*`` functions, on:

* writer-built native ``.msl`` dumps with ASLR-shifted modules/anon regions,
  FAILED-page gaps that differ per dump, heap/stack/anon types;
* ELF cores with ASLR-shifted PT_LOADs imported through ``import_dump``;
* the ``generate_msl_fixtures`` single-page and compressed fixtures;
* zstd/lz4-compressed regions and AEAD-encrypted containers;
* region view filters (heap, stack, heap+stack);
* tiny forced slab widths;
* the VA path over gcore sources (including short tail pages).

plus a tracemalloc comparison for 4 dumps x 32 MiB captured.
"""

from __future__ import annotations

import random
import struct
import sys
import tracemalloc
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.binary_formats.elf_core_reader import (  # noqa: E402
    ELF_MAGIC, ELFCLASS64, ELFDATA2LSB, ET_CORE, PF_R, PT_LOAD,
    _EHDR64_SIZE, _PHDR64_FMT, _PHDR64_SIZE,
)
from memdiver.core.dump_source import MslDumpSource  # noqa: E402
from memdiver.core.dump_sources.gcore import GCoreDumpSource  # noqa: E402
from memdiver.core.region_align import (  # noqa: E402
    VA_PAGE_SIZE, AlignedLayout, AlignmentCoverage, DumpRegionMap,
    NormalizedRegion, _anon_key_type_name, _extract_captured_pages,
    _KeySourceFormat, align_dumps, build_dump_region_map, build_module_lookup,
    build_va_page_index, find_owning_module, read_aligned_range, read_va_slab,
)
from memdiver.core.variance import (  # noqa: E402
    WelfordVariance, classify_variance, compute_variance,
)
from memdiver.engine.consensus import ConsensusVector  # noqa: E402
from memdiver.engine.consensus_msl import (  # noqa: E402
    build_msl_consensus, build_msl_consensus_result, build_msl_incremental,
)
from memdiver.engine.consensus_va import build_va_consensus  # noqa: E402
from memdiver.msl.enums import CompAlgo, PageState, RegionType  # noqa: E402
from memdiver.msl.region_select import parse_selection  # noqa: E402
from memdiver.msl.writer import (  # noqa: E402
    ModuleEntrySpec, MslEncryptionConfig, MslWriter,
)

PAGE = 4096
KEY = b"\x01" * 32


# ---------------------------------------------------------------------------
# Reference: the pre-change (eager) algorithm, copied from the old sources
# ---------------------------------------------------------------------------


def _ref_region_map(dump_index, reader, region_filter=None) -> DumpRegionMap:
    """Old ``build_dump_region_map`` (eager page copies)."""
    from memdiver.core.region_view_filter import is_active, stored_region_infos

    modules = reader.collect_modules()
    mod_starts, mod_intervals = build_module_lookup(modules)
    regions = reader.collect_regions()
    infos: List[Any] = [None] * len(regions)
    if is_active(region_filter):
        all_infos = stored_region_infos(reader, regions)
        kept = [(r, i) for r, i in zip(regions, all_infos)
                if region_filter.includes(i)]
        regions = [r for r, _ in kept]
        infos = [i for _, i in kept]
    rmap = DumpRegionMap(dump_index=dump_index)
    anon_counters: Dict[str, int] = {}
    key_source = _KeySourceFormat(reader)
    for region, info in zip(regions, infos):
        owner = find_owning_module(region.base_addr, mod_starts, mod_intervals)
        if owner:
            mod_path, offset = owner
            key = f"mod:{mod_path}:{offset:#x}"
        else:
            type_name = _anon_key_type_name(region.region_type, key_source)
            base_key = f"anon:{type_name}:{region.region_size:#x}"
            ordinal = anon_counters.get(base_key, 0)
            anon_counters[base_key] = ordinal + 1
            key = f"{base_key}:{ordinal}"
        captured = _extract_captured_pages(region, reader)
        if captured:
            rmap.regions[key] = NormalizedRegion(
                key=key, captured_pages=captured, page_size=region.page_size,
                source_base_addr=region.base_addr,
                region_type=region.region_type, info=info,
            )
    return rmap


def _ref_align(region_maps):
    """Old ``align_dumps`` output as eager ``(key, off, ps, vaddrs, [bytes])``."""
    common = set(region_maps[0].regions)
    for rm in region_maps[1:]:
        common &= set(rm.regions)
    out = []
    for key in sorted(common):
        regs = [rm.regions[key] for rm in region_maps]
        if len({r.page_size for r in regs}) > 1:
            continue
        ps = regs[0].page_size
        pages = set(regs[0].captured_pages)
        for r in regs[1:]:
            pages &= set(r.captured_pages)
        for off in sorted(pages):
            out.append((key, off, ps, [r.source_base_addr + off for r in regs],
                        [r.captured_pages[off] for r in regs]))
    return out


def _ref_msl_consensus(sources, region_filter=None):
    """Old ``build_msl_consensus_result`` loop (per-page ``np.var``)."""
    maps = [_ref_region_map(i, s.get_reader(),
                            region_filter if region_filter is not None
                            else getattr(s, "region_filter", None))
            for i, s in enumerate(sources)]
    slices = _ref_align(maps)
    if not slices:
        return np.array([], dtype=np.float32), 0, b"", []
    total = sum(s[2] for s in slices)
    variance = np.zeros(total, dtype=np.float32)
    reference = bytearray(total)
    offset = 0
    layout = []
    for key, off, ps, vaddrs, data in slices:
        mat = np.stack([np.frombuffer(d, dtype=np.uint8) for d in data]
                       ).astype(np.float32)
        variance[offset:offset + ps] = np.var(mat, axis=0)
        reference[offset:offset + ps] = data[0]
        layout.append((offset, ps, list(vaddrs)))
        offset += ps
    return variance, total, bytes(reference), layout


def _ref_va_consensus(sources):
    """Old ``build_va_consensus``: every dump's slab whole, then compute_variance."""
    indexes = [build_va_page_index(i, s) for i, s in enumerate(sources)]
    slices = align_dumps([ix.region_map for ix in indexes])
    if not slices:
        return np.array([], dtype=np.float32), 0, b"", []
    slabs = [read_va_slab(s, ix, slices) for s, ix in zip(sources, indexes)]
    total = sum(s.page_size for s in slices)
    layout, off = [], 0
    for s in slices:
        layout.append((off, s.page_size, list(s.source_vaddrs)))
        off += s.page_size
    return compute_variance(slabs, total), total, slabs[0], layout


def _ref_incremental_slab(builder, dump_index) -> bytes:
    """Old ``MslIncrementalBuilder._materialize_slab``."""
    src = builder._sources[dump_index]
    rmap = _ref_region_map(dump_index, src.get_reader(),
                           builder._region_filter if builder._region_filter
                           is not None else getattr(src, "region_filter", None))
    slab = bytearray(builder.total_bytes)
    for e in builder._layout:
        slab[e.slab_offset:e.slab_offset + e.page_size] = \
            rmap.regions[e.key].captured_pages[e.page_offset]
    return bytes(slab)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _pages(rng: random.Random, n: int, *, varying: float) -> bytes:
    """*n* pages: a constant body with a *varying* share of random bytes."""
    out = bytearray(b"\x5A" * (n * PAGE))
    for i in range(int(n * PAGE * varying)):
        out[rng.randrange(n * PAGE)] = rng.getrandbits(8)
    return bytes(out)


def _write_msl(path: Path, seed: int, *, shift: int = 0,
               compression: CompAlgo = CompAlgo.NONE,
               encryption: Optional[MslEncryptionConfig] = None,
               failed_page: Optional[int] = None) -> Path:
    """A native .msl with a module, heap, stack and two anon regions.

    *shift* relocates every region (ASLR); *failed_page* marks one heap page
    FAILED (a per-dump gap that drops out of the intersection).
    """
    rng = random.Random(seed)
    w = MslWriter(path, imported=False, encryption=encryption,
                  dump_uuid=None, timestamp_ns=1)
    mod_base = 0x400000 + shift
    w.add_module_list_index([ModuleEntrySpec(mod_base, 0x10000, "/usr/lib/libfoo.so")])
    w.add_memory_region(mod_base, _pages(rng, 3, varying=0.02),
                        protection=0x05, region_type=RegionType.IMAGE,
                        compression=compression)
    heap_states = [PageState.CAPTURED] * 6
    if failed_page is not None:
        heap_states[failed_page] = PageState.FAILED
    n_heap = sum(1 for s in heap_states if s == PageState.CAPTURED)
    w.add_memory_region(0x20000000 + shift, _pages(rng, n_heap, varying=0.3),
                        protection=0x03, region_type=RegionType.HEAP,
                        page_states=[int(s) for s in heap_states],
                        compression=compression)
    w.add_memory_region(0x7FFE0000 + shift, _pages(rng, 2, varying=0.1),
                        protection=0x03, region_type=RegionType.STACK,
                        compression=compression)
    for base in (0x30000000, 0x31000000):
        w.add_memory_region(base + shift, _pages(rng, 2, varying=0.05),
                            protection=0x03, region_type=RegionType.ANONYMOUS,
                            compression=compression)
    w.write()
    return path


def _msl_set(tmp_path, n=3, **kw) -> List[Path]:
    return [_write_msl(tmp_path / f"d{i}.msl", seed=100 + i, shift=i * 0x1000000,
                       failed_page=(i % 3) + 1, **kw)
            for i in range(n)]


class _Open:
    """Open MslDumpSources for the duration of a ``with`` block."""

    def __init__(self, paths, **kw):
        self.sources = [MslDumpSource(p, **kw) for p in paths]

    def __enter__(self):
        for s in self.sources:
            s.open()
        return self.sources

    def __exit__(self, *exc):
        for s in self.sources:
            s.close()


def _assert_same(new, ref):
    variance, total, reference, layout = ref
    assert new.total_bytes == total
    assert new.variance.dtype == np.float32
    assert np.array_equal(new.variance, variance)
    assert new.variance.tobytes() == variance.tobytes()  # bit-identical
    assert new.reference_bytes == reference
    assert new.layout == layout
    assert np.array_equal(np.bincount(classify_variance(new.variance), minlength=4),
                          np.bincount(classify_variance(variance), minlength=4))


# ---------------------------------------------------------------------------
# MSL one-shot
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("chunk", [None, 2, 3, 7, PAGE - 1, PAGE + 1])
def test_msl_one_shot_bit_identical(tmp_path, chunk):
    with _Open(_msl_set(tmp_path, n=4)) as srcs:
        ref = _ref_msl_consensus(srcs)
        new = build_msl_consensus_result(srcs, chunk_positions=chunk)
    assert ref[1] > 0
    _assert_same(new, ref)


@pytest.mark.parametrize("spec", ["heap", "stack", "heap,stack"])
def test_msl_region_filter_bit_identical(tmp_path, spec):
    sel = parse_selection(spec)
    with _Open(_msl_set(tmp_path, n=3)) as srcs:
        ref = _ref_msl_consensus(srcs, region_filter=sel)
        new = build_msl_consensus_result(srcs, region_filter=sel, chunk_positions=5)
        maps_new = [build_dump_region_map(i, s.get_reader(), region_filter=sel)
                    for i, s in enumerate(srcs)]
        maps_ref = [_ref_region_map(i, s.get_reader(), sel) for i, s in enumerate(srcs)]
        for mn, mr in zip(maps_new, maps_ref):
            assert list(mn.regions) == list(mr.regions)
            for k in mn.regions:
                assert list(mn.regions[k].captured_pages) == list(mr.regions[k].captured_pages)
                assert mn.regions[k].materialize() == mr.regions[k].captured_pages
    assert ref[1] > 0
    _assert_same(new, ref)


def test_msl_filter_set_on_sources(tmp_path):
    sel = parse_selection("heap")
    with _Open(_msl_set(tmp_path, n=3), region_filter=sel) as srcs:
        ref = _ref_msl_consensus(srcs)
        new = build_msl_consensus_result(srcs)
    _assert_same(new, ref)


def test_region_keys_offsets_and_coverage_unchanged(tmp_path):
    with _Open(_msl_set(tmp_path, n=3)) as srcs:
        maps_new = [build_dump_region_map(i, s.get_reader()) for i, s in enumerate(srcs)]
        maps_ref = [_ref_region_map(i, s.get_reader()) for i, s in enumerate(srcs)]
        slices = align_dumps(maps_new)
        ref_slices = _ref_align(maps_ref)
        assert [(s.key, s.page_offset, s.page_size, s.source_vaddrs) for s in slices] \
            == [r[:4] for r in ref_slices]
        assert all(s.data == r[4] for s, r in zip(slices, ref_slices))
        assert AlignmentCoverage.from_alignment(maps_new, slices) \
            == AlignmentCoverage.from_alignment(maps_ref, slices)


def test_tuple_api_and_consensus_vector(tmp_path):
    with _Open(_msl_set(tmp_path, n=3)) as srcs:
        ref = _ref_msl_consensus(srcs)
        v, total, refb, layout = build_msl_consensus(srcs, 3, return_layout=True)
        cv = ConsensusVector()
        cv.build_from_sources(srcs)
    assert np.array_equal(v, ref[0]) and total == ref[1] and refb == ref[2]
    assert layout == ref[3]
    assert cv.alignment_report.method == "module_offset"
    assert np.array_equal(cv.variance, ref[0])
    assert np.array_equal(np.asarray(cv.classifications), classify_variance(ref[0]))


def test_generated_fixtures(tmp_path):
    from tests.fixtures.generate_msl_fixtures import write_aslr_fixture

    paths = [write_aslr_fixture(tmp_path / f"a{i}.msl", region_base=0x7F0000000000 + i * 0x10000,
                                key_bytes=bytes([i + 1]) * 32) for i in range(3)]
    with _Open(paths) as srcs:
        ref = _ref_msl_consensus(srcs)
        new = build_msl_consensus_result(srcs, chunk_positions=3)
    assert ref[1] == PAGE
    _assert_same(new, ref)


@pytest.mark.parametrize("algo", [CompAlgo.ZSTD, CompAlgo.LZ4])
def test_compressed_regions_match_uncompressed(tmp_path, algo):
    """Compressed blocks are decompressed lazily (one region cached per reader)
    and give the same result as the identical uncompressed dumps.

    (The old eager path read compressed blocks' RAW payload bytes as page
    data -- see ``test_old_eager_path_misread_compressed_pages``.)
    """
    plain = _msl_set(tmp_path / "plain", n=3)
    comp = _msl_set(tmp_path / "comp", n=3, compression=algo)
    with _Open(plain) as srcs:
        ref = _ref_msl_consensus(srcs)
    with _Open(comp) as srcs:
        new = build_msl_consensus_result(srcs, chunk_positions=1000)
        builder = build_msl_incremental(srcs)
        for i in range(3):
            builder.fold_next(i)
    _assert_same(new, ref)
    assert builder.get_reference() == ref[2]


def test_old_eager_path_misread_compressed_pages(tmp_path):
    from tests.fixtures.generate_msl_fixtures import write_compressed_msl_fixture

    path = write_compressed_msl_fixture(tmp_path / "c.msl")
    with MslDumpSource(path) as src:
        reader = src.get_reader()
        region = reader.collect_regions()[0]
        eager = _extract_captured_pages(region, reader)
        lazy = build_dump_region_map(0, reader).regions
        (lazy_region,) = lazy.values()
        page = lazy_region.captured_pages[0]
    assert page[:64] == b"\xCC" * 32 + b"\xDD" * 32 and len(page) == PAGE
    # The eager path used to serve compressed bytes (eager[0] != page);
    # core/msl_helpers.get_region_page_data now slices the decompressed
    # payload, so both paths agree.
    assert eager[0] == page


def test_encrypted_containers(tmp_path):
    enc = MslEncryptionConfig(raw_key=KEY)
    plain = _msl_set(tmp_path / "plain", n=3)
    crypt = _msl_set(tmp_path / "enc", n=3, encryption=enc)
    with _Open(plain) as srcs:
        ref = _ref_msl_consensus(srcs)
    with _Open(crypt, key=KEY) as srcs:
        ref_enc = _ref_msl_consensus(srcs)
        new = build_msl_consensus_result(srcs, chunk_positions=777)
    _assert_same(new, ref)
    _assert_same(new, ref_enc)


def test_encrypted_map_refuses_silent_redecrypt_after_close(tmp_path):
    crypt = _msl_set(tmp_path / "enc", n=1,
                     encryption=MslEncryptionConfig(raw_key=KEY))
    with _Open(crypt, key=KEY) as srcs:
        rmap = build_dump_region_map(0, srcs[0].get_reader())
    region = next(iter(rmap.regions.values()))
    with pytest.raises(RuntimeError, match="encrypted reader was closed"):
        list(region.captured_pages.values())


def test_elf_cores_imported_with_aslr(tmp_path):
    from memdiver.msl.importer import import_dump

    rng = random.Random(9)
    body = [bytes(rng.getrandbits(8) for _ in range(3 * PAGE)) for _ in range(2)]
    paths = []
    for i in range(3):
        shift = i * 0x200000
        segs = []
        for j, b in enumerate(body):
            mutated = bytearray(b)
            for _ in range(300):
                mutated[rng.randrange(len(mutated))] = rng.getrandbits(8)
            segs.append((0x7F0000000000 + j * 0x100000 + shift, bytes(mutated)))
        core = _write_core(tmp_path, f"c{i}.core", segs)
        out = tmp_path / f"c{i}.msl"
        import_dump(core, out)
        paths.append(out)
    with _Open(paths) as srcs:
        ref = _ref_msl_consensus(srcs)
        new = build_msl_consensus_result(srcs, chunk_positions=11)
    assert ref[1] == 6 * PAGE
    _assert_same(new, ref)


# ---------------------------------------------------------------------------
# Incremental builder
# ---------------------------------------------------------------------------


def test_incremental_slab_and_numerics_unchanged(tmp_path):
    with _Open(_msl_set(tmp_path, n=4)) as srcs:
        builder = build_msl_incremental(srcs, region_filter=parse_selection("heap,stack"))
        ref_w = WelfordVariance(builder.total_bytes)
        for i in range(4):
            ref_slab = _ref_incremental_slab(builder, i)
            assert bytes(builder._materialize_slab(i)) == ref_slab
            builder.fold_next(i)
            ref_w.add_dump(ref_slab)
            assert np.array_equal(builder.get_live_variance(), ref_w.variance())
        assert builder.get_reference() == _ref_incremental_slab(builder, 0)
        assert isinstance(builder.get_reference(), bytes)


# ---------------------------------------------------------------------------
# read_aligned_range
# ---------------------------------------------------------------------------


def test_read_aligned_range_equals_eager_slab_slices(tmp_path):
    with _Open(_msl_set(tmp_path, n=2)) as srcs:
        maps = [build_dump_region_map(i, s.get_reader()) for i, s in enumerate(srcs)]
        slices = align_dumps(maps)
        layout = AlignedLayout.from_slices(slices)
        eager = b"".join(s.data[1] for s in slices)
        rng = random.Random(3)
        for _ in range(50):
            a = rng.randrange(layout.size)
            n = rng.randrange(1, layout.size - a + 1)
            assert bytes(read_aligned_range(maps[1], layout, a, n)) == eager[a:a + n]
        buf = np.zeros(layout.size, dtype=np.uint8)
        read_aligned_range(maps[1], layout, 0, layout.size, into=buf)
        assert buf.tobytes() == eager


def test_truncated_container_is_zero_filled(tmp_path):
    """A page cut short by truncation reads as its real bytes then zeros."""
    p = _write_msl(tmp_path / "t.msl", seed=1)
    blob = p.read_bytes()
    t = tmp_path / "trunc.msl"
    t.write_bytes(blob[:len(blob) - 3 * PAGE - 100])
    with MslDumpSource(t) as src:
        reader = src.get_reader()
        eager = _ref_region_map(0, reader)
        lazy = build_dump_region_map(0, reader)
        slices = align_dumps([lazy])
        layout = AlignedLayout.from_slices(slices)
        got = bytes(read_aligned_range(lazy, layout, 0, layout.size))
    want = b"".join(eager.regions[s.key].captured_pages[s.page_offset].ljust(s.page_size, b"\0")
                    for s in slices)
    assert got == want


def test_short_page_is_zero_filled():
    """Zero-fill covers exactly the bytes a short page cannot supply."""
    region = NormalizedRegion(key="k", captured_pages={0: b"\xAA" * 10, 8: b"\xBB" * 8},
                              page_size=8 * 2, source_base_addr=0, region_type=0)
    rmap = DumpRegionMap(dump_index=0, regions={"k": region})
    layout = AlignedLayout([(0, 16, "k", 0), (16, 16, "k", 8)])
    got = bytes(read_aligned_range(rmap, layout, 4, 26))
    assert got == b"\xAA" * 6 + b"\0" * 6 + b"\xBB" * 8 + b"\0" * 6


def test_region_map_survives_reader_close(tmp_path):
    p = _write_msl(tmp_path / "x.msl", seed=5)
    with MslDumpSource(p) as src:
        eager = _ref_region_map(0, src.get_reader())
        lazy = build_dump_region_map(0, src.get_reader())
    for k, r in lazy.regions.items():
        assert r.materialize() == eager.regions[k].captured_pages


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------


def test_budget_refuses_unless_forced(tmp_path):
    from memdiver.core.service_errors import CapabilityError

    with _Open(_msl_set(tmp_path, n=3)) as srcs:
        with pytest.raises(CapabilityError) as exc:
            build_msl_consensus_result(srcs, budget=1024)
        assert exc.value.code == "memory_budget_exceeded"
        ref = _ref_msl_consensus(srcs)
        forced = build_msl_consensus_result(srcs, budget=1024, force=True)
        cv = ConsensusVector()
        with pytest.raises(CapabilityError):
            cv.build_from_sources(srcs, budget=1024)
    _assert_same(forced, ref)


# ---------------------------------------------------------------------------
# VA path
# ---------------------------------------------------------------------------


def _write_core(tmp_path: Path, name: str, segments) -> Path:
    """Minimal ELF64 ET_CORE with one PT_LOAD per ``(vaddr, body)``."""
    e_phnum = len(segments)
    data_off = _EHDR64_SIZE + e_phnum * _PHDR64_SIZE
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ELF_MAGIC + bytes([ELFCLASS64, ELFDATA2LSB, 1]) + b"\x00" * 9,
        ET_CORE, 62, 1, 0, _EHDR64_SIZE, 0, 0,
        _EHDR64_SIZE, _PHDR64_SIZE, e_phnum, 0, 0, 0,
    )
    phdrs, bodies, offset = b"", b"", data_off
    for vaddr, body in segments:
        phdrs += struct.pack(_PHDR64_FMT, PT_LOAD, PF_R, offset, vaddr, vaddr,
                             len(body), len(body), VA_PAGE_SIZE)
        bodies += body
        offset += len(body)
    p = tmp_path / name
    p.write_bytes(ehdr + phdrs + bodies)
    return p


def _gcore_set(tmp_path, n=3):
    rng = random.Random(21)
    paths = []
    for i in range(n):
        segs = [
            (0x10000, bytes(rng.getrandbits(8) for _ in range(3 * PAGE))),
            # Short tail page (and a 1-byte tail) exercise partial VA pages.
            (0x40000, bytes([7]) * (2 * PAGE + 1)),
            (0x80000 + (i * PAGE if i == 2 else 0), bytes(rng.getrandbits(8) for _ in range(PAGE + 333))),
        ]
        if i:  # an extra leading segment shifts the file layout
            segs.insert(0, (0x900000, b"\x01" * PAGE * i))
        paths.append(_write_core(tmp_path, f"core{i}.core", segs))
    return paths


@pytest.mark.parametrize("chunk", [None, 2, 3, PAGE, PAGE + 1])
def test_va_path_bit_identical(tmp_path, chunk):
    srcs = [GCoreDumpSource(p) for p in _gcore_set(tmp_path)]
    for s in srcs:
        s.open()
    try:
        ref = _ref_va_consensus(srcs)
        new = build_va_consensus(srcs, chunk_positions=chunk)
        cv = ConsensusVector()
        cv.build_from_sources(srcs)
    finally:
        for s in srcs:
            s.close()
    assert ref[1] > 0
    _assert_same(new, ref)
    assert cv.alignment_report.method == "virtual_address"
    assert np.array_equal(cv.variance, ref[0])


# ---------------------------------------------------------------------------
# Memory: 4 dumps x 32 MiB captured
# ---------------------------------------------------------------------------


def _big_msl(path: Path, seed: int) -> Path:
    rng = np.random.default_rng(seed)
    w = MslWriter(path, imported=False, timestamp_ns=1)
    base = np.full(8 * 1024 * 1024, 0x33, dtype=np.uint8)
    for j in range(4):  # 4 x 8 MiB anon regions = 32 MiB captured
        data = base.copy()
        idx = rng.integers(0, data.size, data.size // 50)
        data[idx] = rng.integers(0, 256, idx.size, dtype=np.uint8)
        w.add_memory_region(0x10000000 * (j + 1) + seed * 0x1000, data.tobytes(),
                            region_type=RegionType.ANONYMOUS)
    w.write()
    return path


def _peak(fn) -> int:
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_peak_memory_4x32mib(tmp_path, capsys):
    paths = [_big_msl(tmp_path / f"b{i}.msl", i) for i in range(4)]
    with _Open(paths) as srcs:
        holder = {}
        before = _peak(lambda: holder.__setitem__("ref", _ref_msl_consensus(srcs)))
        ref = holder.pop("ref")
        size = ref[1]
        after = _peak(lambda: holder.__setitem__("new", build_msl_consensus_result(srcs)))
        new = holder.pop("new")
        # Outputs every build must return: float32 variance + reference bytes.
        outputs = size * 4 + size
        disk = _peak(lambda: holder.__setitem__(
            "disk", build_msl_consensus_result(srcs, budget=size * 3, force=True)))
        disk_result = holder.pop("disk")
    _assert_same(new, ref)
    assert np.array_equal(np.asarray(disk_result.variance), ref[0])
    with capsys.disabled():
        mib = 1 << 20
        print(f"\n[aligned-lazy] aligned={size / mib:.0f} MiB  eager peak={before / mib:.1f} MiB  "
              f"lazy peak={after / mib:.1f} MiB (outputs {outputs / mib:.0f} MiB)  "
              f"lazy+memmap peak={disk / mib:.1f} MiB  "
              f"working set eager={(before - outputs) / mib:.1f} lazy={(after - outputs) / mib:.1f} MiB")
    assert size == 32 * 1024 * 1024
    # Everything beyond the returned outputs: < 1/3 of the eager path's.
    assert after - outputs < (before - outputs) / 3
    # With the variance spilled to a memmap (tight budget), the whole peak
    # is < 1/3 of the eager path's.
    assert disk < before / 3


# ---------------------------------------------------------------------------
# slab_variance extensions
# ---------------------------------------------------------------------------


def test_plan_slabs_without_legacy_grid_never_emits_width_one():
    from memdiver.core.slab_variance import plan_slabs

    size = (1 << 24) + 1  # the legacy grid would reduce the last column alone
    assert plan_slabs(size, 1 << 20)[-1] == (size - 1, size)
    assert all(e - s >= 2 for s, e in plan_slabs(size, 1 << 20, legacy_chunk=None))
    assert all(e - s >= 2 for s, e in plan_slabs(9, 2, legacy_chunk=None))


def test_callable_slab_reader_streams_like_a_buffer():
    from memdiver.core.slab_variance import CallableSlabReader, stream_variance

    rng = np.random.default_rng(1)
    bufs = [rng.integers(0, 256, 1000, dtype=np.uint8).tobytes() for _ in range(3)]
    readers = [CallableSlabReader(lambda s, e, b=b: b[s:e], len(b)) for b in bufs]
    var, ref = stream_variance(readers, 1000, chunk_positions=7)
    assert np.array_equal(var, compute_variance(bufs, 1000))
    assert ref == bufs[0]


def test_plan_slab_variance_counts_extra_components():
    from memdiver.core.slab_variance import plan_slab_variance

    plan = plan_slab_variance(2, 100, budget=0, extra={"alignment_index": 5000, "zero": 0})
    assert plan.estimate.breakdown["alignment_index"] == 5000
    assert "zero" not in plan.estimate.breakdown
