"""Streaming importers: bounded RAM and output identical to the in-memory path.

The in-memory reference for ELF cores and minidumps is rebuilt from the
importer's original (still present) helpers -- ``_add_segment_region`` and
``_derive_regions`` with its default in-memory spec builders -- so each
streamed import is compared against exactly what the pre-streaming code
produced (regions, page states, captured bytes, key hints, modules).
Raw dumps are checked from first principles (file bytes + zero page pad).
"""

from __future__ import annotations

import os
import shutil
import tracemalloc
from pathlib import Path
from typing import List

import pytest

from memdiver.core.binary_formats.elf_core_reader import PF_R, PF_W, ElfCoreReader
from memdiver.core.binary_formats.minidump_reader import (
    MEM_COMMIT, MEM_FREE, MEM_PRIVATE, PAGE_READWRITE, MinidumpReader,
)
from memdiver.core.models import CryptoSecret
from memdiver.msl import importer as imp
from memdiver.msl.enums import ArchType, BlockType, OSType
from memdiver.msl.import_sources import MappedFile, RunBuilder, RunSource
from memdiver.msl.page_map import get_region_page_data
from memdiver.msl.reader import MslReader
from memdiver.msl.writer import MslWriter
from tests.fixtures import synth_elf_core
from tests.test_elf_core_importer import _build_core, _nt_file_note, _prstatus_note
from tests.test_minidump_reader import AMD64, _build_minidump

PAGE = 4096


def _secret(value: bytes, kind: str = "CLIENT_TRAFFIC_SECRET_0") -> CryptoSecret:
    return CryptoSecret(secret_type=kind, identifier=b"\x00" * 32,
                        secret_value=value)


def _snapshot(path: Path):
    """Everything observable about regions/hints/modules, UUID-free."""
    with MslReader(path) as reader:
        regions = sorted(reader.collect_regions(), key=lambda r: r.base_addr)
        base_of = {r.block_header.block_uuid: r.base_addr for r in regions}
        region_rows = [
            (r.base_addr, r.region_size, r.protection, r.region_type,
             r.page_size_log2, r.timestamp_ns,
             [(iv.state, iv.count) for iv in r.page_intervals],
             get_region_page_data(reader, r))
            for r in regions
        ]
        hints = sorted(
            (base_of[h.region_uuid], h.region_offset, h.key_length,
             h.key_type, h.protocol, h.confidence, h.key_state)
            for h in reader.collect_key_hints()
        )
        modules = [(m.base_addr, m.module_size, m.path)
                   for m in reader.collect_modules()]
    return region_rows, hints, modules


# -- raw ---------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, PAGE - 1, PAGE, 3 * PAGE + 17])
def test_raw_matches_first_principles(tmp_path, size) -> None:
    body = bytes((i * 31 + 7) & 0xFF for i in range(size))
    if size > 64:
        body = body[:40] + b"SECRET-KEY-0123456789" + body[61:]
    src = tmp_path / "a.dump"
    src.write_bytes(body)
    secrets = [_secret(b"SECRET-KEY-0123456789"), _secret(b"absent-needle")]

    out = tmp_path / "a.msl"
    result = imp.import_raw_dump(src, out, secrets=secrets)

    padded = body + b"\x00" * ((-size) % PAGE)
    regions, hints, _ = _snapshot(out)
    assert len(regions) == 1
    base, region_size, *_, data = regions[0]
    assert (base, region_size, data) == (0, len(padded), padded)
    expected_hints = 1 if size > 64 else 0
    assert result.key_hints_written == expected_hints == len(hints)
    if expected_hints:
        assert hints[0][1] == 40
    assert result.total_bytes == size


def test_raw_secret_in_padding_not_hinted(tmp_path) -> None:
    """Hints search only original bytes, never the synthesised zero pad."""
    src = tmp_path / "z.dump"
    src.write_bytes(b"\x01" * 10)
    out = tmp_path / "z.msl"
    result = imp.import_raw_dump(src, out, secrets=[_secret(b"\x00" * 8)])
    assert result.key_hints_written == 0


# -- ELF core ----------------------------------------------------------------


def _reference_elf(core: Path, out: Path, secrets) -> None:
    """The pre-streaming import_elf_core body (in-memory helpers)."""
    with ElfCoreReader(core) as reader:
        info = reader.info
        writer = MslWriter(out, pid=info.pid or 0, os_type=OSType.LINUX,
                           arch_type=ArchType.UNKNOWN)
        imp._add_module_index(writer, info.file_mappings)
        for seg in info.segments:
            region_uuid, data = imp._add_segment_region(
                writer, reader, seg, info, None)
            if secrets and data:
                imp._add_key_hints(writer, region_uuid, data, secrets)
        writer.add_end_of_capture()
        writer.write()


def _assert_elf_equivalent(tmp_path: Path, core: Path, secrets) -> None:
    streamed, reference = tmp_path / "s.msl", tmp_path / "r.msl"
    imp.import_elf_core(core, streamed, secrets=secrets)
    _reference_elf(core, reference, secrets)
    assert _snapshot(streamed) == _snapshot(reference)


def test_elf_synth_fixture_matches_in_memory(tmp_path) -> None:
    core = synth_elf_core.build(tmp_path / "run") / "gcore.core"
    secrets = [_secret(b"SEG03"), _secret(b"SEG11"), _secret(b"nope!")]
    _assert_elf_equivalent(tmp_path, core, secrets)
    streamed = _snapshot(tmp_path / "s.msl")
    assert len(streamed[1]) == 2  # two planted tags found


def test_elf_bss_tail_partial_page_and_padding_hint(tmp_path) -> None:
    """filesz < memsz, a non-page-aligned filesz, and a secret whose tail
    lies in the zero page-padding (found by the in-memory path too)."""
    body_a = bytes((i % 251) for i in range(PAGE + 100))
    body_a = body_a[:-4] + b"KEY\x00"  # last stored bytes + pad zeros
    body_b = b"\xAB" * 300
    segments = [
        (0x400000, len(body_a), 4 * PAGE, PF_R, body_a),
        (0x500000, len(body_b), len(body_b), PF_R | PF_W, body_b),
        (0x600000, 0, 2 * PAGE, PF_R | PF_W, b""),
    ]
    notes = _prstatus_note(77) + _nt_file_note(
        [(0x400000, 0x400000 + PAGE, "/usr/lib/libx.so.1")])
    core = _build_core(tmp_path, segments, notes)
    secrets = [_secret(b"KEY\x00\x00\x00\x00"), _secret(b"\xAB" * 8),
               _secret(b"\x00" * 16)]
    _assert_elf_equivalent(tmp_path, core, secrets)
    assert len(_snapshot(tmp_path / "s.msl")[1]) == 4  # zeros hit 2 regions


def test_elf_truncated_core_matches_in_memory(tmp_path) -> None:
    body = bytes((i * 3) & 0xFF for i in range(3 * PAGE))
    core = _build_core(tmp_path, [(0x400000, len(body), len(body), PF_R, body)],
                       _prstatus_note(1))
    core.write_bytes(core.read_bytes()[:-(PAGE + 123)])  # chop stored bytes
    _assert_elf_equivalent(tmp_path, core, [_secret(body[10:30])])


# -- minidump ----------------------------------------------------------------


def _reference_minidump(dmp: Path, out: Path) -> None:
    with MinidumpReader(dmp) as reader:
        writer = MslWriter(out)
        for spec in imp._derive_regions(reader, 12):  # in-memory builders
            writer.add_memory_region(
                spec.base, spec.data, protection=spec.protection,
                region_type=spec.region_type, page_size_log2=12,
                page_states=spec.page_states)
        writer.add_end_of_capture()
        writer.write()


def _assert_minidump_equivalent(tmp_path: Path, blob: bytes) -> list:
    dmp = tmp_path / "m.dmp"
    dmp.write_bytes(blob)
    streamed, reference = tmp_path / "s.msl", tmp_path / "r.msl"
    imp.import_minidump(dmp, streamed)
    _reference_minidump(dmp, reference)
    snap = _snapshot(streamed)
    assert snap == _snapshot(reference)
    return snap[0]


def _pattern(n: int, seed: int) -> bytes:
    return bytes(((i * 13) + seed) & 0xFF for i in range(n))


def _commit(base: int, size: int):
    return (base, base, PAGE_READWRITE, size, MEM_COMMIT, PAGE_READWRITE,
            MEM_PRIVATE)


@pytest.mark.parametrize("use_memory64", [False, True])
def test_minidump_partial_and_shared_pages(tmp_path, use_memory64) -> None:
    """Unaligned spans, two spans sharing a page, a full multi-page span,
    a FAILED gap, an unclaimed span (safety net) and a free range."""
    descriptors = [
        (0x10000 + 100, _pattern(PAGE + 50, 1)),        # partial head/tail
        (0x10000 + 2 * PAGE + 10, _pattern(20, 2)),     # shares page 2 ...
        (0x10000 + 2 * PAGE + 100, _pattern(30, 3)),    # ... with this one
        (0x20000, _pattern(3 * PAGE, 4)),                # fully covered pages
        (0x90000 + 5, _pattern(77, 5)),                  # unclaimed span
    ]
    mem_infos = [
        _commit(0x10000, 6 * PAGE),
        _commit(0x20000, 5 * PAGE),
        (0x30000, 0x30000, PAGE_READWRITE, PAGE, MEM_FREE, PAGE_READWRITE,
         MEM_PRIVATE),
    ]
    regions = _assert_minidump_equivalent(tmp_path, _build_minidump(
        descriptors, mem_infos=mem_infos, arch=AMD64, pid=5,
        use_memory64=use_memory64))
    assert [r[0] for r in regions] == [0x10000, 0x20000, 0x90000]


def test_minidump_overlapping_spans_fall_back(tmp_path) -> None:
    descriptors = [(0x10000, _pattern(2 * PAGE, 1)),
                   (0x10000 + PAGE + 7, _pattern(PAGE, 9))]
    _assert_minidump_equivalent(tmp_path, _build_minidump(
        descriptors, mem_infos=[_commit(0x10000, 4 * PAGE)], arch=AMD64))


def test_minidump_without_memory_info_list(tmp_path) -> None:
    descriptors = [(0x10000 + 9, _pattern(500, 1)), (0x40000, _pattern(PAGE, 2))]
    regions = _assert_minidump_equivalent(
        tmp_path, _build_minidump(descriptors, arch=AMD64))
    assert len(regions) == 2


# -- RunSource ----------------------------------------------------------------


def test_run_source_reads_and_finds_across_runs(tmp_path) -> None:
    src = tmp_path / "f.bin"
    src.write_bytes(b"0123456789abcdef")
    with MappedFile(src) as mapped:
        builder = RunBuilder()
        builder.add_file(4, 4)          # "4567"
        builder.add_file(8, 2)          # coalesced -> "456789"
        builder.add_literal(b"XY")
        builder.add_zeros(3)
        builder.add_zeros(1)            # coalesced zero run
        builder.add_file(0, 2)          # "01"
        assert len(builder.runs) == 4
        source = RunSource(mapped, builder.runs)
        stream = b"456789XY\x00\x00\x00\x0001"
        assert len(source) == len(stream)
        assert bytes(source(0, len(stream))) == stream
        assert isinstance(source(1, 3), memoryview)  # zero-copy inside a run
        for needle in (b"89XY", b"Y\x00", b"\x00\x00\x00\x00", b"\x0001",
                       b"45", b"01", b"zz", b""):
            assert source.find(needle) == stream.find(needle), needle


# -- bounded memory / huge input ----------------------------------------------


def _write_patterned(path: Path, size: int) -> None:
    chunk = _pattern(1 << 20, 3)
    with open(path, "wb") as fh:
        for _ in range(size // len(chunk)):
            fh.write(chunk)


def test_raw_import_peak_memory_is_bounded(tmp_path) -> None:
    size = 64 << 20
    src = tmp_path / "big.dump"
    _write_patterned(src, size)
    out = tmp_path / "big.msl"
    tracemalloc.start()
    try:
        imp.import_raw_dump(src, out, secrets=[_secret(b"not-present-anywhere")])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 16 << 20, f"peak {peak / 2**20:.1f} MiB"
    with MslReader(out) as reader:
        (region,) = reader.collect_regions()
        assert region.region_size == size


def _region_block_count(path: Path) -> int:
    with MslReader(path) as reader:
        return sum(1 for hdr, _ in reader.iter_blocks()
                   if hdr.block_type == BlockType.MEMORY_REGION)


@pytest.mark.slow
def test_sparse_raw_over_4gib_imports(tmp_path) -> None:
    if shutil.disk_usage(tmp_path).free < 10 << 30:
        pytest.skip("needs >= 10 GiB free disk")
    size = (4 << 30) + PAGE
    src = tmp_path / "sparse.dump"
    with open(src, "wb") as fh:
        fh.truncate(size)
    out = tmp_path / "sparse.msl"
    try:
        result = imp.import_raw_dump(src, out)
        assert result.total_bytes == size
        assert _region_block_count(out) >= 2
        with MslReader(out) as reader:
            total = sum(r.region_size for r in reader.collect_regions())
        assert total == size
    finally:
        for p in (src, out):
            if p.exists():
                os.remove(p)
