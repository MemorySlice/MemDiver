"""Tests for ``msl.importer.import_minidump`` and the ``import_dump`` dispatch.

Reuses the ``_build_minidump`` helper from ``test_minidump_reader`` to
synthesize Windows minidumps, then checks the three-state page model
(CAPTURED / FAILED / absent), protection+type mapping, metadata, and the
format dispatcher regression for plain raw ``.dump`` files.
"""

from __future__ import annotations

from math import ceil
from pathlib import Path
from typing import List

from memdiver.core.binary_formats.minidump_reader import (
    MEM_COMMIT,
    MEM_FREE,
    MEM_IMAGE,
    MEM_PRIVATE,
    MEM_RESERVE,
    PAGE_EXECUTE_READ,
    PAGE_READWRITE,
)
from memdiver.msl.enums import ArchType, OSType, PageState, Protection, RegionType, SourceFormat
from memdiver.msl.importer import import_dump, import_minidump
from memdiver.msl.page_map import get_region_page_data
from memdiver.msl.reader import MslReader
from memdiver.msl.writer import CapBit

from tests.test_minidump_reader import AMD64, _build_minidump

PAGE = 4096


def _write(tmp_path: Path, data: bytes, name: str) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _region_by_base(reader: MslReader, base: int):
    for r in reader.collect_regions():
        if r.base_addr == base:
            return r
    return None


def _states(region) -> List[PageState]:
    return [iv.state for iv in region.page_intervals for _ in range(iv.count)]


def test_full_fidelity_three_state(tmp_path) -> None:
    """With a MemoryInfoList: CAPTURED vs FAILED; reserved/free left absent.

    UNMAPPED is a live-acquisition TOCTOU state a static Minidump cannot
    witness, so imports never synthesize it: reserved/free ranges become
    absent (no region) rather than UNMAPPED.
    """
    committed_data = bytes((i % 253 for i in range(PAGE)))
    descriptors = [(0x10000, committed_data)]  # backs only the first region
    mem_infos = [
        # Committed + captured (descriptor covers it).
        (0x10000, 0x10000, PAGE_READWRITE, PAGE, MEM_COMMIT,
         PAGE_READWRITE, MEM_PRIVATE),
        # Committed but NO descriptor -> FAILED.
        (0x20000, 0x20000, PAGE_READWRITE, PAGE, MEM_COMMIT,
         PAGE_READWRITE, MEM_PRIVATE),
        # Reserved and free -> absent (no region synthesized).
        (0x30000, 0x30000, PAGE_READWRITE, PAGE, MEM_RESERVE,
         PAGE_READWRITE, MEM_PRIVATE),
        (0x40000, 0x40000, PAGE_READWRITE, PAGE, MEM_FREE,
         PAGE_READWRITE, MEM_PRIVATE),
    ]
    path = _write(tmp_path, _build_minidump(
        descriptors, mem_infos=mem_infos, arch=AMD64, pid=999), "full.dmp")

    out = tmp_path / "full.msl"
    import_minidump(path, out)

    with MslReader(out) as reader:
        bases = {r.base_addr for r in reader.collect_regions()}
        assert 0x10000 in bases
        assert 0x20000 in bases
        assert 0x30000 not in bases  # reserved -> absent
        assert 0x40000 not in bases  # free -> absent

        captured = _region_by_base(reader, 0x10000)
        assert all(s == PageState.CAPTURED for s in _states(captured))
        assert get_region_page_data(reader, captured) == committed_data

        failed = _region_by_base(reader, 0x20000)
        assert all(s == PageState.FAILED for s in _states(failed))
        assert get_region_page_data(reader, failed) == b""

        # No region anywhere carries an UNMAPPED page on import.
        for r in reader.collect_regions():
            assert all(s != PageState.UNMAPPED for s in _states(r))

        # Imported files flag their page states as inferred, not observed.
        assert reader.file_header.cap_bitmap & CapBit.PAGE_STATES_INFERRED
        assert reader.file_header.page_states_inferred


def test_reserved_and_free_left_absent(tmp_path) -> None:
    """Reserved/free ranges are left absent regardless of size (no UNMAPPED).

    Only the committed+captured region is emitted; neither a small reserved
    gap nor a huge free span produces a region.
    """
    from memdiver.msl.importer import MAX_UNMAPPED_REGION_PAGES

    committed_data = bytes(PAGE)
    big = (MAX_UNMAPPED_REGION_PAGES + 1) * PAGE  # one page over the old cap
    descriptors = [(0x10000, committed_data)]
    mem_infos = [
        (0x10000, 0x10000, PAGE_READWRITE, PAGE, MEM_COMMIT,
         PAGE_READWRITE, MEM_PRIVATE),
        # A small reserved gap: now left absent.
        (0x20000, 0x20000, PAGE_READWRITE, PAGE, MEM_RESERVE,
         PAGE_READWRITE, MEM_PRIVATE),
        # A huge free span: also left absent.
        (0x1000000, 0x1000000, PAGE_READWRITE, big, MEM_FREE,
         PAGE_READWRITE, MEM_PRIVATE),
    ]
    path = _write(tmp_path, _build_minidump(
        descriptors, mem_infos=mem_infos, arch=AMD64, pid=7), "big.dmp")

    out = tmp_path / "big.msl"
    import_minidump(path, out)

    with MslReader(out) as reader:
        bases = {r.base_addr for r in reader.collect_regions()}
        assert 0x10000 in bases        # committed CAPTURED
        assert 0x20000 not in bases    # small reserved -> absent
        assert 0x1000000 not in bases  # huge free -> absent
        for r in reader.collect_regions():
            assert all(s != PageState.UNMAPPED for s in _states(r))


def test_fallback_all_captured(tmp_path) -> None:
    """No MemoryInfoList: descriptors become all-CAPTURED, no fabricated FAILED."""
    d0 = bytes((i % 191 for i in range(PAGE)))
    d1 = bytes((0x40 + (i % 5) for i in range(PAGE)))
    descriptors = [(0x10000, d0), (0x20000, d1)]
    path = _write(tmp_path, _build_minidump(descriptors), "fallback.dmp")

    out = tmp_path / "fallback.msl"
    result = import_minidump(path, out)
    assert result.regions_written == 2

    with MslReader(out) as reader:
        for base, blob in ((0x10000, d0), (0x20000, d1)):
            r = _region_by_base(reader, base)
            states = _states(r)
            assert states, "region must have pages"
            assert all(s == PageState.CAPTURED for s in states)
            assert get_region_page_data(reader, r) == blob


def test_protection_and_type_mapping(tmp_path) -> None:
    """PAGE_EXECUTE_READ + MEM_IMAGE -> READ|EXECUTE, RegionType.IMAGE."""
    data = bytes((i % 97 for i in range(PAGE)))
    descriptors = [(0x50000, data)]
    mem_infos = [
        (0x50000, 0x50000, PAGE_EXECUTE_READ, PAGE, MEM_COMMIT,
         PAGE_EXECUTE_READ, MEM_IMAGE),
    ]
    path = _write(tmp_path, _build_minidump(
        descriptors, mem_infos=mem_infos), "prot.dmp")

    out = tmp_path / "prot.msl"
    import_minidump(path, out)

    with MslReader(out) as reader:
        r = _region_by_base(reader, 0x50000)
        assert r.protection == int(Protection.READ | Protection.EXECUTE)
        assert r.region_type == int(RegionType.IMAGE)


def test_metadata_and_provenance(tmp_path) -> None:
    """os_type WINDOWS, arch from SystemInfo, pid from MiscInfo, prov format."""
    descriptors = [(0x10000, bytes(PAGE))]
    mem_infos = [
        (0x10000, 0x10000, PAGE_READWRITE, PAGE, MEM_COMMIT,
         PAGE_READWRITE, MEM_PRIVATE),
    ]
    path = _write(tmp_path, _build_minidump(
        descriptors, mem_infos=mem_infos, arch=AMD64, pid=2468), "meta.dmp")

    out = tmp_path / "meta.msl"
    import_minidump(path, out)

    with MslReader(out) as reader:
        hdr = reader.file_header
        assert hdr.os_type == OSType.WINDOWS
        assert hdr.arch_type == ArchType.X86_64
        assert hdr.pid == 2468
        prov = reader.collect_import_provenance()
        assert prov[0].source_format == SourceFormat.MINIDUMP == 3


# -- Dispatcher regression ----------------------------------------------------


def test_dispatch_raw_dump_unchanged(tmp_path) -> None:
    """A plain raw .dump routes to raw import: one all-CAPTURED region."""
    raw = _write(tmp_path, b"\x11\x22\x33\x44" * 300, "plain.dump")
    out = tmp_path / "plain.msl"
    result = import_dump(raw, out)
    assert result.regions_written == 1

    with MslReader(out) as reader:
        regions = reader.collect_regions()
        assert len(regions) == 1
        assert regions[0].base_addr == 0
        assert all(s == PageState.CAPTURED for s in _states(regions[0]))
        # Raw import: all-CAPTURED is legitimate (bytes are present), but the
        # page states are still inferred, not observed.
        assert reader.file_header.page_states_inferred
        prov = reader.collect_import_provenance()
        assert prov[0].source_format == SourceFormat.RAW_DUMP == 1


def test_dispatch_routes_minidump(tmp_path) -> None:
    """A synthetic minidump routes through import_minidump (source_format 3)."""
    descriptors = [(0x10000, bytes(PAGE))]
    mem_infos = [
        (0x10000, 0x10000, PAGE_READWRITE, PAGE, MEM_COMMIT,
         PAGE_READWRITE, MEM_PRIVATE),
    ]
    dmp = _write(tmp_path, _build_minidump(
        descriptors, mem_infos=mem_infos, pid=55), "auto.dmp")
    out = tmp_path / "auto.msl"
    import_dump(dmp, out)

    with MslReader(out) as reader:
        prov = reader.collect_import_provenance()
        assert prov[0].source_format == SourceFormat.MINIDUMP
        assert reader.file_header.os_type == OSType.WINDOWS
