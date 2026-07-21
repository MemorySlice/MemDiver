"""Tests for ``msl.importer.import_elf_core`` — ELF core -> MSL three-state.

Builds synthetic ELF64 ``ET_CORE`` dumps by hand (adapting the segment
builder from ``test_gcore_dump_source.py`` and the note layout from
``test_elf_core_reader.py``) and verifies the importer's per-segment
three-state page model, provenance, module index, and round-trip.
"""

from __future__ import annotations

import struct
from math import ceil
from pathlib import Path
from typing import List, Sequence, Tuple

from memdiver.core.binary_formats.elf_core_reader import (
    ELF_MAGIC,
    ELFCLASS64,
    ELFDATA2LSB,
    ET_CORE,
    NT_FILE,
    NT_PRSTATUS,
    PF_R,
    PF_W,
    PT_LOAD,
    PT_NOTE,
    _EHDR64_SIZE,
    _PHDR64_FMT,
    _PHDR64_SIZE,
    _align4,
)
from memdiver.core.dump_source import open_dump
from memdiver.msl.enums import PageState, SourceFormat
from memdiver.msl.importer import import_elf_core
from memdiver.msl.page_map import get_region_page_data
from memdiver.msl.reader import MslReader
from memdiver.msl.writer import CapBit

PAGE = 4096

# One PT_LOAD spec: (vaddr, filesz, memsz, flags, body).
Segment = Tuple[int, int, int, int, bytes]


def _note(n_type: int, desc: bytes, name: bytes = b"CORE\x00") -> bytes:
    """Serialize one ELF note record (namesz/descsz/type + padded fields)."""
    hdr = struct.pack("<III", len(name), len(desc), n_type)
    name_pad = b"\x00" * (_align4(len(name)) - len(name))
    desc_pad = b"\x00" * (_align4(len(desc)) - len(desc))
    return hdr + name + name_pad + desc + desc_pad


def _prstatus_note(pid: int) -> bytes:
    """NT_PRSTATUS note whose pr_pid sits at desc offset 32."""
    desc = bytearray(120)
    desc[32:36] = pid.to_bytes(4, "little", signed=True)
    return _note(NT_PRSTATUS, bytes(desc))


def _nt_file_note(mappings: Sequence[Tuple[int, int, str]]) -> bytes:
    """NT_FILE note: count, page_size, {start,end,file_ofs}*, NUL names."""
    count = len(mappings)
    body = struct.pack("<QQ", count, PAGE)
    for start, end, _path in mappings:
        body += struct.pack("<QQQ", start, end, 0)
    for _start, _end, path in mappings:
        body += path.encode() + b"\x00"
    return _note(NT_FILE, body)


def _build_core(tmp_path: Path, segments: Sequence[Segment],
                notes: bytes) -> Path:
    """Write a synthetic ELF64 ET_CORE with PT_LOAD segments + a PT_NOTE."""
    e_phnum = len(segments) + 1  # + PT_NOTE
    e_phoff = _EHDR64_SIZE
    data_start = e_phoff + e_phnum * _PHDR64_SIZE

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ELF_MAGIC + bytes([ELFCLASS64, ELFDATA2LSB, 1]) + b"\x00" * 9,
        ET_CORE, 62, 1, 0, e_phoff, 0, 0,
        _EHDR64_SIZE, _PHDR64_SIZE, e_phnum, 0, 0, 0,
    )

    note_off = data_start
    seg_cursor = note_off + len(notes)

    phdrs = bytearray()
    bodies = bytearray()
    for vaddr, filesz, memsz, flags, body in segments:
        assert len(body) == filesz
        phdrs += struct.pack(
            _PHDR64_FMT, PT_LOAD, flags, seg_cursor, vaddr, vaddr,
            filesz, memsz, PAGE,
        )
        bodies += body
        seg_cursor += filesz
    phdrs += struct.pack(
        _PHDR64_FMT, PT_NOTE, 0, note_off, 0, 0, len(notes), len(notes), 0,
    )

    blob = ehdr + bytes(phdrs) + notes + bytes(bodies)
    p = tmp_path / "synthetic.core"
    p.write_bytes(blob)
    return p


def _region_by_base(reader: MslReader, base: int):
    for r in reader.collect_regions():
        if r.base_addr == base:
            return r
    raise AssertionError(f"no region with base {base:#x}")


def _states(region) -> List[PageState]:
    """Expand a region's page states to a per-page list."""
    return [iv.state for iv in region.page_intervals for _ in range(iv.count)]


def test_import_elf_core_three_state(tmp_path) -> None:
    """One region per PT_LOAD with a correct three-state page map."""
    body_a = bytes((i % 251 for i in range(2 * PAGE)))  # 2 full pages
    body_b = bytes((0xB0 + (i % 7) for i in range(PAGE)))  # 1 full page
    va_a, va_b, va_c = 0x400000, 0x500000, 0x600000
    segments = [
        (va_a, len(body_a), len(body_a), PF_R, body_a),        # fully captured
        (va_b, len(body_b), 2 * PAGE, PF_R | PF_W, body_b),    # .bss tail
        (va_c, 0, PAGE, PF_R | PF_W, b""),                     # pure bss
    ]
    notes = _prstatus_note(1234) + _nt_file_note(
        [(va_a, va_a + 2 * PAGE, "/usr/lib/libc.so.6")])
    core = _build_core(tmp_path, segments, notes)

    out = tmp_path / "core.msl"
    result = import_elf_core(core, out)
    assert result.regions_written == 3

    with MslReader(out) as reader:
        regions = reader.collect_regions()
        assert len(regions) == 3

        # Region A: fully captured, size == ceil(memsz/ps)*ps.
        ra = _region_by_base(reader, va_a)
        assert ra.region_size == ceil(len(body_a) / PAGE) * PAGE
        assert all(s == PageState.CAPTURED for s in _states(ra))
        assert get_region_page_data(reader, ra) == body_a

        # Region B: CAPTURED prefix + FAILED .bss tail.
        rb = _region_by_base(reader, va_b)
        assert rb.region_size == 2 * PAGE
        states_b = _states(rb)
        captured_b = ceil(len(body_b) / PAGE)
        assert states_b[:captured_b] == [PageState.CAPTURED] * captured_b
        assert all(s == PageState.FAILED for s in states_b[captured_b:])
        data_b = get_region_page_data(reader, rb)
        assert data_b == body_b               # FAILED tail adds zero bytes
        assert len(data_b) == captured_b * PAGE

        # Region C: pure bss -> all FAILED, no data.
        rc = _region_by_base(reader, va_c)
        assert all(s == PageState.FAILED for s in _states(rc))
        assert get_region_page_data(reader, rc) == b""

        # ELF import assigns only CAPTURED/FAILED; UNMAPPED is never
        # synthesized, and the page states are flagged inferred.
        for r in regions:
            assert all(s != PageState.UNMAPPED for s in _states(r))
        assert reader.file_header.cap_bitmap & CapBit.PAGE_STATES_INFERRED
        assert reader.file_header.page_states_inferred

        # Provenance + pid + module index.
        prov = reader.collect_import_provenance()
        assert len(prov) == 1
        assert prov[0].source_format == SourceFormat.ELF_CORE == 2
        assert reader.file_header.pid == 1234

        indices = reader.collect_module_list_index()
        assert indices, "expected a module list index from NT_FILE"
        paths = {e.path for idx in indices for e in idx.entries}
        assert "/usr/lib/libc.so.6" in paths


def test_import_elf_core_roundtrip_vas(tmp_path) -> None:
    """open_dump exposes only captured VAs at their real base addresses."""
    body_a = bytes((i % 200 for i in range(PAGE)))
    body_b = bytes((i % 100 for i in range(PAGE)))
    va_a, va_b = 0x400000, 0x800000
    segments = [
        (va_a, len(body_a), len(body_a), PF_R, body_a),
        (va_b, len(body_b), 2 * PAGE, PF_R | PF_W, body_b),  # FAILED tail
    ]
    core = _build_core(tmp_path, segments, _prstatus_note(77))

    out = tmp_path / "rt.msl"
    import_elf_core(core, out)

    with open_dump(out) as src:
        ranges = list(src.iter_ranges())

    # Exactly the captured runs, at real base VAs; the FAILED tail of B and
    # any gap between A and B produce no ranges.
    assert ranges[0][0] == va_a
    assert ranges[0][2] == body_a
    assert ranges[1][0] == va_b
    assert ranges[1][2] == body_b
    assert len(ranges) == 2


def test_import_elf_core_truncated_marks_tail_failed(tmp_path) -> None:
    """A truncated/damaged core marks unread tail pages FAILED, never
    fabricating captured zero-fill for missing on-disk bytes."""
    va = 0x1000
    body = bytes((i % 256 for i in range(3 * PAGE)))  # 3 full stored pages
    core = _build_core(
        tmp_path, [(va, 3 * PAGE, 3 * PAGE, PF_R | PF_W, body)],
        _prstatus_note(1234),
    )
    # Chop 1.5 pages off the end: only 1.5 of the 3 stored pages survive.
    full = core.read_bytes()
    core.write_bytes(full[: len(full) - (3 * PAGE - 3 * PAGE // 2)])

    out = tmp_path / "trunc.msl"
    import_elf_core(core, out)

    with MslReader(out) as reader:
        r = _region_by_base(reader, va)
        states = _states(r)
        assert len(states) == 3
        assert states[0] == PageState.CAPTURED       # only the fully-read page
        assert all(s == PageState.FAILED for s in states[1:])  # partial + missing
        # Only the one fully-captured page's real bytes are stored; the
        # half-page that was truncated is dropped, not zero-filled.
        assert get_region_page_data(reader, r) == body[:PAGE]
