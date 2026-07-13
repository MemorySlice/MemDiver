"""Tests for :class:`core.dump_sources.gcore.GCoreDumpSource`."""

from __future__ import annotations

import mmap
import struct
from pathlib import Path

import pytest

from core.binary_formats.elf_core_reader import (
    ELF_MAGIC,
    ELFCLASS64,
    ELFDATA2LSB,
    ET_CORE,
    PF_R,
    PT_LOAD,
    _EHDR64_SIZE,
    _PHDR64_FMT,
    _PHDR64_SIZE,
)
from core.dump_source import open_dump
from core.dump_sources.gcore import GCoreDumpSource
from tests._paths import SKIP_REASON, dataset_root


def _build_core_two_segments(tmp_path: Path, body_a: bytes, body_b: bytes) -> Path:
    """Write a minimal ELF64 ET_CORE with two contiguous PT_LOAD segments.

    The two segments map to adjacent virtual addresses and their captured
    bytes are concatenated back-to-back in ``view="vas"``. Returns the path.
    """
    e_phnum = 2
    e_phoff = _EHDR64_SIZE
    data_off = e_phoff + e_phnum * _PHDR64_SIZE

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ELF_MAGIC + bytes([ELFCLASS64, ELFDATA2LSB, 1]) + b"\x00" * 9,
        ET_CORE,           # e_type
        62,                # e_machine (x86_64)
        1,                 # e_version
        0,                 # e_entry
        e_phoff,           # e_phoff
        0,                 # e_shoff
        0,                 # e_flags
        _EHDR64_SIZE,      # e_ehsize
        _PHDR64_SIZE,      # e_phentsize
        e_phnum,           # e_phnum
        0, 0, 0,           # e_shentsize, e_shnum, e_shstrndx
    )

    off_a = data_off
    off_b = data_off + len(body_a)
    vaddr_a = 0x400000
    vaddr_b = vaddr_a + len(body_a)

    phdr_a = struct.pack(
        _PHDR64_FMT, PT_LOAD, PF_R, off_a, vaddr_a, vaddr_a,
        len(body_a), len(body_a), 0x1000,
    )
    phdr_b = struct.pack(
        _PHDR64_FMT, PT_LOAD, PF_R, off_b, vaddr_b, vaddr_b,
        len(body_b), len(body_b), 0x1000,
    )

    blob = ehdr + phdr_a + phdr_b + body_a + body_b
    p = tmp_path / "synthetic.core"
    p.write_bytes(blob)
    return p


def _gcore_path():
    root = dataset_root()
    if root is None:
        return None
    p = (
        root / "dataset_memory_slice" / "gocryptfs"
        / "dataset_gocryptfs" / "run_0001" / "gcore.core"
    )
    return p if p.is_file() else None


def test_gcore_dispatch() -> None:
    """``open_dump`` must pick the gcore branch for an ELF ET_CORE file."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    source = open_dump(path)
    try:
        assert isinstance(source, GCoreDumpSource)
    finally:
        close = getattr(source, "close", None)
        if callable(close):
            close()


def test_iter_ranges_covers_content() -> None:
    """PT_LOAD segments cover a non-zero virtual footprint."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    with GCoreDumpSource(path) as src:
        spans = [(start, end) for start, end, _ in src.iter_ranges(view="vas")]
    assert spans, "expected at least one PT_LOAD segment with content"
    total = sum(end - start for start, end in spans)
    assert total > 0


def test_read_range_raw_prefix() -> None:
    """``read_range(0, 16, view="raw")`` returns bytes that start with ELF magic."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    with GCoreDumpSource(path) as src:
        header = src.read_range(0, 16, view="raw")
    assert len(header) == 16
    assert header.startswith(b"\x7fELF")


def test_metadata_shape() -> None:
    """``metadata()`` advertises the gcore format and basic PT_LOAD info."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    with GCoreDumpSource(path) as src:
        meta = src.metadata()
    assert meta["format"] == "gcore"
    assert meta["region_count"] > 0
    assert meta["raw_size"] > 0
    assert isinstance(meta.get("modules"), list)


def test_va_to_file_offset_roundtrip() -> None:
    """Every PT_LOAD start VA maps back through ``va_to_file_offset``."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    with GCoreDumpSource(path) as src:
        checked = 0
        for start, _end, file_off in src.iter_ranges(view="vas"):
            assert src.va_to_file_offset(start) == file_off
            checked += 1
            if checked >= 5:
                break
        assert checked > 0


# -- Regression tests on synthetic cores (no dataset required) ----------------


def test_reader_raw_bytes_is_mmap_not_copy(tmp_path) -> None:
    """``_reader_raw_bytes`` returns the live mmap, never a full bytes copy.

    Copying the whole core would defeat the mmap-only design and risk OOM on
    multi-GB dumps; the returned object must be the mmap itself.
    """
    path = _build_core_two_segments(tmp_path, b"AAAA", b"BBBB")
    with GCoreDumpSource(path) as src:
        raw = src._reader_raw_bytes()  # noqa: SLF001
        assert isinstance(raw, mmap.mmap)
        assert not isinstance(raw, bytes)


def test_find_all_raw_finds_segment_payload(tmp_path) -> None:
    """raw find_all locates a needle that exists in the file body."""
    path = _build_core_two_segments(tmp_path, b"hello", b"world")
    with GCoreDumpSource(path) as src:
        hits = src.find_all(b"world", view="raw")
    assert len(hits) == 1
    with GCoreDumpSource(path) as src:
        assert src.read_range(hits[0], 5, view="raw") == b"world"


def test_find_all_vas_within_segment(tmp_path) -> None:
    """A needle wholly inside one segment is found at the right VAS offset."""
    path = _build_core_two_segments(tmp_path, b"AXYZA", b"QQQQ")
    with GCoreDumpSource(path) as src:
        assert src.find_all(b"XYZ", view="vas") == [1]


def test_find_all_vas_straddling_boundary(tmp_path) -> None:
    """A needle crossing the boundary of two adjacent VAS segments is found.

    Segment A ends with ``..NE`` and segment B begins with ``ED..``; the
    needle ``NEED`` straddles the join and must be located exactly once.
    """
    body_a = b"FOOBARNE"   # 8 bytes; needle starts at flat offset 6
    body_b = b"EDLE"       # contiguous in VAS -> "...NEEDLE..."
    path = _build_core_two_segments(tmp_path, body_a, body_b)
    with GCoreDumpSource(path) as src:
        hits = src.find_all(b"NEED", view="vas")
        # Cross-check against the flattened stream that view="vas" exposes.
        flat = src.read_range(0, src.size_for("vas"), view="vas")
    assert hits == [6]
    assert flat[6:10] == b"NEED"


def test_find_all_vas_no_duplicate_across_overlap(tmp_path) -> None:
    """Overlap stitching must not double-count a match that begins in the tail."""
    # "ABAB" spans the boundary; ensure a needle starting exactly in segment B
    # is reported once, owned by segment B (flat offset 4), not by A's tail.
    path = _build_core_two_segments(tmp_path, b"ZZZZ", b"NEEDLE")
    with GCoreDumpSource(path) as src:
        hits = src.find_all(b"NEED", view="vas")
    assert hits == [4]
