"""Unit tests for :mod:`core.binary_formats.minidump_reader`.

Synthetic Windows minidumps are assembled by hand with ``struct`` (all
little-endian) so the parser can be exercised without a real ``.dmp``
capture. The :func:`_build_minidump` helper is shared with
``test_minidump_importer.py``.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import pytest

from memdiver.core.format_detect import detect_format
from memdiver.core.binary_formats.minidump_reader import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_PRIVATE,
    MEMORY64_LIST_STREAM,
    MEMORY_INFO_LIST_STREAM,
    MEMORY_LIST_STREAM,
    MISC_INFO_STREAM,
    MINIDUMP_MISC1_PROCESS_ID,
    PAGE_EXECUTE_READ,
    PAGE_READWRITE,
    PROCESSOR_ARCHITECTURE_AMD64,
    SYSTEM_INFO_STREAM,
    MinidumpReader,
)

# Public arch alias so callers read like ``arch=AMD64``.
AMD64 = PROCESSOR_ARCHITECTURE_AMD64

# struct layouts mirrored from the reader (little-endian). --------------------
_HEADER = struct.Struct("<4sIIIIIq")          # 28 bytes
_DIRECTORY = struct.Struct("<III")            # 12 bytes
_MEM_DESC = struct.Struct("<QII")             # 16 bytes (start, size, rva)
_MEM64_HDR = struct.Struct("<QQ")             # 16 bytes (count, base_rva)
_MEM64_DESC = struct.Struct("<QQ")            # 16 bytes (start, size)
_MEMINFO_LIST_HDR = struct.Struct("<IIQ")     # 16 bytes
_MEMINFO = struct.Struct("<QQIIQIIII")        # 48 bytes
_MISC = struct.Struct("<III")                 # 12 bytes

# A MINIDUMP_MEMORY_INFO tuple mirrors the reader's decode order:
# (base, alloc_base, alloc_protect, region_size, state, protect, type).
MemInfo = Tuple[int, int, int, int, int, int, int]


def _build_minidump(
    descriptors: Sequence[Tuple[int, bytes]],
    mem_infos: Optional[Sequence[MemInfo]] = None,
    arch: int = AMD64,
    pid: Optional[int] = None,
    use_memory64: bool = False,
    *,
    signature: bytes = b"MDMP",
    version: int = 42,
    include_system_info: bool = True,
    os_major: int = 10,
    os_minor: int = 0,
) -> bytes:
    """Assemble a minimal minidump image and return its bytes.

    ``descriptors`` is a list of ``(start_va, blob)`` — each blob's file
    RVA is computed so it lands in a contiguous data region after every
    stream body, matching the Memory64List contiguous-payload convention.
    """
    # -- Decide the stream set and pre-compute each stream body's size. --
    mem_body_size = (
        _MEM64_HDR.size + len(descriptors) * _MEM64_DESC.size
        if use_memory64
        else 4 + len(descriptors) * _MEM_DESC.size
    )
    streams: List[Tuple[int, int]] = [(
        MEMORY64_LIST_STREAM if use_memory64 else MEMORY_LIST_STREAM,
        mem_body_size,
    )]
    if mem_infos is not None:
        streams.append((MEMORY_INFO_LIST_STREAM,
                        _MEMINFO_LIST_HDR.size + len(mem_infos) * _MEMINFO.size))
    if include_system_info:
        streams.append((SYSTEM_INFO_STREAM, 24))
    if pid is not None:
        streams.append((MISC_INFO_STREAM, _MISC.size))

    num_streams = len(streams)
    dir_rva = _HEADER.size
    body_start = dir_rva + num_streams * _DIRECTORY.size
    total_body = sum(size for _t, size in streams)
    blob_start = body_start + total_body

    # -- RVA of each descriptor's payload inside the contiguous blob region. --
    blob_region = bytearray()
    blob_rvas: List[int] = []
    for _start, blob in descriptors:
        blob_rvas.append(blob_start + len(blob_region))
        blob_region += blob

    # -- Build stream bodies + directory entries in lockstep. --
    bodies = bytearray()
    directory = bytearray()
    cursor = body_start
    for stream_type, size in streams:
        directory += _DIRECTORY.pack(stream_type, size, cursor)
        bodies += _stream_body(stream_type, size, descriptors, blob_rvas,
                               blob_start, mem_infos, arch, os_major, os_minor,
                               pid, use_memory64)
        cursor += size
    assert len(bodies) == total_body

    header = _HEADER.pack(signature, version, num_streams, dir_rva, 0, 0, 0)
    return bytes(header + directory + bodies + blob_region)


def _stream_body(stream_type, size, descriptors, blob_rvas, blob_start,
                 mem_infos, arch, os_major, os_minor, pid, use_memory64):
    """Serialize one stream body given the pre-computed blob RVAs."""
    if stream_type in (MEMORY_LIST_STREAM, MEMORY64_LIST_STREAM):
        if use_memory64:
            out = bytearray(_MEM64_HDR.pack(len(descriptors), blob_start))
            for start, blob in descriptors:
                out += _MEM64_DESC.pack(start, len(blob))
            return bytes(out)
        out = bytearray(struct.pack("<I", len(descriptors)))
        for (start, blob), rva in zip(descriptors, blob_rvas):
            out += _MEM_DESC.pack(start, len(blob), rva)
        return bytes(out)
    if stream_type == MEMORY_INFO_LIST_STREAM:
        out = bytearray(_MEMINFO_LIST_HDR.pack(
            _MEMINFO_LIST_HDR.size, _MEMINFO.size, len(mem_infos)))
        for (base, ab, ap, rs, st, pr, ty) in mem_infos:
            out += _MEMINFO.pack(base, ab, ap, 0, rs, st, pr, ty, 0)
        return bytes(out)
    if stream_type == SYSTEM_INFO_STREAM:
        # Real MINIDUMP_SYSTEM_INFO: arch (u16) @0, then an 8-byte
        # processor-info prefix, then MajorVersion @8, MinorVersion @12,
        # BuildNumber @16. The distinct BuildNumber makes a wrong-offset read
        # (the old @12/@16 bug) visible instead of coincidentally matching.
        return (struct.pack("<H", arch) + b"\x00" * 6
                + struct.pack("<III", os_major, os_minor, 19041) + b"\x00" * 4)
    if stream_type == MISC_INFO_STREAM:
        return _MISC.pack(_MISC.size, MINIDUMP_MISC1_PROCESS_ID, pid)
    raise AssertionError(f"unhandled stream type {stream_type}")


def _write(tmp_path: Path, data: bytes, name: str = "synthetic.dmp") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# -- Tests --------------------------------------------------------------------


def test_detect_format_minidump(tmp_path) -> None:
    blob = _build_minidump([(0x1000, b"ABCD")])
    assert detect_format(blob[:16]) == "minidump"


def test_header_and_descriptors_memory_list(tmp_path) -> None:
    """MemoryList descriptors are merged; read_at returns exact blobs."""
    descriptors = [(0x1000, b"hello!!!"), (0x2000, b"\xDE\xAD\xBE\xEF")]
    path = _write(tmp_path, _build_minidump(descriptors, version=42))

    with MinidumpReader(path) as reader:
        info = reader.info
        assert info.version == 42
        assert len(info.memory_descriptors) == 2
        by_start = {d.start: d for d in info.memory_descriptors}
        for start, blob in descriptors:
            d = by_start[start]
            assert d.size == len(blob)
            assert bytes(reader.read_at(d.rva, d.size)) == blob


def test_memory64_list_cumulative_rva(tmp_path) -> None:
    """Memory64List: single BaseRva + contiguous blob -> per-descriptor bytes."""
    descriptors = [(0x400000, b"AAAA"), (0x500000, b"BBBBBB"), (0x600000, b"C")]
    path = _write(tmp_path, _build_minidump(descriptors, use_memory64=True))

    with MinidumpReader(path) as reader:
        by_start = {d.start: d for d in reader.info.memory_descriptors}
        assert len(by_start) == 3
        for start, blob in descriptors:
            d = by_start[start]
            assert d.size == len(blob)
            assert bytes(reader.read_at(d.rva, d.size)) == blob
        # RVAs are strictly cumulative from a single base.
        rvas = [by_start[s].rva for s, _ in descriptors]
        assert rvas[1] == rvas[0] + 4
        assert rvas[2] == rvas[1] + 6


def test_memory_info_list_parsed(tmp_path) -> None:
    """MemoryInfoList entries decode via the SizeOfEntry stride."""
    mem_infos = [
        (0x1000, 0x1000, PAGE_READWRITE, 0x2000, MEM_COMMIT,
         PAGE_READWRITE, MEM_PRIVATE),
        (0x4000, 0x4000, PAGE_EXECUTE_READ, 0x1000, MEM_COMMIT,
         PAGE_EXECUTE_READ, MEM_IMAGE),
    ]
    path = _write(tmp_path, _build_minidump(
        [(0x1000, b"data")], mem_infos=mem_infos))

    with MinidumpReader(path) as reader:
        info = reader.info
        assert info.has_memory_info_list is True
        assert len(info.memory_info) == 2
        first = info.memory_info[0]
        assert first.base == 0x1000
        assert first.alloc_base == 0x1000
        assert first.region_size == 0x2000
        assert first.state == MEM_COMMIT
        assert first.protect == PAGE_READWRITE
        assert first.type == MEM_PRIVATE
        second = info.memory_info[1]
        assert second.protect == PAGE_EXECUTE_READ
        assert second.type == MEM_IMAGE


def test_system_info_and_misc_info(tmp_path) -> None:
    """SystemInfo arch + OS version and MiscInfo pid are extracted.

    os_major/os_minor are asserted (not just arch) so the SYSTEM_INFO field
    offsets stay pinned: with the pre-fix @12/@16 read a 10.0 dump decoded as
    0/<build> instead of 10/0.
    """
    path = _write(tmp_path, _build_minidump(
        [(0x1000, b"xy")], arch=AMD64, pid=4321, os_major=10, os_minor=0))

    with MinidumpReader(path) as reader:
        info = reader.info
        assert info.system_info is not None
        assert info.system_info.arch == AMD64
        assert info.system_info.os_major == 10
        assert info.system_info.os_minor == 0
        assert info.pid == 4321


def test_optional_streams_absent(tmp_path) -> None:
    """Missing optional streams are tolerated (no info list / sysinfo / pid)."""
    path = _write(tmp_path, _build_minidump(
        [(0x1000, b"z")], include_system_info=False, pid=None))

    with MinidumpReader(path) as reader:
        info = reader.info
        assert info.has_memory_info_list is False
        assert info.system_info is None
        assert info.pid is None
        assert len(info.memory_descriptors) == 1


def test_zero_size_descriptor_skipped(tmp_path) -> None:
    """A DataSize==0 descriptor is dropped, not emitted."""
    descriptors = [(0x1000, b""), (0x2000, b"keep")]
    path = _write(tmp_path, _build_minidump(descriptors))

    with MinidumpReader(path) as reader:
        starts = {d.start for d in reader.info.memory_descriptors}
        assert starts == {0x2000}


def test_zero_size_descriptor_skipped_memory64(tmp_path) -> None:
    """Zero-size descriptors are skipped in the Memory64List path too."""
    descriptors = [(0x1000, b"AA"), (0x2000, b""), (0x3000, b"BBB")]
    path = _write(tmp_path, _build_minidump(descriptors, use_memory64=True))

    with MinidumpReader(path) as reader:
        by_start = {d.start: d for d in reader.info.memory_descriptors}
        assert set(by_start) == {0x1000, 0x3000}
        # The skipped zero-size entry must not shift the cumulative cursor.
        assert bytes(reader.read_at(by_start[0x3000].rva, 3)) == b"BBB"


def test_bad_magic_raises(tmp_path) -> None:
    path = _write(tmp_path, _build_minidump(
        [(0x1000, b"AB")], signature=b"XXXX"))
    with pytest.raises(ValueError):
        with MinidumpReader(path):
            pass


def test_truncated_file_raises(tmp_path) -> None:
    """A file cut below its declared stream directory raises ValueError."""
    blob = _build_minidump([(0x1000, b"ABCD")])
    # Keep just the header: the directory range check must now fail.
    path = _write(tmp_path, blob[:_HEADER.size])
    with pytest.raises(ValueError):
        with MinidumpReader(path):
            pass


def test_empty_file_raises(tmp_path) -> None:
    path = _write(tmp_path, b"")
    with pytest.raises(ValueError):
        with MinidumpReader(path):
            pass
