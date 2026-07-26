"""Minimal mmap-only Windows Minidump (.dmp) reader.

Parses enough of a ``MINIDUMP`` file (magic ``MDMP``) to drive memory
extraction and region enumeration:

- ``MemoryListStream`` / ``Memory64ListStream`` -> the set of
  :class:`MinidumpMemoryDescriptor` mappings (virtual address ->
  file-relative RVA) used for reading target memory.
- ``MemoryInfoListStream`` -> per-region protection/state metadata
  (:class:`MinidumpMemoryInfo`), matching ``VirtualQuery``.
- ``SystemInfoStream`` -> processor architecture and OS version.
- ``MiscInfoStream`` -> the recorded process id.

The reader never slurps the whole file: all I/O goes through a single
``mmap`` view opened in :meth:`MinidumpReader.open`. Minidumps are
always little-endian; unknown stream types are skipped and optional
streams may be absent. Any Rva/DataSize that overruns the file raises
``ValueError`` rather than silently mis-parsing.
"""

from __future__ import annotations

import logging
import mmap
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("memdiver.core.binary_formats.minidump_reader")


# Minidump constants (subset) -------------------------------------------------

# "MDMP" == 0x504D444D little-endian.
MDMP_MAGIC = b"MDMP"

# MINIDUMP_STREAM_TYPE values we care about.
THREAD_LIST_STREAM = 3
MODULE_LIST_STREAM = 4
MEMORY_LIST_STREAM = 5
SYSTEM_INFO_STREAM = 7
MEMORY64_LIST_STREAM = 9
MISC_INFO_STREAM = 15
MEMORY_INFO_LIST_STREAM = 16

# MEMORY_INFORMATION.State (Win32 MEM_*).
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

# MEMORY_INFORMATION.Type (Win32 MEM_*).
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

# MEMORY_INFORMATION.Protect / AllocationProtect (Win32 PAGE_*).
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

# MINIDUMP_SYSTEM_INFO.ProcessorArchitecture (PROCESSOR_ARCHITECTURE_*).
PROCESSOR_ARCHITECTURE_INTEL = 0
PROCESSOR_ARCHITECTURE_ARM = 5
PROCESSOR_ARCHITECTURE_AMD64 = 9
PROCESSOR_ARCHITECTURE_ARM64 = 12

# MINIDUMP_MISC_INFO.Flags1 bit: ProcessId field is valid.
MINIDUMP_MISC1_PROCESS_ID = 0x1


# Public data classes ---------------------------------------------------------


@dataclass
class MinidumpMemoryDescriptor:
    """One saved memory range (MINIDUMP_MEMORY_DESCRIPTOR[64]).

    ``rva`` is the absolute file offset at which the ``size`` bytes for
    the range starting at virtual address ``start`` are stored.
    """

    start: int
    size: int
    rva: int


@dataclass
class MinidumpMemoryInfo:
    """One region record from MINIDUMP_MEMORY_INFO (mirrors VirtualQuery)."""

    base: int
    alloc_base: int
    alloc_protect: int
    region_size: int
    state: int
    protect: int
    type: int


@dataclass
class MinidumpSystemInfo:
    """Subset of MINIDUMP_SYSTEM_INFO (arch + OS version)."""

    arch: int
    os_major: int
    os_minor: int


@dataclass
class MinidumpInfo:
    """Parsed summary of a Windows minidump."""

    version: int = 0
    memory_descriptors: List[MinidumpMemoryDescriptor] = field(default_factory=list)
    memory_info: List[MinidumpMemoryInfo] = field(default_factory=list)
    system_info: Optional[MinidumpSystemInfo] = None
    pid: Optional[int] = None
    has_memory_info_list: bool = False


# struct formats (minidump, little-endian) -----------------------------------

# MINIDUMP_HEADER: Signature, Version, NumberOfStreams, StreamDirectoryRva,
# CheckSum, TimeDateStamp, Flags.
_HEADER_FMT = "<4sIIIIIq"
_HEADER = struct.Struct(_HEADER_FMT)
_HEADER_SIZE = _HEADER.size  # 28

# MINIDUMP_DIRECTORY: StreamType, Location.DataSize, Location.Rva.
_DIRECTORY = struct.Struct("<III")
_DIRECTORY_SIZE = _DIRECTORY.size  # 12

# MINIDUMP_MEMORY_DESCRIPTOR: StartOfMemoryRange, Memory.DataSize, Memory.Rva.
_MEMORY_DESCRIPTOR = struct.Struct("<QII")
_MEMORY_DESCRIPTOR_SIZE = _MEMORY_DESCRIPTOR.size  # 16

# MINIDUMP_MEMORY64_LIST header: NumberOfMemoryRanges (u64), BaseRva (u64).
_MEMORY64_HEADER = struct.Struct("<QQ")
_MEMORY64_HEADER_SIZE = _MEMORY64_HEADER.size  # 16

# MINIDUMP_MEMORY_DESCRIPTOR64: StartOfMemoryRange, DataSize.
_MEMORY_DESCRIPTOR64 = struct.Struct("<QQ")
_MEMORY_DESCRIPTOR64_SIZE = _MEMORY_DESCRIPTOR64.size  # 16

# MINIDUMP_MEMORY_INFO_LIST header: SizeOfHeader, SizeOfEntry, NumberOfEntries.
_MEMORY_INFO_LIST_HEADER = struct.Struct("<IIQ")
_MEMORY_INFO_LIST_HEADER_SIZE = _MEMORY_INFO_LIST_HEADER.size  # 16

# MINIDUMP_MEMORY_INFO: BaseAddress, AllocationBase, AllocationProtect,
# __alignment1, RegionSize, State, Protect, Type, __alignment2.
_MEMORY_INFO = struct.Struct("<QQIIQIIII")
_MEMORY_INFO_SIZE = _MEMORY_INFO.size  # 48

# MINIDUMP_MISC_INFO (prefix): SizeOfInfo, Flags1, ProcessId.
_MISC_INFO = struct.Struct("<III")
_MISC_INFO_SIZE = _MISC_INFO.size  # 12


class MinidumpReader:
    """mmap-only reader for Windows minidump (.dmp) files."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._file = None
        self._mmap: Optional[mmap.mmap] = None
        self._info: Optional[MinidumpInfo] = None

    # -- Lifecycle ----------------------------------------------------------

    def open(self) -> None:
        """Map the file and parse the header + stream directory."""
        if self._mmap is not None:
            return
        self._file = open(self._path, "rb")
        size = self._path.stat().st_size
        if size == 0:
            raise ValueError(f"Empty minidump file: {self._path}")
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        self._info = self._parse()

    def close(self) -> None:
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        if self._file is not None:
            self._file.close()
            self._file = None
        self._info = None

    def __enter__(self) -> "MinidumpReader":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- Public properties -------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def info(self) -> MinidumpInfo:
        if self._info is None:
            raise RuntimeError("MinidumpReader not opened")
        return self._info

    @property
    def size(self) -> int:
        return len(self._mmap) if self._mmap is not None else 0

    # -- Reading ------------------------------------------------------------

    def read_at(self, rva: int, size: int) -> bytes:
        """Return ``size`` bytes at ``rva`` (a bounded copy out of the mmap).

        The range is bounds-checked against the mapped file; an out-of-range
        or truncated request raises ``ValueError``. A copy is returned rather
        than a zero-copy ``memoryview`` on purpose: an exported view of the mmap
        makes ``close()`` raise ``BufferError`` ("cannot close exported pointers
        exist") if any caller still holds it. These reads are small structural /
        region slices, so the copy cost is negligible and every caller already
        copies the result into its own buffer.
        """
        if self._mmap is None:
            raise RuntimeError("MinidumpReader not opened")
        self._check_range(rva, size, "read")
        return self._mmap[rva:rva + size]

    # -- Parsing ------------------------------------------------------------

    def _check_range(self, rva: int, size: int, what: str) -> None:
        """Raise ``ValueError`` unless ``[rva, rva+size)`` lies in the file."""
        length = len(self._mmap) if self._mmap is not None else 0
        if rva < 0 or size < 0 or rva + size > length:
            raise ValueError(
                f"truncated/invalid minidump: {what} at rva={rva} size={size} "
                f"exceeds file length {length}",
            )

    def _parse(self) -> MinidumpInfo:
        assert self._mmap is not None
        buf = self._mmap
        if len(buf) < _HEADER_SIZE:
            raise ValueError(
                "truncated/invalid minidump: file too small for MINIDUMP_HEADER",
            )

        (signature, version, num_streams, stream_dir_rva,
         _checksum, _timestamp, _flags) = _HEADER.unpack_from(buf, 0)
        if signature != MDMP_MAGIC:
            raise ValueError(
                f"Not a minidump file: bad signature {signature!r} "
                f"(want {MDMP_MAGIC!r})",
            )

        info = MinidumpInfo(version=version)

        # Walk the MINIDUMP_DIRECTORY array.
        dir_bytes = num_streams * _DIRECTORY_SIZE
        self._check_range(stream_dir_rva, dir_bytes, "stream directory")
        for idx in range(num_streams):
            entry_off = stream_dir_rva + idx * _DIRECTORY_SIZE
            stream_type, data_size, rva = _DIRECTORY.unpack_from(buf, entry_off)
            self._dispatch_stream(stream_type, data_size, rva, info)

        return info

    def _dispatch_stream(
        self,
        stream_type: int,
        data_size: int,
        rva: int,
        info: MinidumpInfo,
    ) -> None:
        """Route one directory entry to its stream parser (skip unknown)."""
        if stream_type == MEMORY_LIST_STREAM:
            self._parse_memory_list(rva, data_size, info)
        elif stream_type == MEMORY64_LIST_STREAM:
            self._parse_memory64_list(rva, data_size, info)
        elif stream_type == MEMORY_INFO_LIST_STREAM:
            self._parse_memory_info_list(rva, data_size, info)
        elif stream_type == SYSTEM_INFO_STREAM:
            self._parse_system_info(rva, data_size, info)
        elif stream_type == MISC_INFO_STREAM:
            self._parse_misc_info(rva, data_size, info)
        else:
            logger.debug("Skipping stream type %d (rva=%d)", stream_type, rva)

    def _parse_memory_list(
        self, rva: int, data_size: int, info: MinidumpInfo,
    ) -> None:
        """Parse a MINIDUMP_MEMORY_LIST (embedded descriptors + Rva)."""
        buf = self._mmap
        assert buf is not None
        self._check_range(rva, 4, "memory list header")
        count = struct.unpack_from("<I", buf, rva)[0]
        base = rva + 4
        array_bytes = count * _MEMORY_DESCRIPTOR_SIZE
        self._check_range(base, array_bytes, "memory list descriptors")
        for i in range(count):
            off = base + i * _MEMORY_DESCRIPTOR_SIZE
            start, size, mem_rva = _MEMORY_DESCRIPTOR.unpack_from(buf, off)
            if size == 0:
                continue
            self._check_range(mem_rva, size, "memory descriptor payload")
            info.memory_descriptors.append(
                MinidumpMemoryDescriptor(start=start, size=size, rva=mem_rva),
            )

    def _parse_memory64_list(
        self, rva: int, data_size: int, info: MinidumpInfo,
    ) -> None:
        """Parse a MINIDUMP_MEMORY64_LIST.

        Descriptor payloads are stored contiguously starting at ``BaseRva``;
        each descriptor's absolute rva is the running cumulative offset from
        ``BaseRva`` (each range consumes ``DataSize`` bytes in order).
        """
        buf = self._mmap
        assert buf is not None
        self._check_range(rva, _MEMORY64_HEADER_SIZE, "memory64 list header")
        count, base_rva = _MEMORY64_HEADER.unpack_from(buf, rva)
        desc_base = rva + _MEMORY64_HEADER_SIZE
        array_bytes = count * _MEMORY_DESCRIPTOR64_SIZE
        self._check_range(desc_base, array_bytes, "memory64 list descriptors")

        cursor = base_rva
        for i in range(count):
            off = desc_base + i * _MEMORY_DESCRIPTOR64_SIZE
            start, size = _MEMORY_DESCRIPTOR64.unpack_from(buf, off)
            if size == 0:
                continue
            self._check_range(cursor, size, "memory64 descriptor payload")
            info.memory_descriptors.append(
                MinidumpMemoryDescriptor(start=start, size=size, rva=cursor),
            )
            cursor += size

    def _parse_memory_info_list(
        self, rva: int, data_size: int, info: MinidumpInfo,
    ) -> None:
        """Parse a MINIDUMP_MEMORY_INFO_LIST.

        Iterate entries using ``SizeOfEntry`` as the stride (forward-compat)
        but only decode the first 48 bytes (MINIDUMP_MEMORY_INFO) of each.
        """
        buf = self._mmap
        assert buf is not None
        self._check_range(rva, _MEMORY_INFO_LIST_HEADER_SIZE, "memory info list header")
        size_of_header, size_of_entry, num_entries = (
            _MEMORY_INFO_LIST_HEADER.unpack_from(buf, rva)
        )
        info.has_memory_info_list = True
        if size_of_entry < _MEMORY_INFO_SIZE:
            logger.warning(
                "MINIDUMP_MEMORY_INFO SizeOfEntry=%d smaller than expected %d",
                size_of_entry, _MEMORY_INFO_SIZE,
            )
            return
        base = rva + size_of_header
        for i in range(num_entries):
            off = base + i * size_of_entry
            self._check_range(off, _MEMORY_INFO_SIZE, "memory info entry")
            (base_addr, alloc_base, alloc_protect, _align1, region_size,
             state, protect, mem_type, _align2) = _MEMORY_INFO.unpack_from(buf, off)
            info.memory_info.append(MinidumpMemoryInfo(
                base=base_addr,
                alloc_base=alloc_base,
                alloc_protect=alloc_protect,
                region_size=region_size,
                state=state,
                protect=protect,
                type=mem_type,
            ))

    def _parse_system_info(
        self, rva: int, data_size: int, info: MinidumpInfo,
    ) -> None:
        """Parse the ProcessorArchitecture + OS version of MINIDUMP_SYSTEM_INFO."""
        buf = self._mmap
        assert buf is not None
        # ProcessorArchitecture (u16) at 0; MajorVersion/MinorVersion (u32)
        # begin at offset 12 (after the 12-byte processor-info prefix).
        self._check_range(rva, 20, "system info")
        arch = struct.unpack_from("<H", buf, rva)[0]
        os_major = struct.unpack_from("<I", buf, rva + 12)[0]
        os_minor = struct.unpack_from("<I", buf, rva + 16)[0]
        info.system_info = MinidumpSystemInfo(
            arch=arch, os_major=os_major, os_minor=os_minor,
        )

    def _parse_misc_info(
        self, rva: int, data_size: int, info: MinidumpInfo,
    ) -> None:
        """Parse the ProcessId out of MINIDUMP_MISC_INFO (if flagged valid)."""
        buf = self._mmap
        assert buf is not None
        self._check_range(rva, _MISC_INFO_SIZE, "misc info")
        _size_of_info, flags1, process_id = _MISC_INFO.unpack_from(buf, rva)
        if flags1 & MINIDUMP_MISC1_PROCESS_ID:
            info.pid = process_id
