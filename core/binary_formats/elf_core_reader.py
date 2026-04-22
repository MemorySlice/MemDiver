"""Minimal mmap-only ELF64 core-dump reader.

Parses enough of an ``ET_CORE`` ELF64 file to drive the
:class:`core.dump_sources.gcore.GCoreDumpSource`:

- Every ``PT_LOAD`` program header (for virtual-address -> file-offset).
- ``PT_NOTE`` segments, with special treatment for ``NT_FILE`` (module
  map) and ``NT_PRSTATUS`` (to extract the recorded PID).

The reader never slurps the whole file: all I/O goes through a single
``mmap`` view opened in :meth:`ElfCoreReader.open`. Byte order is
restricted to little-endian ELF64 because Linux ``gcore`` on x86_64 /
aarch64 always emits that shape; big-endian or 32-bit inputs raise
``NotImplementedError`` rather than silently mis-parsing.
"""

from __future__ import annotations

import logging
import mmap
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("memdiver.core.binary_formats.elf_core_reader")


# ELF constants (subset) ------------------------------------------------------

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_CORE = 4

PT_LOAD = 1
PT_NOTE = 4

# Linux note types for core files.
NT_PRSTATUS = 1
# NT_FILE is "FILE" interpreted as little-endian u32; kernel emits 0x46494c45.
NT_FILE = 0x46494C45

# PF_* program-header flags (lowest 3 bits).
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4


# Public data classes ---------------------------------------------------------


@dataclass
class PtLoadSegment:
    """A single ``PT_LOAD`` program header."""

    vaddr: int
    memsz: int
    file_offset: int
    filesz: int
    flags: int  # r/w/x bitmask (PF_R|PF_W|PF_X)


@dataclass
class NtFileEntry:
    """One file-backed mapping recorded in an ``NT_FILE`` note."""

    start: int
    end: int
    page_offset: int
    path: str


@dataclass
class ElfCoreInfo:
    """Parsed summary of an ELF core dump."""

    pid: Optional[int] = None
    segments: List[PtLoadSegment] = field(default_factory=list)
    file_mappings: List[NtFileEntry] = field(default_factory=list)


# struct formats (ELF64 little-endian) ---------------------------------------

# Ehdr64: we only need the fields up to and including e_phnum.
_EHDR64_FMT = "<16sHHIQQQIHHHHHH"
_EHDR64_SIZE = struct.calcsize(_EHDR64_FMT)
# (e_ident[16], e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
#  e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)

# Phdr64: p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align.
_PHDR64_FMT = "<IIQQQQQQ"
_PHDR64_SIZE = struct.calcsize(_PHDR64_FMT)

# Note header (common to 32/64-bit): namesz, descsz, n_type.
_NHDR_FMT = "<III"
_NHDR_SIZE = struct.calcsize(_NHDR_FMT)

# NT_PRSTATUS: pid is at offset 32 in the elf_prstatus struct on x86_64.
# Layout (prefix): struct elf_siginfo (12 bytes) + pr_cursig (short)
# + pr_sigpend (unsigned long = 8) + pr_sighold (unsigned long = 8)
# + pr_pid (pid_t = int) ...
# That puts pr_pid at 12 + 2 + 2 (pad) + 8 + 8 = 32. Validate by reading an int.
_PRSTATUS_PR_PID_OFFSET = 32
_PRSTATUS_PR_PID_SIZE = 4


class ElfCoreReader:
    """mmap-only reader for Linux ELF64 core dumps."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._file = None
        self._mmap: Optional[mmap.mmap] = None
        self._info: Optional[ElfCoreInfo] = None

    # -- Lifecycle ----------------------------------------------------------

    def open(self) -> None:
        """Map the file and parse ehdr + phdrs + notes."""
        if self._mmap is not None:
            return
        self._file = open(self._path, "rb")
        size = self._path.stat().st_size
        if size == 0:
            raise ValueError(f"Empty ELF core file: {self._path}")
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

    def __enter__(self) -> "ElfCoreReader":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- Public properties -------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def info(self) -> ElfCoreInfo:
        if self._info is None:
            raise RuntimeError("ElfCoreReader not opened")
        return self._info

    @property
    def size(self) -> int:
        return len(self._mmap) if self._mmap is not None else 0

    # -- Reading ------------------------------------------------------------

    def read_at(self, file_offset: int, length: int) -> bytes:
        """Read ``length`` bytes at absolute file offset via the mmap."""
        if self._mmap is None:
            return b""
        if file_offset < 0 or file_offset >= len(self._mmap):
            return b""
        end = min(file_offset + length, len(self._mmap))
        return self._mmap[file_offset:end]

    def read_va(self, va: int, length: int) -> bytes:
        """Read ``length`` bytes starting at virtual address ``va``.

        Walks the ``PT_LOAD`` table and spans segment boundaries if the
        requested range crosses into the next PT_LOAD. Returns whatever
        bytes are captured; gaps produce a short read.
        """
        if length <= 0 or self._mmap is None:
            return b""
        result = bytearray()
        remaining = length
        cursor = va
        for seg in self.info.segments:
            if seg.filesz == 0:
                continue
            seg_end = seg.vaddr + seg.filesz
            if cursor >= seg_end:
                continue
            if cursor < seg.vaddr:
                # Gap before this segment: stop, short-read what we have.
                break
            inside = cursor - seg.vaddr
            take = min(seg.filesz - inside, remaining)
            file_off = seg.file_offset + inside
            result.extend(self.read_at(file_off, take))
            remaining -= take
            cursor += take
            if remaining <= 0:
                break
        return bytes(result)

    # -- Parsing ------------------------------------------------------------

    def _parse(self) -> ElfCoreInfo:
        assert self._mmap is not None
        buf = self._mmap
        if len(buf) < _EHDR64_SIZE:
            raise ValueError("File too small for an ELF64 header")
        self._validate_ident(bytes(buf[:16]))

        (_, e_type, _e_machine, _e_version, _e_entry, e_phoff, _e_shoff,
         _e_flags, _e_ehsize, e_phentsize, e_phnum,
         _e_shentsize, _e_shnum, _e_shstrndx) = struct.unpack(
            _EHDR64_FMT, bytes(buf[:_EHDR64_SIZE]),
        )

        if e_type != ET_CORE:
            raise ValueError(f"Not an ET_CORE file (e_type={e_type})")
        if e_phentsize != _PHDR64_SIZE:
            raise ValueError(
                f"Unexpected e_phentsize={e_phentsize} (want {_PHDR64_SIZE})",
            )

        info = ElfCoreInfo()
        for idx in range(e_phnum):
            phdr_off = e_phoff + idx * e_phentsize
            if phdr_off + _PHDR64_SIZE > len(buf):
                logger.warning("Truncated phdr table at index %d", idx)
                break
            (p_type, p_flags, p_offset, p_vaddr, _p_paddr,
             p_filesz, p_memsz, _p_align) = struct.unpack(
                _PHDR64_FMT, bytes(buf[phdr_off:phdr_off + _PHDR64_SIZE]),
            )
            if p_type == PT_LOAD:
                info.segments.append(PtLoadSegment(
                    vaddr=p_vaddr,
                    memsz=p_memsz,
                    file_offset=p_offset,
                    filesz=p_filesz,
                    flags=p_flags & (PF_R | PF_W | PF_X),
                ))
            elif p_type == PT_NOTE:
                self._parse_note_segment(buf, p_offset, p_filesz, info)

        return info

    @staticmethod
    def _validate_ident(ident: bytes) -> None:
        if not ident.startswith(ELF_MAGIC):
            raise ValueError("Not an ELF file: missing \\x7fELF magic")
        ei_class = ident[4]
        ei_data = ident[5]
        if ei_class != ELFCLASS64:
            raise NotImplementedError(
                f"Only ELFCLASS64 supported (got ei_class={ei_class})",
            )
        if ei_data != ELFDATA2LSB:
            raise NotImplementedError(
                f"Only little-endian ELF supported (got ei_data={ei_data})",
            )

    def _parse_note_segment(
        self,
        buf: mmap.mmap,
        seg_offset: int,
        seg_size: int,
        info: ElfCoreInfo,
    ) -> None:
        """Walk the note records inside a PT_NOTE segment."""
        end = min(seg_offset + seg_size, len(buf))
        cursor = seg_offset
        while cursor + _NHDR_SIZE <= end:
            namesz, descsz, n_type = struct.unpack(
                _NHDR_FMT, bytes(buf[cursor:cursor + _NHDR_SIZE]),
            )
            name_start = cursor + _NHDR_SIZE
            desc_start = name_start + _align4(namesz)
            desc_end = desc_start + descsz
            if desc_end > end:
                logger.warning(
                    "Truncated note record at offset %d (n_type=%#x)",
                    cursor, n_type,
                )
                break
            desc_bytes = bytes(buf[desc_start:desc_end])
            if n_type == NT_PRSTATUS and info.pid is None:
                info.pid = _parse_prstatus_pid(desc_bytes)
            elif n_type == NT_FILE and not info.file_mappings:
                info.file_mappings = _parse_nt_file(desc_bytes)
            # Advance past the desc with 4-byte alignment padding.
            cursor = desc_start + _align4(descsz)


# Helper functions ------------------------------------------------------------


def _align4(value: int) -> int:
    """Round ``value`` up to the next multiple of 4 (ELF note alignment)."""
    return (value + 3) & ~3


def _align_padding(value: int) -> int:
    """Padding bytes appended after a note field to reach 4-byte alignment."""
    return _align4(value) - value


def _parse_prstatus_pid(desc: bytes) -> Optional[int]:
    """Extract ``pr_pid`` from an ``NT_PRSTATUS`` note description."""
    off = _PRSTATUS_PR_PID_OFFSET
    size = _PRSTATUS_PR_PID_SIZE
    if len(desc) < off + size:
        return None
    return int.from_bytes(desc[off:off + size], "little", signed=True)


def _parse_nt_file(desc: bytes) -> List[NtFileEntry]:
    """Decode the ``NT_FILE`` description payload into module entries.

    Layout per Linux kernel (``fs/binfmt_elf.c``):

        long count
        long page_size
        { long start; long end; long file_ofs } * count
        char[] filename0 filename1 ... filenameN-1   (NUL-separated)
    """
    if len(desc) < 16:
        return []
    count = int.from_bytes(desc[0:8], "little", signed=False)
    page_size = int.from_bytes(desc[8:16], "little", signed=False)
    triples_start = 16
    triples_end = triples_start + count * 24  # 3 * 8 bytes
    if triples_end > len(desc):
        return []
    names_blob = desc[triples_end:]
    names = names_blob.split(b"\x00")
    # The blob ends with a trailing NUL which yields an empty string — drop it.
    if names and names[-1] == b"":
        names = names[:-1]
    if len(names) < count:
        # Defensive: pad with empty strings rather than raising.
        names = names + [b""] * (count - len(names))

    entries: List[NtFileEntry] = []
    for i in range(count):
        base = triples_start + i * 24
        start = int.from_bytes(desc[base:base + 8], "little", signed=False)
        end = int.from_bytes(desc[base + 8:base + 16], "little", signed=False)
        file_ofs_pages = int.from_bytes(
            desc[base + 16:base + 24], "little", signed=False,
        )
        page_offset = file_ofs_pages * page_size
        try:
            path = names[i].decode("utf-8", errors="replace")
        except (UnicodeDecodeError, IndexError):
            path = ""
        entries.append(NtFileEntry(
            start=start, end=end, page_offset=page_offset, path=path,
        ))
    return entries
