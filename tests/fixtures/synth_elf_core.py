"""Synthetic ELF ``gcore.core`` + ``meta.json`` builder.

``build(run_dir)`` writes a realistic synthetic ``gcore.core`` (an ELF64
``ET_CORE`` with >10 ``PT_LOAD`` segments, plus a ``PT_NOTE`` carrying an
``NT_PRSTATUS`` note that encodes a plausible PID and an ``NT_FILE`` note that
records several file-backed mappings) alongside a matching ``meta.json``
sidecar, both under ``run_dir``.

The synthetic core is parsed by
:class:`memdiver.core.binary_formats.elf_core_reader.ElfCoreReader`, so its
byte layout mirrors exactly what that reader expects:

* little-endian ELF64 ``ET_CORE`` header (``e_machine`` = x86_64);
* a ``PT_NOTE`` program header whose payload is a sequence of ELF notes
  (``namesz``/``descsz``/``n_type`` header, 4-byte aligned name and desc);
* ``NT_PRSTATUS`` (type 1) with ``pr_pid`` at desc offset 32 (4-byte LE);
* ``NT_FILE`` (type 0x46494c45) with the ``count/page_size`` + triples +
  NUL-separated-names payload;
* >10 ``PT_LOAD`` program headers, each backing a small captured body.

The builder is idempotent: if both ``gcore.core`` and ``meta.json`` already
exist under ``run_dir`` it returns immediately without regenerating them.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

from memdiver.core.binary_formats.elf_core_reader import (
    ELF_MAGIC,
    ELFCLASS64,
    ELFDATA2LSB,
    ET_CORE,
    NT_FILE,
    NT_PRSTATUS,
    PF_R,
    PF_W,
    PF_X,
    PT_LOAD,
    PT_NOTE,
    _EHDR64_SIZE,
    _NHDR_FMT,
    _PHDR64_FMT,
    _PHDR64_SIZE,
    _PRSTATUS_PR_PID_OFFSET,
    _PRSTATUS_PR_PID_SIZE,
    _align4,
)

# -- Synthetic run parameters (kept internally consistent with meta.json) -----

_PID = 65219
_PAGE_SIZE = 4096
_ASLR_BASE = 0x400000
_NUM_LOAD = 12  # > 10 PT_LOAD segments, as the reader tests require.
_BODY_SIZE = 256  # bytes captured per PT_LOAD segment (keeps the core tiny).
_EM_X86_64 = 62

# A handful of plausible file-backed mappings for the NT_FILE note. The first
# entry's VA range coincides with the first PT_LOAD segment so the module map
# lines up with a captured region.
_FILE_MAPPINGS = [
    ("/usr/bin/gocryptfs", _ASLR_BASE, _ASLR_BASE + 0x2000, 0),
    ("/lib/x86_64-linux-gnu/libc.so.6", 0x7F000000_0000, 0x7F000000_2000, 0),
    ("/lib/x86_64-linux-gnu/libcrypto.so.3", 0x7F000010_0000, 0x7F000010_3000, 0),
]


def build(run_dir: Path) -> Path:
    """Write ``gcore.core`` + ``meta.json`` under ``run_dir`` (idempotent)."""
    run_dir = Path(run_dir)
    core_path = run_dir / "gcore.core"
    meta_path = run_dir / "meta.json"

    if core_path.is_file() and meta_path.is_file():
        return run_dir

    run_dir.mkdir(parents=True, exist_ok=True)

    core_bytes = _build_core_bytes()
    core_path.write_bytes(core_bytes)

    meta = _build_meta(core_size=len(core_bytes))
    meta_path.write_text(json.dumps(meta, indent=2))

    return run_dir


# -- ELF core assembly --------------------------------------------------------


def _build_core_bytes() -> bytes:
    """Assemble the full synthetic ELF64 ``ET_CORE`` byte stream."""
    note_payload = _build_note_payload()

    # Program-header table: one PT_NOTE followed by _NUM_LOAD PT_LOAD entries.
    e_phnum = 1 + _NUM_LOAD
    e_phoff = _EHDR64_SIZE
    phdr_table_size = e_phnum * _PHDR64_SIZE
    data_start = e_phoff + phdr_table_size

    # PT_NOTE data comes first in the data section, then the PT_LOAD bodies.
    note_offset = data_start
    note_size = len(note_payload)

    load_bodies: list[bytes] = []
    load_phdrs: list[bytes] = []
    body_offset = note_offset + note_size
    for i in range(_NUM_LOAD):
        vaddr = _ASLR_BASE + i * 0x1000
        body = _load_body(i)
        load_phdrs.append(struct.pack(
            _PHDR64_FMT,
            PT_LOAD,             # p_type
            _load_flags(i),      # p_flags
            body_offset,         # p_offset
            vaddr,               # p_vaddr
            vaddr,               # p_paddr
            len(body),           # p_filesz
            len(body),           # p_memsz
            _PAGE_SIZE,          # p_align
        ))
        load_bodies.append(body)
        body_offset += len(body)

    note_phdr = struct.pack(
        _PHDR64_FMT,
        PT_NOTE,        # p_type
        0,              # p_flags
        note_offset,    # p_offset
        0,              # p_vaddr
        0,              # p_paddr
        note_size,      # p_filesz
        note_size,      # p_memsz
        1,              # p_align
    )

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ELF_MAGIC + bytes([ELFCLASS64, ELFDATA2LSB, 1]) + b"\x00" * 9,
        ET_CORE,        # e_type
        _EM_X86_64,     # e_machine
        1,              # e_version
        0,              # e_entry
        e_phoff,        # e_phoff
        0,              # e_shoff
        0,              # e_flags
        _EHDR64_SIZE,   # e_ehsize
        _PHDR64_SIZE,   # e_phentsize
        e_phnum,        # e_phnum
        0, 0, 0,        # e_shentsize, e_shnum, e_shstrndx
    )

    return b"".join(
        [ehdr, note_phdr, *load_phdrs, note_payload, *load_bodies]
    )


def _load_flags(index: int) -> int:
    """Vary segment permissions so the module map looks realistic."""
    if index == 0:
        return PF_R | PF_X
    if index % 3 == 0:
        return PF_R | PF_W
    return PF_R


def _load_body(index: int) -> bytes:
    """Deterministic, recognisable content for PT_LOAD segment ``index``."""
    tag = f"SEG{index:02d}".encode("ascii")
    filler = bytes(((index * 7 + j) & 0xFF) for j in range(_BODY_SIZE - len(tag)))
    return tag + filler


# -- PT_NOTE payload ----------------------------------------------------------


def _build_note_payload() -> bytes:
    """Concatenate the NT_PRSTATUS and NT_FILE notes for the PT_NOTE segment."""
    prstatus = _pack_note(NT_PRSTATUS, b"CORE\x00", _build_prstatus_desc())
    nt_file = _pack_note(NT_FILE, b"CORE\x00", _build_nt_file_desc())
    return prstatus + nt_file


def _pack_note(n_type: int, name: bytes, desc: bytes) -> bytes:
    """Pack a single ELF note (name/desc padded to 4-byte alignment).

    ``name`` must already include its trailing NUL; ``namesz``/``descsz`` count
    the raw (unpadded) lengths, matching what :class:`ElfCoreReader` reads.
    """
    namesz = len(name)
    descsz = len(desc)
    header = struct.pack(_NHDR_FMT, namesz, descsz, n_type)
    name_padded = name + b"\x00" * (_align4(namesz) - namesz)
    desc_padded = desc + b"\x00" * (_align4(descsz) - descsz)
    return header + name_padded + desc_padded


def _build_prstatus_desc() -> bytes:
    """An elf_prstatus desc with ``pr_pid`` at offset 32 (rest zero-filled)."""
    desc = bytearray(150)  # comfortably larger than the pr_pid offset.
    end = _PRSTATUS_PR_PID_OFFSET + _PRSTATUS_PR_PID_SIZE
    desc[_PRSTATUS_PR_PID_OFFSET:end] = _PID.to_bytes(
        _PRSTATUS_PR_PID_SIZE, "little", signed=True,
    )
    return bytes(desc)


def _build_nt_file_desc() -> bytes:
    """Encode the NT_FILE payload: count/page_size + triples + names."""
    count = len(_FILE_MAPPINGS)
    header = count.to_bytes(8, "little") + _PAGE_SIZE.to_bytes(8, "little")

    triples = bytearray()
    names = bytearray()
    for path, start, end, file_ofs_pages in _FILE_MAPPINGS:
        triples += start.to_bytes(8, "little")
        triples += end.to_bytes(8, "little")
        triples += file_ofs_pages.to_bytes(8, "little")
        names += path.encode("utf-8") + b"\x00"

    return bytes(header) + bytes(triples) + bytes(names)


# -- meta.json ----------------------------------------------------------------


def _build_meta(core_size: int) -> dict:
    """Build a ``meta.json`` payload consistent with the generated core."""
    return {
        "run_id": 1,
        "cipher": "aes",
        "password": "correct horse battery staple",
        "master_key_hex": "00112233445566778899aabbccddeeff",
        "aslr_base": hex(_ASLR_BASE),
        "pid": _PID,
        "dumps": {
            "gcore": {"path": "run_0001/gcore.core", "size": core_size},
            "memslicer": {"path": "run_0001/memslicer.msl", "size": 0},
        },
    }
