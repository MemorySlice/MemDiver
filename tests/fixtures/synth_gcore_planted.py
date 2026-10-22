"""A tiny gcore ELF core with one planted payload whose raw and vas offsets differ.

``write_planted_core(path)`` writes an ELF64 ``ET_CORE`` with two ``PT_LOAD``
segments whose bodies are stored in REVERSE file order, so the payload planted
in the second segment sits at a different offset in the ``"raw"`` view (file
bytes) than in the ``"vas"`` view (PT_LOADs concatenated in program-header
order). Any surface that sizes or reads in one view and reports offsets in the
other shows up as a wrong byte against this file.

Usable from pytest and as a script (the Playwright e2e suite runs it to build
its gcore fixture)::

    python -m tests.fixtures.synth_gcore_planted OUT.core
"""
from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

from memdiver.core.binary_formats.elf_core_reader import (
    ELF_MAGIC,
    ELFCLASS64,
    ELFDATA2LSB,
    ET_CORE,
    PF_R,
    PF_W,
    PT_LOAD,
    _EHDR64_SIZE,
    _PHDR64_FMT,
    _PHDR64_SIZE,
)

PLANTED_SECRET = b"secret=ABCDEF01"
SECRET_REGEX = r"secret=[A-F0-9]{8}"

_SEGMENT_SIZE = 4096
_PLANT_AT = 0x100  # offset of the payload inside the second segment
_VADDRS = (0x400000, 0x7F0000000000)


@dataclass(frozen=True)
class PlantedCore:
    path: Path
    raw_offset: int
    vas_offset: int
    raw_size: int
    vas_size: int


def _bodies(payload: bytes) -> tuple:
    first = bytes((j * 7 + 3) & 0x7F for j in range(_SEGMENT_SIZE))
    second = bytearray(b"\x00" * _SEGMENT_SIZE)
    second[_PLANT_AT:_PLANT_AT + len(payload)] = payload
    return first, bytes(second)


def write_planted_core(path: Path, payload: bytes = PLANTED_SECRET) -> PlantedCore:
    """Write the core to *path*; return where *payload* lands in each view."""
    path = Path(path)
    bodies = _bodies(payload)
    data_off = _EHDR64_SIZE + len(bodies) * _PHDR64_SIZE
    # Reverse file order: segment 1's body first, then segment 0's.
    file_offsets = (data_off + _SEGMENT_SIZE, data_off)
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ELF_MAGIC + bytes([ELFCLASS64, ELFDATA2LSB, 1]) + b"\x00" * 9,
        ET_CORE, 62, 1, 0, _EHDR64_SIZE, 0, 0, _EHDR64_SIZE, _PHDR64_SIZE,
        len(bodies), 0, 0, 0,
    )
    phdrs = b"".join(
        struct.pack(_PHDR64_FMT, PT_LOAD, PF_R | PF_W, file_offsets[i],
                    _VADDRS[i], _VADDRS[i], _SEGMENT_SIZE, _SEGMENT_SIZE, 0x1000)
        for i in range(len(bodies)))
    blob = ehdr + phdrs + bodies[1] + bodies[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return PlantedCore(
        path=path,
        raw_offset=data_off + _PLANT_AT,
        vas_offset=_SEGMENT_SIZE + _PLANT_AT,
        raw_size=len(blob),
        vas_size=_SEGMENT_SIZE * len(bodies),
    )


def main(argv: list) -> int:
    if len(argv) != 1:
        print("usage: synth_gcore_planted.py OUT.core", file=sys.stderr)
        return 2
    core = write_planted_core(Path(argv[0]))
    print(json.dumps({
        "path": str(core.path),
        "raw_offset": core.raw_offset,
        "vas_offset": core.vas_offset,
        "raw_size": core.raw_size,
        "vas_size": core.vas_size,
        "secret": PLANTED_SECRET.decode("ascii"),
        "regex": SECRET_REGEX,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
