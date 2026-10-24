"""Builders for ``.msl`` files with several VAS maps (spec 5.8 rule 25).

Capture-segment maps go through ``MslWriter.add_vas_map``; extension-segment
maps (spec 4.6) are VAS_MAP blocks in ``add_extension_segment``.
"""

from pathlib import Path
from typing import Sequence

from memdiver.msl.enums import BlockType, VasNameSource
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import ExtensionBlock, MslWriter, _build_vas_map_payload

HEAP_BASE = 0x5555_0000_0000
HEAP_SIZE = 0x4000


def vas_entry(path: str, base: int = HEAP_BASE, size: int = HEAP_SIZE,
              name_source: int = VasNameSource.UNSPECIFIED) -> MslVasEntry:
    """One rw- VAS entry named *path*."""
    return MslVasEntry(base, size, 0x03, 0x05, path, int(name_source))


def write_vas_msl(path: Path,
                  capture_maps: Sequence[Sequence[MslVasEntry]] = (),
                  segment_maps: Sequence[Sequence[MslVasEntry]] = (),
                  imported: bool = False) -> Path:
    """Write a one-region file with *capture_maps* then one segment per *segment_maps*."""
    w = MslWriter(path, imported=imported)
    w.add_memory_region(HEAP_BASE, b"\xAA" * HEAP_SIZE)
    for entries in capture_maps:
        w.add_vas_map(entries)
    for entries in segment_maps:
        payload = _build_vas_map_payload(entries)
        w.add_extension_segment("memdiver/test",
                                [ExtensionBlock(BlockType.VAS_MAP, payload)])
    w.add_end_of_capture()
    w.write()
    return path
