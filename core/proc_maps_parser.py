"""Parser for Linux ``/proc/<pid>/maps`` formatted files.

Used to pair ``gdb_raw.maps``/``lldb_raw.maps`` sidecar files with their
corresponding ``.bin`` raw memory dumps so that a flat file offset can be
projected back onto the original virtual-address space.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List

from msl.enums import RegionType


@dataclass(frozen=True)
class MapRegion:
    """A single ``/proc/<pid>/maps`` entry paired with a classification."""

    start: int
    end: int
    perm: str
    file_offset: int
    dev: str
    inode: int
    path: str
    is_anon: bool
    region_type: int  # msl.enums.RegionType value

    @property
    def size(self) -> int:
        return self.end - self.start


# -- Classification ----------------------------------------------------------

_PSEUDO_OTHER = {"[vdso]", "[vvar]", "[vsyscall]"}


def _is_image_path(path: str) -> bool:
    """Shared-library style paths -> RegionType.IMAGE."""
    if path.endswith(".so"):
        return True
    # ".so.<digits>" suffix (e.g. libc.so.6, libssl.so.1.1)
    tail = path.rsplit(".so", 1)
    if len(tail) == 2 and tail[1].startswith(".") and tail[1][1:].split(".")[0].isdigit():
        return True
    if "/lib/" in path or "/usr/" in path:
        return True
    return False


def classify_region(path: str) -> int:
    """Return the ``RegionType`` int for a given map-entry path."""
    if path == "":
        return int(RegionType.ANONYMOUS)
    if path.startswith("[heap"):  # [heap], [heap:N]
        return int(RegionType.HEAP)
    if path.startswith("[stack"):  # [stack], [stack:tid]
        return int(RegionType.STACK)
    if path in _PSEUDO_OTHER:
        return int(RegionType.OTHER)
    if path.startswith("[anon_shmem"):
        return int(RegionType.SHARED_MEM)
    if path.startswith("["):
        return int(RegionType.OTHER)
    if _is_image_path(path):
        return int(RegionType.IMAGE)
    if path.startswith("/"):
        return int(RegionType.MAPPED_FILE)
    return int(RegionType.UNKNOWN)


# -- Parsing ----------------------------------------------------------------

def _parse_line(line: str) -> "MapRegion | None":
    """Parse one ``/proc/<pid>/maps`` line; return None for blank lines."""
    stripped = line.rstrip("\n").rstrip("\r")
    if not stripped.strip():
        return None
    # Split on whitespace but keep the path intact (path may contain spaces).
    parts = stripped.split(None, 5)
    if len(parts) < 5:
        return None
    addr_range, perm, offset_tok, dev, inode_tok = parts[:5]
    path = parts[5].strip() if len(parts) == 6 else ""
    start_tok, end_tok = addr_range.split("-", 1)
    start = int(start_tok, 16)
    end = int(end_tok, 16)
    file_offset = int(offset_tok, 16)
    inode = int(inode_tok)
    is_anon = path == "" or path.startswith("[")
    region_type = classify_region(path)
    return MapRegion(
        start=start, end=end, perm=perm, file_offset=file_offset,
        dev=dev, inode=inode, path=path, is_anon=is_anon,
        region_type=region_type,
    )


def parse_maps_text(text: str) -> List[MapRegion]:
    """Parse a ``/proc/<pid>/maps`` style blob into ``MapRegion`` entries."""
    regions: List[MapRegion] = []
    for line in text.splitlines():
        entry = _parse_line(line)
        if entry is not None:
            regions.append(entry)
    return regions


def parse_maps_file(maps_path: Path) -> List[MapRegion]:
    """Read and parse a ``.maps`` sidecar file."""
    text = Path(maps_path).read_text(encoding="utf-8", errors="replace")
    return parse_maps_text(text)
