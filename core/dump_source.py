"""DumpSource implementations and auto-detect factory."""

import logging
from pathlib import Path
from typing import Any, Dict, Iterator, List, Literal, Tuple

from .dump_io import DumpReader

logger = logging.getLogger("memdiver.core.dump_source")

ViewMode = Literal["raw", "vas"]


def _find_all_in_bytes(data: bytes, needle: bytes) -> List[int]:
    offsets, start = [], 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


class RawDumpSource:
    """DumpSource for raw binary .dump files."""

    def __init__(self, path: Path):
        self._path = path
        self._reader = DumpReader(path)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def format_name(self) -> str:
        return "raw"

    @property
    def size(self) -> int:
        return self._reader.size

    def size_for(self, view: ViewMode = "raw") -> int:
        return self._reader.size

    def open(self) -> None:
        self._reader.open()

    def close(self) -> None:
        self._reader.close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def _ensure_open(self) -> None:
        if self._reader._mmap is None:
            self._reader.open()

    def read_all(self, view: ViewMode = "raw") -> bytes:
        self._ensure_open()
        return self._reader.read_all()

    def read_range(self, offset: int, length: int, view: ViewMode = "raw") -> bytes:
        self._ensure_open()
        return self._reader.read_range(offset, length)

    def find_all(self, needle: bytes, view: ViewMode = "raw") -> List[int]:
        self._ensure_open()
        return self._reader.find_all(needle)

    def iter_ranges(self) -> Iterator[Tuple[int, int, bytes]]:
        data = self.read_all()
        if data:
            yield (0, len(data), data)

    def metadata(self) -> Dict[str, Any]:
        return {"format": "raw", "path": str(self._path)}


class MslDumpSource:
    """DumpSource for Memory Slice (.msl) files.

    Exposes two byte views of the same file: ``view="raw"`` reads the
    .msl container bytes directly (file/block headers, payloads, hash
    chain), and ``view="vas"`` reads a flattened projection of captured
    memory regions ordered by base address. Scanners default to VAS;
    UI endpoints pass ``view="raw"`` to inspect the container.
    """

    def __init__(self, path: Path):
        self._path = path
        self._reader = None
        self._size: int = -1
        # close() is a no-op when True; reader lifetime is owned by the
        # caller (see borrow_reader).
        self._borrowed: bool = False
        self._raw_reader: "DumpReader | None" = None

    @classmethod
    def borrow_reader(cls, path: Path, reader) -> "MslDumpSource":
        """Construct an MslDumpSource around an already-open MslReader.

        The resulting source borrows the reader; close() is a no-op and the
        reader's lifecycle stays with the caller. Used by the reader cache
        service to hand out DumpSource handles backed by pooled readers
        without double-opening the file.
        """
        source = cls(Path(path))
        source._reader = reader
        source._size = -1
        source._borrowed = True
        return source

    @property
    def path(self) -> Path:
        return self._path

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def format_name(self) -> str:
        return "msl"

    @property
    def size(self) -> int:
        # VAS size preserved as the default for scanner back-compat;
        # UI callers use size_for("raw") for the container size.
        return self.size_for("vas")

    def size_for(self, view: ViewMode = "vas") -> int:
        if view == "raw":
            try:
                return self._path.stat().st_size
            except OSError:
                return 0
        if self._reader is None:
            return 0
        if self._size < 0:
            self._size = sum(
                r.region_size for r in self._reader.collect_regions()
            )
        return self._size

    def _ensure_raw_reader(self) -> DumpReader:
        """Lazily open a DumpReader over the raw .msl container bytes."""
        if self._raw_reader is None:
            self._raw_reader = DumpReader(self._path)
        if self._raw_reader._mmap is None:
            self._raw_reader.open()
        return self._raw_reader

    @staticmethod
    def _require_vas(view: ViewMode) -> None:
        """Defensive guard for the else-branch of view dispatch.

        The public API is typed `ViewMode = Literal["raw", "vas"]`, but
        dynamic callers can still pass a bad value at runtime. Rather
        than silently executing the VAS branch for `view="garbage"`,
        surface the error.
        """
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")

    def open(self) -> None:
        from msl.reader import MslReader
        self._reader = MslReader(self._path)
        self._reader.open()
        self._size = -1

    def close(self) -> None:
        if self._raw_reader is not None:
            self._raw_reader.close()
            self._raw_reader = None
        if self._borrowed:
            # Reader ownership stays with the external holder; just detach.
            self._reader = None
            self._size = -1
            return
        if self._reader:
            self._reader.close()
            self._reader = None
        self._size = -1

    def get_reader(self):
        """Return the underlying MslReader (must be opened first)."""
        if self._reader is None:
            raise RuntimeError("MslDumpSource not opened; use context manager")
        return self._reader

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def read_all(self, view: ViewMode = "vas") -> bytes:
        if view == "raw":
            return self._ensure_raw_reader().read_all()
        self._require_vas(view)
        return b"".join(chunk for _, _, chunk in self.iter_ranges())

    def read_range(self, offset: int, length: int, view: ViewMode = "vas") -> bytes:
        if view == "raw":
            return self._ensure_raw_reader().read_range(offset, length)
        self._require_vas(view)
        result, flat_pos = bytearray(), 0
        for _va, rng_len, chunk in self.iter_ranges():
            rng_end = flat_pos + rng_len
            if rng_end <= offset:
                flat_pos = rng_end
                continue
            if flat_pos >= offset + length:
                break
            s, e = max(0, offset - flat_pos), min(rng_len, offset + length - flat_pos)
            result.extend(chunk[s:e])
            flat_pos = rng_end
        return bytes(result)

    def find_all(self, needle: bytes, view: ViewMode = "vas") -> List[int]:
        if view == "raw":
            return self._ensure_raw_reader().find_all(needle)
        self._require_vas(view)
        if self._reader is None:
            return []
        offsets = []
        flat_offset = 0
        for _vaddr, _length, chunk in self.iter_ranges():
            for idx in _find_all_in_bytes(chunk, needle):
                offsets.append(flat_offset + idx)
            flat_offset += len(chunk)
        return offsets

    def va_to_vas_offset(self, va: int) -> "int | None":
        """Translate a virtual address to a flat VAS offset.

        Returns the offset into the ``view="vas"`` byte stream where the
        captured bytes for ``va`` live, or ``None`` if ``va`` falls
        outside any captured page.
        """
        if self._reader is None:
            return None
        flat_pos = 0
        for vaddr, length, _chunk in self.iter_ranges():
            if vaddr <= va < vaddr + length:
                return flat_pos + (va - vaddr)
            flat_pos += length
        return None

    def va_to_file_offset(self, va: int) -> "int | None":
        """Translate a virtual address to a file offset in the .msl container.

        Returns the file offset of the MEMORY_REGION or MODULE_ENTRY
        block header whose address range contains ``va``. Landing on
        the block header (rather than the middle of a payload) gives
        a useful forensic anchor in raw view.
        """
        if self._reader is None:
            return None
        for region in self._reader.collect_regions():
            if region.base_addr <= va < region.base_addr + region.region_size:
                return region.block_header.file_offset
        for mod in self._reader.collect_modules():
            if mod.base_addr <= va < mod.base_addr + mod.module_size:
                return mod.block_header.file_offset
        return None

    def iter_ranges(self) -> Iterator[Tuple[int, int, bytes]]:
        if self._reader is None:
            return
        from msl.page_map import iter_captured_ranges
        regions = self._reader.collect_regions()
        regions.sort(key=lambda r: r.base_addr)
        for region in regions:
            page_data = self._get_region_page_data(region)
            for vaddr, length, chunk in iter_captured_ranges(
                region.page_states, page_data,
                region.base_addr, region.page_size,
            ):
                yield (vaddr, length, bytes(chunk))

    def metadata(self) -> Dict[str, Any]:
        if self._reader is None:
            return {
                "format": "msl",
                "path": str(self._path),
                "raw_size": self.size_for("raw"),
            }
        hdr = self._reader.file_header
        return {
            "format": "msl",
            "path": str(self._path),
            "dump_uuid": str(hdr.dump_uuid),
            "pid": hdr.pid,
            "os_type": hdr.os_type,
            "arch_type": hdr.arch_type,
            "version": f"{hdr.version_major}.{hdr.version_minor}",
            "raw_size": self.size_for("raw"),
            "vas_size": self.size_for("vas"),
        }

    def _get_region_page_data(self, region) -> bytes:
        from .msl_helpers import get_region_page_data
        return get_region_page_data(self._reader, region)

def open_dump(path: Path) -> "RawDumpSource | MslDumpSource | GdbRawDumpSource | LldbRawDumpSource | GCoreDumpSource":  # noqa: F821
    """Auto-detect dump format and return appropriate DumpSource.

    Dispatch order:
      1. MSL container (magic bytes).
      2. ELF core dump (``\\x7fELF`` with ``e_type == ET_CORE``) — handled
         by :class:`core.dump_sources.gcore.GCoreDumpSource`. Checked
         before filename-based regioned-raw detection so an unusually
         named ELF core still takes the correct branch.
      3. Regioned raw flavours by filename suffix (``.gdb_raw.bin`` /
         ``.lldb_raw.bin``), optionally resolved from a ``.maps`` path.
      4. Fallback: opaque :class:`RawDumpSource`.
    """
    from msl.enums import FILE_MAGIC
    path = Path(path)
    name = path.name

    # Convenience: user pointed at the .maps sidecar — redirect to its .bin.
    if name.endswith("gdb_raw.maps") or name.endswith("lldb_raw.maps"):
        bin_candidate = path.with_suffix(".bin")
        if bin_candidate.exists():
            path = bin_candidate
            name = path.name

    try:
        with open(path, "rb") as f:
            magic = f.read(18)
    except OSError:
        magic = b""

    if magic[:8] == FILE_MAGIC:
        return MslDumpSource(path)

    # ELF core dump: \x7fELF magic + e_type == ET_CORE (4) at offset 16.
    if magic[:4] == b"\x7fELF" and len(magic) >= 18:
        e_type = int.from_bytes(magic[16:18], "little")
        if e_type == 4:  # ET_CORE
            from core.dump_sources.gcore import GCoreDumpSource
            return GCoreDumpSource(path)

    if name.endswith("gdb_raw.bin") and not name.endswith("lldb_raw.bin"):
        from core.dump_sources.gdb_raw import GdbRawDumpSource
        return GdbRawDumpSource(path)
    if name.endswith("lldb_raw.bin"):
        from core.dump_sources.lldb_raw import LldbRawDumpSource
        return LldbRawDumpSource(path)

    return RawDumpSource(path)
