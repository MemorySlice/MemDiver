"""Private base class for regioned raw-dump sources (gdb_raw, lldb_raw).

Both flavours share the same layout: a flat ``.bin`` file that is the
byte-wise concatenation of every captured ``/proc/<pid>/maps`` region,
plus a sidecar ``.maps`` describing each region's virtual address range,
permissions and backing path.

This module implements the shared DumpSource surface once so that the
concrete subclasses in :mod:`core.dump_sources.gdb_raw` and
:mod:`core.dump_sources.lldb_raw` only need to declare ``format_name``.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from memdiver.core.dump_io import DumpReader
from memdiver.core.proc_maps_parser import MapRegion, parse_maps_file

logger = logging.getLogger("memdiver.core.dump_sources.regioned")


class _RegionedRawSource:
    """Base for raw ``.bin`` dumps paired with a ``/proc/<pid>/maps`` sidecar.

    The public surface mirrors :class:`core.dump_source.RawDumpSource` and
    :class:`core.dump_source.MslDumpSource` so scanners and UI code can
    treat all dump flavours uniformly.
    """

    # Subclasses override.
    format_name: str = "regioned_raw"

    #: The ``.maps`` sidecar is a real virtual-address map, so cross-dump
    #: consensus can align these captures by VA
    #: (:mod:`memdiver.engine.consensus_va`) instead of falling back to flat
    #: file offsets. Same declaration as :class:`GCoreDumpSource`; both expose
    #: ``iter_ranges`` -> ``(start_va, end_va, file_offset)``, which is the
    #: whole contract the VA path needs.
    supports_va_alignment: bool = True

    def __init__(self, bin_path: Path, maps_path: "Path | None" = None):
        self._bin_path = Path(bin_path)
        self._maps_path = Path(maps_path) if maps_path is not None else None
        self._reader = DumpReader(self._bin_path)
        self._regions: List[MapRegion] = []
        # Cumulative bin-file offsets per region, clamped to the bin size.
        # _cum_offsets[i] is the bin offset where region i starts.
        # _cum_offsets[len(regions)] is the end offset of the last usable region.
        self._cum_offsets: List[int] = []
        # Number of regions actually reachable within the .bin (<= len(_regions)).
        self._usable_region_count: int = 0

    # -- Path / metadata properties -----------------------------------------

    @property
    def path(self) -> Path:
        return self._bin_path

    @property
    def name(self) -> str:
        return self._bin_path.name

    @property
    def size(self) -> int:
        """Raw file size in bytes (matches mmap'd bin size).

        ``DumpReader.size`` returns the mapped length when open and 0 when
        unmapped, so a falsy result deliberately falls back to a ``stat()``
        of the bin path — covering the not-yet-opened case without poking
        the reader's private mmap handle.
        """
        return self._reader.size or self._raw_file_size()

    def _raw_file_size(self) -> int:
        try:
            return self._bin_path.stat().st_size
        except OSError:
            return 0

    # -- Lifecycle ----------------------------------------------------------

    def open(self) -> None:
        """Open the .bin (mmap) and parse the .maps sidecar."""
        self._reader.open()
        if not self._regions:
            self._regions = parse_maps_file(self._resolve_maps_path())
        self._rebuild_offset_table()

    def close(self) -> None:
        self._reader.close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def _ensure_open(self) -> None:
        if self._reader._mmap is None:
            self.open()

    # -- Region resolution --------------------------------------------------

    def _resolve_maps_path(self) -> Path:
        """Pick the sidecar ``.maps`` path, with a graceful fallback."""
        if self._maps_path is not None and self._maps_path.exists():
            return self._maps_path
        # Primary: ``foo.<flavour>_raw.bin`` -> ``foo.<flavour>_raw.maps``
        primary = self._bin_path.with_suffix(".maps")  # .bin -> .maps
        if primary.exists():
            return primary
        # Legacy fallback: drop both suffixes -> ``foo.maps``
        fallback = self._bin_path.with_suffix("").with_suffix(".maps")
        if fallback.exists():
            return fallback
        raise FileNotFoundError(
            f"No .maps sidecar for {self._bin_path} (looked for "
            f"{primary} and {fallback})"
        )

    def _rebuild_offset_table(self) -> None:
        """Compute cumulative bin offsets for each region; clamp to bin size."""
        bin_size = self._raw_file_size()
        cum: List[int] = [0]
        usable = 0
        running = 0
        for region in self._regions:
            if running >= bin_size:
                break
            region_size = region.end - region.start
            # If this region would overflow the bin, clamp — the raw writer may
            # have truncated here. Still counts as "usable" because the partial
            # bytes are legitimately present.
            if running + region_size > bin_size:
                region_size = bin_size - running
            running += region_size
            cum.append(running)
            usable += 1
        self._cum_offsets = cum
        self._usable_region_count = usable
        padding = bin_size - running
        if padding and self.format_name == "lldb_raw":
            logger.info(
                "lldb_raw: %d padding bytes beyond last captured region in %s",
                padding, self._bin_path.name,
            )

    # -- Size queries -------------------------------------------------------

    def size_for(self, view: str = "vas") -> int:
        if view == "raw":
            return self._raw_file_size()
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        if not self._cum_offsets:
            return 0
        return self._cum_offsets[self._usable_region_count]

    # -- Iteration ----------------------------------------------------------

    def iter_ranges(self, view: str = "vas") -> Iterator[Tuple[int, int, int]]:
        """Yield ``(start_va, end_va, file_offset)`` per captured region.

        Note: the yielded tuples are always VA-based; this iterator is
        VA-only. ``view`` is accepted (and validated) only for signature
        parity with the other DumpSource methods (``read_range``,
        ``find_all``, ``size_for``) — ``"raw"`` produces the same VA tuples
        as ``"vas"``. Callers wanting raw-file ranges already have the
        ``file_offset`` element of each tuple.
        """
        if view not in ("vas", "raw"):
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        for idx in range(self._usable_region_count):
            region = self._regions[idx]
            bin_offset = self._cum_offsets[idx]
            next_offset = self._cum_offsets[idx + 1]
            served = next_offset - bin_offset
            yield (region.start, region.start + served, bin_offset)

    # -- Reading ------------------------------------------------------------

    def read_range(self, offset: int, length: int, view: str = "raw") -> bytes:
        """Read ``length`` bytes starting at ``offset`` in the chosen view."""
        self._ensure_open()
        if view == "raw":
            return self._reader.read_range(offset, length)
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        return self._read_vas_range(offset, length)

    def _read_vas_range(self, vas_offset: int, length: int) -> bytes:
        """Map a flat VAS offset through the region table into the bin."""
        if length <= 0:
            return b""
        result = bytearray()
        remaining = length
        pos = vas_offset
        for idx in range(self._usable_region_count):
            region_start = self._cum_offsets[idx]
            region_end = self._cum_offsets[idx + 1]
            region_size = region_end - region_start
            if pos >= region_size:
                pos -= region_size
                continue
            take = min(region_size - pos, remaining)
            bin_off = region_start + pos
            result.extend(self._reader.read_range(bin_off, take))
            remaining -= take
            pos = 0
            if remaining <= 0:
                break
        return bytes(result)

    def find_all(self, needle: bytes, view: str = "raw") -> List[int]:
        # An empty needle would make the underlying byte/mmap search yield one
        # hit per byte (effective hang). gcore guards this the same way.
        if not needle:
            return []
        self._ensure_open()
        if view == "raw":
            return self._reader.find_all(needle)
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        return self._find_all_vas(needle)

    def _find_all_vas(self, needle: bytes) -> List[int]:
        """Find occurrences expressed as flat VAS offsets.

        VAS is simply the concatenation of all captured regions, which is
        exactly what the bin already stores. So find_all over the bin is
        find_all over VAS; we just cap it to the usable prefix.
        """
        raw_hits = self._reader.find_all(needle)
        usable_end = self._cum_offsets[self._usable_region_count] if self._cum_offsets else 0
        return [h for h in raw_hits if h < usable_end]

    def find_first(self, needle: bytes, view: str = "raw") -> Optional[int]:
        """First offset of ``needle`` in *view*, or ``None`` (presence query).

        Agrees with ``find_all(needle, view)[0]`` while early-exiting on the
        first hit. An empty needle yields ``None``, matching ``find_all``'s
        empty-list guard for the same reason (it would otherwise match at
        every byte).
        """
        if not needle:
            return None
        self._ensure_open()
        if view == "raw":
            return self._reader.find_first(needle)
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        return self._find_first_vas(needle)

    def _find_first_vas(self, needle: bytes) -> Optional[int]:
        """First occurrence expressed as a flat VAS offset.

        The bin already stores VAS as the concatenation of captured regions
        (see :meth:`_find_all_vas`), so the first bin hit is the first VAS hit
        provided it lands inside the usable prefix. Bin hits are ascending, so
        a first hit at or beyond ``usable_end`` means there is no VAS hit at
        all - it can only sit in the trailing padding.
        """
        hit = self._reader.find_first(needle)
        if hit is None:
            return None
        usable_end = self._cum_offsets[self._usable_region_count] if self._cum_offsets else 0
        return hit if hit < usable_end else None

    # -- VA translation -----------------------------------------------------

    def va_to_file_offset(self, va: int) -> "int | None":
        """Translate a virtual address to a bin-file offset."""
        for idx in range(self._usable_region_count):
            region = self._regions[idx]
            region_bin_start = self._cum_offsets[idx]
            region_bin_end = self._cum_offsets[idx + 1]
            served = region_bin_end - region_bin_start
            if region.start <= va < region.start + served:
                return region_bin_start + (va - region.start)
        return None

    def va_to_vas_offset(self, va: int) -> "int | None":
        """Translate a virtual address to a flat VAS offset.

        Since VAS and raw bin layouts coincide here, this is the same
        value as :meth:`va_to_file_offset`.
        """
        return self.va_to_file_offset(va)

    # -- Metadata -----------------------------------------------------------

    def metadata(self) -> Dict[str, Any]:
        raw_size = self._raw_file_size()
        vas_size = self.size_for("vas") if self._cum_offsets else 0
        return {
            "format": self.format_name,
            "path": str(self._bin_path),
            "region_count": len(self._regions),
            "captured_regions": self._usable_region_count,
            "vas_size": vas_size,
            "raw_size": raw_size,
            "padding_bytes": raw_size - vas_size,
        }
