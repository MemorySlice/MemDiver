"""Extract one process of a full memory image into an ``.msl`` (plan T1.7, MSL half).

The input is an OPEN process-view :class:`~memdiver.core.image.sources.Vol3LayerSource`.
One MEMORY_REGION is written per VMA with a real per-page state map taken from the
view's run table (CAPTURED / FAILED / NOT_RESIDENT); only captured pages are ever read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from memdiver.msl.enums import (
    ArchType, OSType, PageState, Protection, RegionType, SourceFormat, VasNameSource,
)
from memdiver.msl.importer import _looks_like_image
from memdiver.msl.types import MslVasEntry, PhysicalRange
from memdiver.msl.writer import ModuleEntrySpec, MslWriter

PAGE_SIZE_LOG2 = 12
PAGE_SIZE = 1 << PAGE_SIZE_LOG2
#: Same bound as the importers' dense page-map cap (~64 GiB at 4 KiB).
MAX_VMA_PAGES = 1 << 24

_STATE_FOR_RUN = {"captured": PageState.CAPTURED, "failed": PageState.FAILED,
                  "not_resident": PageState.NOT_RESIDENT}


@dataclass(frozen=True)
class ExtractResult:
    output_path: Path
    pid: int
    regions_written: int
    captured_bytes: int
    state_bytes: Dict[str, int]
    physical_ranges: int
    modules_written: int = 0
    skipped_vmas: int = 0


def extract_process_to_msl(
    source: Any,
    output_path: Path,
    *,
    note_fields: Dict[str, str],
    physical_ranges: Optional[Sequence[PhysicalRange]] = None,
) -> ExtractResult:
    """Write the process behind *source* (an open process view) to *output_path*."""
    output_path = Path(output_path)
    layer = source.metadata().get("layer", {})
    pid = int(layer.get("pid", source.descriptor.pid or 0))
    vmas = sorted(source.vmas(), key=lambda v: v.start)
    runs = source.layer_runs()

    writer = MslWriter(output_path, pid=pid, os_type=OSType.LINUX,
                       arch_type=ArchType.X86_64, imported=True)
    modules = _module_specs(vmas)
    if modules:
        writer.add_module_list_index(modules)

    totals = {name: 0 for name in _STATE_FOR_RUN}
    vas_entries: List[MslVasEntry] = []
    written = skipped = 0
    for vma in vmas:
        region_type = _region_type(vma)
        protection = _protection(vma.protection)
        vas_entries.append(MslVasEntry(
            vma.start, _page_aligned_size(vma), protection, region_type, vma.name,
            int(VasNameSource.SOURCE_METADATA)))
        pages = _page_count(vma)
        if pages > MAX_VMA_PAGES:
            skipped += 1
            continue
        states = _page_states(vma, runs, pages)
        _tally(totals, states)
        writer.add_memory_region_source(
            vma.start, pages * PAGE_SIZE, _captured_reader(source, vma, states),
            protection=protection, region_type=region_type,
            page_size_log2=PAGE_SIZE_LOG2, page_states=states)
        written += 1

    writer.add_vas_map(vas_entries)
    if physical_ranges:
        writer.add_physical_memory_map(physical_ranges)
    writer.add_import_provenance(
        source_format=SourceFormat.OTHER, tool_name="memdiver",
        orig_file_size=source.size_for("raw"),
        note=_note(note_fields, layer, pid))
    writer.add_end_of_capture()
    writer.write_streaming()  # read_chunk runs here: the source must stay open
    return ExtractResult(
        output_path=output_path, pid=pid, regions_written=written,
        captured_bytes=totals["captured"], state_bytes=totals,
        physical_ranges=len(physical_ranges or ()), modules_written=len(modules),
        skipped_vmas=skipped)


# -- classification ---------------------------------------------------------------

def _region_type(vma: Any) -> int:
    if vma.is_heap:
        return int(RegionType.HEAP)
    if vma.name.startswith("[stack"):
        return int(RegionType.STACK)
    if vma.file_backed:
        return int(RegionType.IMAGE if _looks_like_image(vma.name)
                   else RegionType.MAPPED_FILE)
    return int(RegionType.ANONYMOUS)


def _protection(rwx: str) -> int:
    bits = 0
    for flag, bit in (("r", Protection.READ), ("w", Protection.WRITE),
                      ("x", Protection.EXECUTE)):
        if flag in rwx:
            bits |= int(bit)
    return bits


def _module_specs(vmas: Sequence[Any]) -> List[ModuleEntrySpec]:
    """One module per distinct file-backed path: the span of all its VMAs."""
    spans: Dict[str, Tuple[int, int]] = {}
    for vma in vmas:
        if vma.file_backed and vma.name.startswith("/"):
            lo, hi = spans.get(vma.name, (vma.start, vma.end))
            spans[vma.name] = (min(lo, vma.start), max(hi, vma.end))
    return [ModuleEntrySpec(base_addr=lo, module_size=hi - lo, path=path)
            for path, (lo, hi) in spans.items()]


# -- page states ------------------------------------------------------------------

def _page_count(vma: Any) -> int:
    return (vma.end - vma.start + PAGE_SIZE - 1) // PAGE_SIZE


def _page_aligned_size(vma: Any) -> int:
    return _page_count(vma) * PAGE_SIZE


def _page_states(vma: Any, runs: Sequence[Any], pages: int) -> bytearray:
    """Per-page states; a page is only CAPTURED/NOT_RESIDENT if one run covers it fully.

    Pages no run covers have unknown content: FAILED (never claimed to be zero).
    """
    states = bytearray([int(PageState.FAILED)]) * pages
    lo, hi = vma.start, vma.start + pages * PAGE_SIZE
    for run in runs:
        if run.end <= lo or run.start >= hi:
            continue
        first = max(run.start, lo)
        first_page = (first - lo + PAGE_SIZE - 1) // PAGE_SIZE
        last_page = (min(run.end, hi) - lo) // PAGE_SIZE
        if last_page > first_page:
            code = int(_STATE_FOR_RUN[run.state.value])
            states[first_page:last_page] = bytes([code]) * (last_page - first_page)
    return states


def _tally(totals: Dict[str, int], states: bytearray) -> None:
    for name, state in _STATE_FOR_RUN.items():
        totals[name] += states.count(int(state)) * PAGE_SIZE


def _captured_reader(source: Any, vma: Any, states: bytearray):
    """``read_chunk(offset, length)`` over the region's captured-page byte stream."""
    spans: List[Tuple[int, int, int]] = []  # (stream_offset, va, length)
    stream = 0
    page, count = 0, len(states)
    captured = int(PageState.CAPTURED)
    while page < count:
        if states[page] != captured:
            page += 1
            continue
        end = page
        while end < count and states[end] == captured:
            end += 1
        length = (end - page) * PAGE_SIZE
        spans.append((stream, vma.start + page * PAGE_SIZE, length))
        stream += length
        page = end

    def read_chunk(offset: int, length: int) -> bytes:
        out = bytearray()
        for span_off, va, span_len in spans:
            lo, hi = max(offset, span_off), min(offset + length, span_off + span_len)
            if lo < hi:
                out += source.read_location(va + (lo - span_off), hi - lo).data
        return bytes(out)

    return read_chunk


# -- provenance -------------------------------------------------------------------

def _note(note_fields: Dict[str, str], layer: Dict[str, Any], pid: int) -> str:
    fields = dict(note_fields)
    fields.setdefault("pid", str(pid))
    if "comm" in layer:
        fields.setdefault("comm", str(layer["comm"]))
    if "process_dtb" in layer:
        fields.setdefault("dtb", f"{int(layer['process_dtb']):#x}")
    return "physical-image extraction; " + "; ".join(
        f"{k}={v}" for k, v in fields.items())
