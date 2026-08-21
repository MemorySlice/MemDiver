"""Raw-to-MSL import: convert .dump files to .msl format."""

import functools
import logging
import struct
from dataclasses import dataclass
from math import ceil
from pathlib import Path
from typing import List, Optional

from memdiver.core.binary_formats.elf_core_reader import (ElfCoreReader, NtFileEntry,
                                                 PtLoadSegment, PF_R, PF_W, PF_X)
from memdiver.core.binary_formats.minidump_reader import (
    MinidumpReader,
    MEM_COMMIT, MEM_RESERVE, MEM_FREE,
    MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PROCESSOR_ARCHITECTURE_INTEL, PROCESSOR_ARCHITECTURE_ARM,
    PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64,
)
from memdiver.core.format_detect import detect_format
from memdiver.core.models import CryptoSecret
from .enums import (ArchType, MslKeyType, MslProtocol, OSType, PageState,
                    Protection, RegionType, SourceFormat)
from .writer import ModuleEntrySpec, MslWriter

logger = logging.getLogger("memdiver.msl.importer")

# Default page size when the ELF core exposes no better hint (spec §5.1
# requires page_size_log2 ∈ [10, 40]; 4096 == 2**12 is the Linux norm).
_DEFAULT_PAGE_SIZE_LOG2 = 12
_MIN_PAGE_SIZE_LOG2 = 10
_MAX_PAGE_SIZE_LOG2 = 40


def _reject_malformed_dump(fn):
    """Translate low-level pack/parse faults on the untrusted-import path into
    a clean ``ValueError`` (the parser contract).

    The importer serializes attacker-controlled dump fields (region sizes,
    base/vaddrs, module base/size, page counts) with ``struct.pack``. A
    corrupted field can drive a value out of its packed range — e.g. a negative
    ``module_size`` from an ``end < start`` NT_FILE entry raises
    ``struct.error`` — or a bogus length can raise ``IndexError`` /
    ``OverflowError``. Those are honest "malformed input" rejections, so they
    must surface as ``ValueError`` rather than leak a raw library error.

    Only those three low-level types are caught, so ``ValueError`` (incl.
    ``MslParseError`` and the ``_check_region_pages`` OOM cap),
    ``NotImplementedError`` and ``CapabilityError`` pass through unchanged —
    no double-wrapping and no swallowing of deliberate rejections.
    """
    @functools.wraps(fn)
    def _wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (struct.error, IndexError, OverflowError) as exc:
            raise ValueError(f"malformed dump: {exc}") from exc
    return _wrapper


@dataclass
class ImportResult:
    """Result of importing a single raw dump to MSL format."""

    source_path: Path
    output_path: Path
    regions_written: int
    key_hints_written: int
    total_bytes: int


_SECRET_TO_KEY_TYPE = {
    "CLIENT_RANDOM": MslKeyType.PRE_MASTER_SECRET,
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET": MslKeyType.HANDSHAKE_SECRET,
    "SERVER_HANDSHAKE_TRAFFIC_SECRET": MslKeyType.HANDSHAKE_SECRET,
    "CLIENT_TRAFFIC_SECRET_0": MslKeyType.APP_TRAFFIC_SECRET,
    "SERVER_TRAFFIC_SECRET_0": MslKeyType.APP_TRAFFIC_SECRET,
    "EXPORTER_SECRET": MslKeyType.SESSION_KEY,
    "SSH2_SESSION_KEY": MslKeyType.SSH_SESSION_KEY,
}

_SECRET_TO_PROTOCOL = {
    "CLIENT_RANDOM": MslProtocol.TLS_12,
    "SSH2_SESSION_KEY": MslProtocol.SSH,
}


def _map_key_type(secret_type: str) -> int:
    return _SECRET_TO_KEY_TYPE.get(secret_type, MslKeyType.UNKNOWN)


def _map_protocol(secret_type: str) -> int:
    return _SECRET_TO_PROTOCOL.get(secret_type, MslProtocol.TLS_13)


# ELF-core import helpers -----------------------------------------------------


def _is_pow2_in_range(page_size: int) -> bool:
    """True if *page_size* is a power of two whose log2 is spec-legal."""
    if page_size <= 0 or (page_size & (page_size - 1)) != 0:
        return False
    log2 = page_size.bit_length() - 1
    return _MIN_PAGE_SIZE_LOG2 <= log2 <= _MAX_PAGE_SIZE_LOG2


def _page_size_log2_for_segment(seg: PtLoadSegment, info,
                                override: Optional[int]) -> int:
    """Pick a page_size_log2 for one PT_LOAD segment (spec §5.1 range).

    Precedence: explicit caller override, then an NT_FILE page_size or a
    segment p_align if the reader happens to expose one (current reader
    exposes neither), then the 4096-byte default. Any candidate outside
    the legal [10, 40] range is discarded with a warning and falls back
    to the default.
    """
    if override is not None:
        if _MIN_PAGE_SIZE_LOG2 <= override <= _MAX_PAGE_SIZE_LOG2:
            return override
        logger.warning("page_size_log2 override %d out of spec range "
                       "[10, 40]; using %d", override, _DEFAULT_PAGE_SIZE_LOG2)
        return _DEFAULT_PAGE_SIZE_LOG2

    for candidate in (getattr(info, "page_size", None),
                      getattr(seg, "p_align", None)):
        if candidate and _is_pow2_in_range(candidate):
            return candidate.bit_length() - 1

    return _DEFAULT_PAGE_SIZE_LOG2


def _protection_from_flags(flags: int) -> int:
    """Map ELF PF_R/PF_W/PF_X program-header bits to MSL Protection bits."""
    prot = 0
    if flags & PF_R:
        prot |= Protection.READ
    if flags & PF_W:
        prot |= Protection.WRITE
    if flags & PF_X:
        prot |= Protection.EXECUTE
    return int(prot)


def _looks_like_image(path: str) -> bool:
    """Heuristic: does an NT_FILE path name an ELF image / shared object?"""
    lowered = path.lower()
    return lowered.endswith(".so") or ".so." in lowered or "/lib" in lowered


def _region_type_for_segment(seg: PtLoadSegment,
                             mappings: List[NtFileEntry]) -> int:
    """Classify a segment as ANONYMOUS, MAPPED_FILE, or IMAGE (best-effort).

    A segment is file-backed when its [vaddr, vaddr+memsz) range overlaps
    an NT_FILE mapping; if that mapping's path looks like an ELF/.so, the
    region is tagged IMAGE, otherwise MAPPED_FILE.
    """
    seg_start = seg.vaddr
    seg_end = seg.vaddr + seg.memsz
    for m in mappings:
        if m.start < seg_end and seg_start < m.end:
            if m.path and _looks_like_image(m.path):
                return int(RegionType.IMAGE)
            return int(RegionType.MAPPED_FILE)
    return int(RegionType.ANONYMOUS)


def _read_segment_data(reader: ElfCoreReader, seg: PtLoadSegment) -> bytes:
    """Return a PT_LOAD segment's stored bytes, exactly as present on disk.

    Reads up to ``min(filesz, memsz)`` bytes at the segment's file offset. No
    zero-padding: a short return (fewer bytes than ``filesz``) signals a
    truncated/damaged core, and the caller marks the missing tail FAILED
    rather than fabricating captured zero-fill.
    """
    filesz = min(seg.filesz, seg.memsz)
    if filesz == 0:
        return b""
    return bytes(reader.read_at(seg.file_offset, filesz))


def _add_segment_region(writer: MslWriter, reader: ElfCoreReader,
                        seg: PtLoadSegment, info,
                        page_size_log2: Optional[int]):
    """Emit one MSL memory region for a PT_LOAD segment.

    Returns (region_uuid, data) where *data* is the assembled captured
    bytes (for key-hint scanning). Implements the three-state page map:
    pages backed by stored bytes are CAPTURED; the [filesz, memsz) tail
    (e.g. .bss) is FAILED — mapped but not stored. On a *truncated* core
    (fewer stored bytes than ``filesz``), the pages past the last fully-read
    page are also FAILED rather than fabricated as captured zero-fill.
    """
    log2 = _page_size_log2_for_segment(seg, info, page_size_log2)
    page_size = 1 << log2

    filesz = min(seg.filesz, seg.memsz)  # defensive: never store past memsz
    total_pages = ceil(seg.memsz / page_size) if seg.memsz else 0
    _check_region_pages(total_pages, seg.vaddr, "PT_LOAD")

    raw = _read_segment_data(reader, seg)
    actual = len(raw)
    if actual < filesz:
        # Truncated/damaged core: trust only whole pages we fully read.
        captured_pages = actual // page_size
        logger.warning(
            "Truncated PT_LOAD at %#x: read %d/%d stored bytes; marking "
            "%d tail page(s) FAILED", seg.vaddr, actual, filesz,
            max(total_pages - captured_pages, 0),
        )
    else:
        # Normal: all stored bytes present; the last page is zero-padded to
        # the boundary (still part of the mapped segment) and stays CAPTURED.
        captured_pages = ceil(filesz / page_size) if filesz else 0
    captured_pages = min(captured_pages, total_pages)
    failed_pages = max(total_pages - captured_pages, 0)

    data = bytearray(raw[:captured_pages * page_size])
    if len(data) < captured_pages * page_size:  # pad only fully-CAPTURED pages
        data.extend(b"\x00" * (captured_pages * page_size - len(data)))
    data = bytes(data)

    page_states = ([PageState.CAPTURED] * captured_pages
                   + [PageState.FAILED] * failed_pages)

    prot = _protection_from_flags(seg.flags)
    rtype = _region_type_for_segment(seg, info.file_mappings)

    region_uuid = writer.add_memory_region(
        seg.vaddr, data, protection=prot, region_type=rtype,
        page_size_log2=log2, page_states=page_states,
    )
    return region_uuid, data


def _add_module_index(writer: MslWriter, mappings: List[NtFileEntry]) -> None:
    """Group NT_FILE mappings by path into a Module List Index (best-effort).

    Each module's base is the lowest mapping start for that path and its
    size spans to the highest mapping end. Any failure is logged and
    swallowed so a missing/garbled NT_FILE note never aborts the import.
    """
    if not mappings:
        return
    try:
        by_path = {}
        for m in mappings:
            if not m.path:
                continue
            lo, hi = by_path.get(m.path, (m.start, m.end))
            by_path[m.path] = (min(lo, m.start), max(hi, m.end))
        _U64_MAX = (1 << 64) - 1
        modules = [
            ModuleEntrySpec(base_addr=lo, module_size=hi - lo, path=path)
            for path, (lo, hi) in sorted(by_path.items(), key=lambda kv: kv[1][0])
            if 0 <= lo <= hi <= _U64_MAX  # drop unpackable (e.g. end < start) entries
        ]
        if modules:
            writer.add_module_list_index(modules)
    except Exception as exc:  # noqa: BLE001 — best-effort metadata only
        logger.warning("Failed to build module list from NT_FILE: %s", exc)


def _add_key_hints(writer: MslWriter, region_uuid, data: bytes,
                   secrets: List[CryptoSecret]) -> int:
    """Scan a region's assembled bytes for known secrets; add key hints."""
    hints = 0
    for secret in secrets:
        offset = data.find(secret.secret_value)
        if offset >= 0:
            writer.add_key_hint(
                region_uuid=region_uuid,
                offset=offset,
                key_length=len(secret.secret_value),
                key_type=_map_key_type(secret.secret_type),
                protocol=_map_protocol(secret.secret_type),
            )
            hints += 1
    return hints


@_reject_malformed_dump
def import_elf_core(
    elf_path: Path,
    output_path: Path,
    secrets: Optional[List[CryptoSecret]] = None,
    page_size_log2: Optional[int] = None,
) -> ImportResult:
    """Convert an ELF ET_CORE dump into an .msl memory slice.

    Emits ONE MSL memory region per PT_LOAD segment (never a spanning
    region across gaps), each with a real three-state page map: pages
    backed by stored bytes are CAPTURED, the [filesz, memsz) tail (e.g.
    .bss) is FAILED. NT_FILE mappings become a best-effort Module List
    Index. Provenance and End-of-Capture mirror import_raw_dump().
    """
    elf_path = Path(elf_path)
    orig_size = elf_path.stat().st_size

    with ElfCoreReader(elf_path) as reader:
        info = reader.info
        writer = MslWriter(
            output_path,
            pid=info.pid or 0,
            os_type=OSType.LINUX,
            arch_type=ArchType.UNKNOWN,
        )

        _add_module_index(writer, info.file_mappings)

        regions_written = 0
        hints_written = 0
        for seg in info.segments:
            region_uuid, data = _add_segment_region(
                writer, reader, seg, info, page_size_log2,
            )
            regions_written += 1
            if secrets and data:
                hints_written += _add_key_hints(
                    writer, region_uuid, data, secrets,
                )

    writer.add_import_provenance(
        source_format=SourceFormat.ELF_CORE,
        tool_name="memdiver",
        orig_file_size=orig_size,
        note=f"Imported from ELF core {elf_path.name}",
        source_path=elf_path,
    )
    writer.add_end_of_capture()
    writer.write()

    return ImportResult(
        source_path=elf_path,
        output_path=output_path,
        regions_written=regions_written,
        key_hints_written=hints_written,
        total_bytes=orig_size,
    )


# Minidump import helpers -----------------------------------------------------


def _align_down(x: int, page: int) -> int:
    """Round *x* down to the nearest multiple of *page*."""
    return x - (x % page)


def _align_up(x: int, page: int) -> int:
    """Round *x* up to the nearest multiple of *page*."""
    return ((x + page - 1) // page) * page


# NOTE: currently unused. Imports no longer synthesize UNMAPPED regions
# (UNMAPPED is a live-acquisition TOCTOU state; free/reserved ranges are left
# absent instead). Retained with _unmapped_region_spec should the size-capped
# materialization ever be revived.
#
# Cap on the span of a free/reserved range that is materialized as an explicit
# UNMAPPED region. The page-state map is a dense 2-bit-per-page bitmap, so an
# unbounded free range (a 64-bit process's exterior address space spans TiB)
# would produce a multi-GiB map. Bounded interior holes (guard pages, freed
# sub-allocations, reserved stacks) are the analytically useful "genuinely
# unmapped" signal; larger free spans are left implicit (region-absent), as
# before. 2**16 pages == 256 MiB at a 4 KiB page (a 16 KiB page-state map).
MAX_UNMAPPED_REGION_PAGES = 1 << 16

# Committed / PT_LOAD page maps are sized from attacker-controlled u64 header
# fields (ELF ``p_memsz`` / minidump ``MEMORY_INFO.region_size``) that
# legitimately exceed the stored byte count — so, unlike descriptor spans, they
# are NOT bounded by the file size. A few-KiB crafted dump can declare a
# petabyte region and drive a multi-billion-element ``[PageState.*] * n`` list
# → OOM on the tool's core "import an untrusted dump" action. Cap the derived
# page count and fail closed before allocating. 1<<24 pages is ~64 GiB at a
# 4 KiB page (far above any real single region, far below a memory-exhaustion
# threshold; larger page sizes only widen the headroom).
MAX_REGION_PAGES = 1 << 24


def _check_region_pages(pages: int, base: int, kind: str) -> None:
    """Fail closed when a region's derived page count is implausibly large.

    Guards the dense per-page ``PageState`` list against attacker-controlled
    region sizes (see ``MAX_REGION_PAGES``). Called before the list is built,
    so a hostile size never allocates.
    """
    if pages > MAX_REGION_PAGES:
        raise ValueError(
            f"{kind} region at {base:#x} declares {pages} pages "
            f"(> cap {MAX_REGION_PAGES}); refusing to allocate the page map "
            "— malformed or hostile dump"
        )


@dataclass
class RegionSpec:
    """One assembled MSL memory region derived from a minidump.

    ``data`` holds exactly the CAPTURED page bytes (FAILED/UNMAPPED pages
    contribute zero bytes), so ``len(data) == captured * page_size``.
    """

    base: int
    page_states: List[int]
    data: bytes
    protection: int
    region_type: int


def _map_minidump_arch(arch: Optional[int]) -> int:
    """Map a minidump ProcessorArchitecture to an MSL ArchType."""
    if arch == PROCESSOR_ARCHITECTURE_AMD64:
        return ArchType.X86_64
    if arch == PROCESSOR_ARCHITECTURE_INTEL:
        return ArchType.X86
    if arch == PROCESSOR_ARCHITECTURE_ARM64:
        return ArchType.ARM64
    if arch == PROCESSOR_ARCHITECTURE_ARM:
        return ArchType.ARM32
    return ArchType.UNKNOWN


def _map_protect(p: int) -> int:
    """Map a Win32 PAGE_* protection value to MSL Protection bits.

    A committed page always carries at least READ so it is never emitted
    with an empty (zero) protection mask.
    """
    prot = 0
    if p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY):
        prot |= Protection.READ
    if p & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE):
        prot |= Protection.WRITE
    if p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY):
        prot |= Protection.EXECUTE
    if p & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY):
        prot |= Protection.COW
    if p & PAGE_GUARD:
        prot |= Protection.GUARD
    return int(prot) or int(Protection.READ)


def _map_type(t: int) -> int:
    """Map a Win32 MEM_* region type to an MSL RegionType."""
    if t == MEM_IMAGE:
        return int(RegionType.IMAGE)
    if t == MEM_MAPPED:
        return int(RegionType.MAPPED_FILE)
    if t == MEM_PRIVATE:
        return int(RegionType.ANONYMOUS)
    return int(RegionType.UNKNOWN)


def _committed_region_spec(reader: MinidumpReader, mem_info, spans,
                           consumed: List[bool], page: int) -> RegionSpec:
    """Assemble one RegionSpec for a MEM_COMMIT VirtualQuery region.

    Each page that overlaps a captured descriptor span is CAPTURED (its
    bytes copied out of a zero-filled page buffer); every other page is
    FAILED (mapped but not stored) and contributes zero bytes to data.
    """
    base = _align_down(mem_info.base, page)
    end = _align_up(mem_info.base + mem_info.region_size, page)
    n = (end - base) // page
    _check_region_pages(n, base, "committed")
    states = [PageState.FAILED] * n
    # Build only the CAPTURED pages by walking the (few) descriptor spans, not
    # every page in the region. A crafted minidump can declare a MEM_COMMIT
    # region up to MAX_REGION_PAGES (~64 GiB) while capturing a single small
    # span; the previous per-page loop allocated a fresh bytearray(page) for
    # all n pages — O(pages x spans) work + allocator churn that could hang the
    # untrusted import path for minutes. This touches only pages a span covers
    # and produces a byte-identical RegionSpec (captured pages, in page order).
    captured: dict[int, bytearray] = {}
    for idx, (span_start, span_end, span_rva) in enumerate(spans):
        if max(span_start, base) >= min(span_end, end):
            continue  # span does not overlap this region
        first_pg = (max(span_start, base) - base) // page
        last_pg = (min(span_end, end) - 1 - base) // page
        for pg in range(first_pg, last_pg + 1):
            pva = base + pg * page
            lo = max(pva, span_start)
            hi = min(pva + page, span_end)
            if lo < hi:
                buffer = captured.get(pg)
                if buffer is None:
                    buffer = bytearray(page)
                    captured[pg] = buffer
                buffer[lo - pva:hi - pva] = reader.read_at(
                    span_rva + (lo - span_start), hi - lo,
                )
                states[pg] = PageState.CAPTURED
                consumed[idx] = True

    data = bytearray()
    for pg in sorted(captured):
        data += captured[pg]

    return RegionSpec(
        base=base,
        page_states=states,
        data=bytes(data),
        protection=_map_protect(mem_info.protect or mem_info.alloc_protect),
        region_type=_map_type(mem_info.type),
    )


def _captured_span_spec(reader: MinidumpReader, span_start: int,
                        span_end: int, span_rva: int, page: int) -> RegionSpec:
    """Assemble an all-CAPTURED RegionSpec directly from a descriptor span.

    Used both by the safety net (spans not covered by any committed
    region) and by the no-MemoryInfoList fallback path.
    """
    base = _align_down(span_start, page)
    end = _align_up(span_end, page)
    n = (end - base) // page
    buffer = bytearray(n * page)
    size = span_end - span_start
    buffer[span_start - base:span_start - base + size] = reader.read_at(
        span_rva, size,
    )
    return RegionSpec(
        base=base,
        page_states=[PageState.CAPTURED] * n,
        data=bytes(buffer),
        protection=int(Protection.READ | Protection.WRITE),
        region_type=int(RegionType.UNKNOWN),
    )


def _unmapped_region_spec(mem_info, page: int) -> Optional[RegionSpec]:
    """Assemble an all-UNMAPPED RegionSpec for a free/reserved VirtualQuery
    range — the container's positive "no committed content here" signal.

    NOTE: currently unused. Imports no longer synthesize UNMAPPED on import,
    because UNMAPPED is a live-acquisition TOCTOU state a static source cannot
    witness; free/reserved ranges are left absent instead (see _derive_regions).
    Retained in case size-capped UNMAPPED materialization is revived.

    Carries zero data (UNMAPPED pages contribute no bytes), protection 0
    (no access), and RegionType.UNKNOWN. Returns ``None`` for a zero-page or
    over-cap range (the latter left implicit; see ``MAX_UNMAPPED_REGION_PAGES``).
    """
    base = _align_down(mem_info.base, page)
    end = _align_up(mem_info.base + mem_info.region_size, page)
    n = (end - base) // page
    if n <= 0:
        return None
    if n > MAX_UNMAPPED_REGION_PAGES:
        logger.debug(
            "Leaving large unmapped range at %#x implicit (%d pages > cap %d)",
            base, n, MAX_UNMAPPED_REGION_PAGES,
        )
        return None
    return RegionSpec(
        base=base,
        page_states=[PageState.UNMAPPED] * n,
        data=b"",
        protection=0,  # unmapped: no access
        region_type=int(RegionType.UNKNOWN),
    )


def _derive_regions(reader: MinidumpReader,
                    page_size_log2: int) -> List[RegionSpec]:
    """Turn a minidump's memory map into a list of MSL RegionSpecs.

    With a MemoryInfoList (VirtualQuery) present, committed pages backed by a
    captured span are CAPTURED and other committed pages are FAILED (mapped
    but no bytes stored in the source). Reserved/free ranges are left absent
    (no region): UNMAPPED is a live-acquisition TOCTOU state a static source
    cannot witness, so it is never synthesized. Any captured span not covered
    by a committed region is still emitted (safety net) so no dumped bytes are
    lost. Without a MemoryInfoList, falls back to all-CAPTURED regions
    straight from the memory descriptors. Imports therefore assign only
    CAPTURED/FAILED, flagged inferred via CapBit.PAGE_STATES_INFERRED.
    """
    page = 1 << page_size_log2
    info = reader.info

    spans = [
        (d.start, d.start + d.size, d.rva)
        for d in sorted(info.memory_descriptors, key=lambda d: d.start)
    ]

    specs: List[RegionSpec] = []

    if info.has_memory_info_list:
        consumed = [False] * len(spans)
        for mem_info in sorted(info.memory_info, key=lambda mi: mi.base):
            if mem_info.state == MEM_COMMIT:
                specs.append(_committed_region_spec(
                    reader, mem_info, spans, consumed, page,
                ))
            elif mem_info.state in (MEM_FREE, MEM_RESERVE):
                # Free/reserved ranges are left absent (no region emitted).
                # UNMAPPED is definitionally a live-acquisition TOCTOU race
                # (present at enumeration, gone at read); a static Minidump
                # never witnesses one, so we do not synthesize it. Absence-by-
                # omission is the honest encoding for "the source does not map
                # this range." See CapBit.PAGE_STATES_INFERRED.
                continue
            # Any other state (unexpected) is skipped: no region emitted.
        # Safety net: never drop dumped bytes for a span no committed
        # region claimed.
        for idx, (span_start, span_end, span_rva) in enumerate(spans):
            if not consumed[idx]:
                specs.append(_captured_span_spec(
                    reader, span_start, span_end, span_rva, page,
                ))
    else:
        logger.info(
            "Minidump has no MemoryInfoList; importing %d descriptors as "
            "all-CAPTURED regions (fallback mode)", len(spans),
        )
        for span_start, span_end, span_rva in spans:
            specs.append(_captured_span_spec(
                reader, span_start, span_end, span_rva, page,
            ))

    # Invariant: CAPTURED page count * page_size == len(data).
    for spec in specs:
        captured = sum(
            1 for s in spec.page_states if int(s) == int(PageState.CAPTURED)
        )
        # A real integrity check on the untrusted-import path: use raise, not
        # assert (which `-O` strips), and ValueError so it funnels through
        # @_reject_malformed_dump like every other malformed-dump signal.
        if captured * page != len(spec.data):
            raise ValueError(
                f"region base={spec.base:#x}: {captured} captured pages * "
                f"{page} != data length {len(spec.data)}"
            )

    return specs


@_reject_malformed_dump
def import_minidump(
    dmp_path: Path,
    output_path: Path,
    pid: int = 0,
    secrets: Optional[List[CryptoSecret]] = None,
    page_size_log2: int = 12,
) -> ImportResult:
    """Convert a Windows Minidump (.dmp) into an .msl memory slice.

    Emits one MSL memory region per committed VirtualQuery region with a
    two-state page map (CAPTURED where a descriptor span backs the page,
    FAILED otherwise — mapped but not stored). Reserved/free ranges are left
    absent; UNMAPPED (a TOCTOU race) is never synthesized on import. When no
    MemoryInfoList is present the reader's memory descriptors become
    all-CAPTURED regions. Provenance and End-of-Capture mirror the other
    importers, and the file is flagged CapBit.PAGE_STATES_INFERRED.
    """
    dmp_path = Path(dmp_path)
    orig_size = dmp_path.stat().st_size

    with MinidumpReader(dmp_path) as reader:
        info = reader.info
        os_type = OSType.WINDOWS
        arch = _map_minidump_arch(
            info.system_info.arch if info.system_info else None,
        )
        eff_pid = pid or info.pid or 0
        writer = MslWriter(
            output_path, pid=eff_pid, os_type=os_type, arch_type=arch,
        )

        regions = _derive_regions(reader, page_size_log2)
        for spec in regions:
            writer.add_memory_region(
                spec.base, spec.data,
                protection=spec.protection,
                region_type=spec.region_type,
                page_size_log2=page_size_log2,
                page_states=spec.page_states,
            )

    writer.add_import_provenance(
        source_format=SourceFormat.MINIDUMP,
        tool_name="memdiver",
        orig_file_size=orig_size,
        note=f"Imported from minidump {dmp_path.name}",
        source_path=dmp_path,
    )
    writer.add_end_of_capture()
    writer.write()

    return ImportResult(
        source_path=dmp_path,
        output_path=output_path,
        regions_written=len(regions),
        key_hints_written=0,
        total_bytes=orig_size,
    )


@_reject_malformed_dump
def import_raw_dump(
    raw_path: Path,
    output_path: Path,
    pid: int = 0,
    secrets: Optional[List[CryptoSecret]] = None,
    os_type: int = OSType.UNKNOWN,
    arch_type: int = ArchType.UNKNOWN,
    page_size_log2: int = 12,
) -> ImportResult:
    """Convert a raw .dump file to .msl format."""
    writer = MslWriter(
        output_path, pid=pid, os_type=os_type, arch_type=arch_type
    )

    # MSL Specification v1.0.0 §5.1 mandates that RegionSize be a multiple
    # of PageSize. Raw .dump files are an arbitrary number of bytes, so we
    # zero-pad up to the next page boundary. Importer-injected padding is
    # transparent because the original size is recorded in the
    # IMPORT_PROVENANCE block's `orig_file_size` field.
    #
    # Read the file directly into a single page-padded buffer (the tail stays
    # zero) rather than ``read_bytes()`` + concatenation — the latter held two
    # full copies of the dump in RAM at once (~2x peak on a multi-GiB import).
    page_size = 1 << page_size_log2
    orig_size = raw_path.stat().st_size
    pad = (-orig_size) % page_size
    region_data = bytearray(orig_size + pad)
    with open(raw_path, "rb") as fh:
        got = fh.readinto(memoryview(region_data)[:orig_size])
    if got < orig_size:  # file shrank between stat and read (rare)
        orig_size = got
        del region_data[orig_size:]
        region_data.extend(b"\x00" * ((-orig_size) % page_size))

    region_uuid = writer.add_memory_region(
        0, region_data, page_size_log2=page_size_log2
    )

    hints_written = 0
    if secrets:
        for secret in secrets:
            # Search only the original bytes (key offsets reference the
            # original file; the page padding is appended past the end and
            # won't shift hits).
            offset = region_data.find(secret.secret_value, 0, orig_size)
            if offset >= 0:
                writer.add_key_hint(
                    region_uuid=region_uuid,
                    offset=offset,
                    key_length=len(secret.secret_value),
                    key_type=_map_key_type(secret.secret_type),
                    protocol=_map_protocol(secret.secret_type),
                )
                hints_written += 1

    writer.add_import_provenance(
        source_format=SourceFormat.RAW_DUMP,
        tool_name="memdiver",
        orig_file_size=orig_size,
        note=f"Imported from {raw_path.name}",
    )
    writer.add_end_of_capture()
    writer.write()

    return ImportResult(
        source_path=raw_path,
        output_path=output_path,
        regions_written=1,
        key_hints_written=hints_written,
        total_bytes=orig_size,
    )


def import_run_directory(
    run_dir: Path,
    output_dir: Path,
    keylog_filename: str = "keylog.csv",
) -> List[ImportResult]:
    """Import all dump files (.dump/.dmp/.core) in a run directory to .msl.

    Each file is routed through :func:`import_dump`, which sniffs the format
    and dispatches to the raw, ELF-core, or minidump importer as appropriate.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []

    secrets = None
    keylog_path = run_dir / keylog_filename
    if keylog_path.is_file():
        from memdiver.core.keylog import KeylogParser

        secrets = KeylogParser().parse(keylog_path)

    dump_files = sorted(
        set(run_dir.glob("*.dump"))
        | set(run_dir.glob("*.dmp"))
        | set(run_dir.glob("*.core"))
    )
    for dump_file in dump_files:
        out_path = output_dir / (dump_file.name + ".msl")
        result = import_dump(dump_file, out_path, secrets=secrets)
        results.append(result)

    return results


# Unified dispatch ------------------------------------------------------------

# ELF e_type value for a core dump (ET_CORE); see <elf.h>.
_ET_CORE = 4


def _is_et_core(head: bytes) -> bool:
    """True if *head* is an ELF header whose e_type is ET_CORE.

    Endianness is read from EI_DATA (byte 5: 1=little, 2=big); e_type is a
    uint16 at offset 16. A non-ELF or truncated header returns False.
    """
    if len(head) < 18 or head[:4] != b"\x7fELF":
        return False
    endian = "<" if head[5] == 1 else ">" if head[5] == 2 else None
    if endian is None:
        return False
    try:
        e_type = struct.unpack_from(f"{endian}H", head, 16)[0]
    except struct.error:
        return False
    return e_type == _ET_CORE


@_reject_malformed_dump
def import_dump(
    src_path: Path,
    output_path: Path,
    pid: int = 0,
    secrets: Optional[List[CryptoSecret]] = None,
    **kwargs,
) -> ImportResult:
    """Import any supported dump into .msl, dispatching on detected format.

    Routes minidumps to :func:`import_minidump`, ELF ET_CORE files to
    :func:`import_elf_core` (falling back to raw if the ELF is not a
    parseable core), and everything else to :func:`import_raw_dump`. The
    raw path is preserved unchanged so plain .dump imports are a no-op
    regression.
    """
    src_path = Path(src_path)
    with open(src_path, "rb") as fh:
        head = fh.read(512)
    fmt = detect_format(head)

    if fmt == "minidump":
        return import_minidump(
            src_path, output_path, pid=pid, secrets=secrets,
        )

    if fmt in ("elf64", "elf32", "elf"):
        if _is_et_core(head):
            try:
                return import_elf_core(
                    src_path, output_path, secrets=secrets,
                )
            except ValueError as exc:
                logger.info(
                    "ELF ET_CORE parse failed (%s); falling back to raw "
                    "import", exc,
                )
        # Not a core (or unparseable) => raw fallback below.

    raw_kwargs = {
        k: v for k, v in kwargs.items()
        if k in ("os_type", "arch_type", "page_size_log2")
    }
    return import_raw_dump(
        src_path, output_path, pid=pid, secrets=secrets, **raw_kwargs,
    )
