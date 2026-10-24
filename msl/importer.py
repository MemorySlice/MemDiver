"""Raw-to-MSL import: convert .dump files to .msl format."""

import functools
import logging
import shutil
import struct
from dataclasses import dataclass, field
from math import ceil
from pathlib import Path
from typing import Callable, List, Optional, Sequence
from uuid import UUID

from memdiver.core.binary_formats.elf_core_reader import (ElfCoreReader, NtFileEntry,
                                                 PtLoadSegment, PF_R, PF_W, PF_X,
                                                 machine_to_arch_type)
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
                    Protection, RegionType, SourceFormat, VasNameSource)
from .import_sources import MappedFile, Run, RunBuilder, RunSource
from .import_threads import (add_thread_contexts, elf_thread_contexts,
                             minidump_thread_contexts)
from .region_select import (REGION_NAMES_NOTE, RegionInfo, RegionSelection,
                            join_provenance_note, selection_provenance_note)
from .types import MslVasEntry
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
    # Region selection outcome (defaults == "no selection requested").
    selection: Optional[str] = None
    excluded_region_count: int = 0
    excluded_bytes: int = 0
    secrets_only_in_excluded: int = 0
    warnings: List[str] = field(default_factory=list)
    # .msl materialize outcome (see import_msl_passthrough(materialize=True)).
    materialized: bool = False
    dropped_key_hints: int = 0
    # Encrypted .msl materialize: copy re-encrypted (default) or written as
    # plaintext on explicit opt-in (decrypt_output).
    reencrypted: bool = False
    decrypted_output: bool = False

    @property
    def has_selection_info(self) -> bool:
        """True when a selection was requested or a warning was raised."""
        return self.selection is not None or bool(self.warnings)

    def selection_summary(self) -> dict:
        """JSON-friendly selection fields (for CLI / API summaries)."""
        return {
            "selection": self.selection,
            "excluded_region_count": self.excluded_region_count,
            "excluded_bytes": self.excluded_bytes,
            "secrets_only_in_excluded": self.secrets_only_in_excluded,
            "warnings": list(self.warnings),
            **({"materialized": True,
                "dropped_key_hints": self.dropped_key_hints,
                "reencrypted": self.reencrypted,
                "decrypted_output": self.decrypted_output}
               if self.materialized else {}),
        }


# Region selection plumbing ---------------------------------------------------

_MSL_SELECTION_WARNING = ("selection is applied at analysis time for .msl; "
                          "use materialize to write a filtered copy")
DECRYPTED_OUTPUT_WARNING = ("materialized copy written DECRYPTED: it holds the "
                            "selected regions as plaintext, unprotected by the "
                            "source's encryption")
_DECRYPT_OUTPUT_IGNORED = ("decrypt_output applies only to a materialized "
                           "(region-filtered) copy; the container was staged "
                           "verbatim and stays encrypted")
_WRONG_KEY_WARNING = ("key material supplied but decryption failed (wrong key "
                      "or tampered file); staged verbatim, regions not counted")


@dataclass
class _SelectionPlan:
    """Which of an import's regions are written, and why.

    ``selection`` is the *effective* selection (``RegionSelection.all()``
    after a zero-byte fallback); ``None`` means no selection was requested
    and the import must behave exactly as before.
    """

    selection: Optional[RegionSelection]
    infos: List[RegionInfo]
    keep: List[bool]
    fallback: bool = False
    warnings: List[str] = field(default_factory=list)

    @property
    def excluded_indices(self) -> List[int]:
        return [i for i, kept in enumerate(self.keep) if not kept]

    @property
    def excluded_count(self) -> int:
        return len(self.excluded_indices)

    @property
    def excluded_bytes(self) -> int:
        return sum(self.infos[i].captured_bytes for i in self.excluded_indices)


def _plan_selection(infos: List[RegionInfo],
                    selection: Optional[RegionSelection]) -> _SelectionPlan:
    """Decide which regions to keep; falls back to all on a zero-byte keep."""
    if selection is None:
        return _SelectionPlan(None, infos, [True] * len(infos))
    keep = [selection.includes(info) for info in infos]
    kept_bytes = sum(i.captured_bytes for i, k in zip(infos, keep) if k)
    if kept_bytes == 0 and not all(keep):
        warning = (f"region selection {selection.to_note()!r} would keep 0 "
                   f"captured bytes; importing all regions instead")
        logger.warning(warning)
        return _SelectionPlan(RegionSelection.all(), infos,
                              [True] * len(infos), True, [warning])
    return _SelectionPlan(selection, infos, keep)


def _add_vas_map_if_excluded(
        writer: MslWriter, plan: _SelectionPlan,
        name_source_for_path: int = VasNameSource.SYNTHESIZED) -> None:
    """Record the full layout (kept AND excluded) once anything was dropped.

    Excluded regions have a VAS entry but no MEMORY_REGION block, which is
    how a reader tells "not captured by selection" apart. ``mapped_path``
    is the module path; *name_source_for_path* is the NameSource written
    for entries that have one (SOURCE_METADATA when the paths come from
    the source's own module metadata, e.g. a minidump module stream;
    SYNTHESIZED when derived). Entries without a path are UNSPECIFIED.
    """
    if not plan.excluded_count:
        return
    writer.add_vas_map([
        MslVasEntry(base_addr=i.base_addr, region_size=i.size,
                    protection=i.protection, region_type=i.region_type,
                    mapped_path=i.module_path or "",
                    name_source=_path_name_source(i.module_path,
                                                  name_source_for_path))
        for i in sorted(plan.infos, key=lambda info: info.base_addr)
    ])


def _path_name_source(path: Optional[str], source_when_set: int) -> int:
    return int(source_when_set) if path else int(VasNameSource.UNSPECIFIED)


def _named_vas_name_source(info: RegionInfo) -> int:
    """NameSource for :func:`_add_named_vas_map`: the mapping name is
    source metadata, a module path is synthesized, nothing is unspecified."""
    if info.name:
        return int(VasNameSource.SOURCE_METADATA)
    if info.module_path:
        return int(VasNameSource.SYNTHESIZED)
    return int(VasNameSource.UNSPECIFIED)


def _add_named_vas_map(writer: MslWriter, plan: _SelectionPlan) -> None:
    """Record the full layout with every region's mapping name, always.

    Used by the ELF-core and regioned-raw importers: ``mapped_path`` is the
    full mapping name (``RegionInfo.name``, e.g. ``[anon:scudo:primary]``)
    or else the module path. Entries carry NameSource SOURCE_METADATA for a
    mapping name (readers trust it, spec 5.8), SYNTHESIZED for a bare
    module path; pre-1.1 readers fall back to the ``region_names=1``
    provenance marker (:func:`_named_base_note`). Excluded regions still
    have a VAS entry but no MEMORY_REGION block.
    """
    writer.add_vas_map([
        MslVasEntry(base_addr=i.base_addr, region_size=i.size,
                    protection=i.protection, region_type=i.region_type,
                    mapped_path=i.name or i.module_path or "",
                    name_source=_named_vas_name_source(i))
        for i in sorted(plan.infos, key=lambda info: info.base_addr)
    ])


def _named_base_note(base_note: str) -> str:
    """*base_note* plus the ``region_names=1`` marker segment."""
    return join_provenance_note(base_note, REGION_NAMES_NOTE)


def _os_type_for_platform(platform: Optional[str]) -> int:
    """Header ``os_type`` of a Linux-family import (Android when detected)."""
    return OSType.ANDROID if platform == "android" else OSType.LINUX


def _provenance_note(base_note: str, plan: _SelectionPlan) -> str:
    if plan.selection is None:
        return base_note
    return join_provenance_note(base_note, selection_provenance_note(
        plan.selection, plan.excluded_count, plan.excluded_bytes,
        fallback=plan.fallback))


def _count_secrets_only_in_excluded(
        secrets: Optional[Sequence[CryptoSecret]], plan: _SelectionPlan,
        searchable_for: Callable[[int], object]) -> int:
    """Secrets present in some excluded region but in no kept region.

    *searchable_for(idx)* returns an object with ``bytes.find`` semantics
    (a :class:`RunSource` searches the mmap in place, never materialising).
    Excluded regions are searched first, so kept regions are only scanned
    for the (usually few) secrets an exclusion actually hides.
    """
    excluded = plan.excluded_indices
    if not secrets or not excluded:
        return 0
    kept = [i for i, k in enumerate(plan.keep) if k]

    def _found_in(indices, needle) -> bool:
        return any(searchable_for(i).find(needle) >= 0 for i in indices)

    return sum(1 for secret in secrets
               if secret.secret_value
               and _found_in(excluded, secret.secret_value)
               and not _found_in(kept, secret.secret_value))


def _selection_result(result: "ImportResult", plan: _SelectionPlan,
                      secrets_only_in_excluded: int = 0) -> "ImportResult":
    """Copy the selection outcome onto *result* (no-op when no selection)."""
    if plan.selection is None:
        return result
    result.selection = plan.selection.to_note()
    result.excluded_region_count = plan.excluded_count
    result.excluded_bytes = plan.excluded_bytes
    result.secrets_only_in_excluded = secrets_only_in_excluded
    result.warnings = list(plan.warnings)
    if secrets_only_in_excluded:
        warning = (f"{secrets_only_in_excluded} keylog secret(s) found only "
                   f"in excluded regions; widen the region selection to "
                   f"keep them")
        logger.warning(warning)
        result.warnings.append(warning)
    return result


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
    raw = _read_segment_data(reader, seg)
    plan = _plan_segment_pages(seg, info, page_size_log2, len(raw))
    log2, page_size = plan.page_size_log2, 1 << plan.page_size_log2
    captured_pages = plan.captured_pages

    data = bytearray(raw[:captured_pages * page_size])
    if len(data) < captured_pages * page_size:  # pad only fully-CAPTURED pages
        data.extend(b"\x00" * (captured_pages * page_size - len(data)))
    data = bytes(data)

    region_uuid = writer.add_memory_region(
        seg.vaddr, data, protection=_protection_from_flags(seg.flags),
        region_type=_region_type_for_segment(seg, info.file_mappings),
        page_size_log2=log2, page_states=plan.page_states(),
    )
    return region_uuid, data


@dataclass(frozen=True)
class _SegmentPagePlan:
    """Three-state page layout of one PT_LOAD segment (see below)."""

    page_size_log2: int
    captured_pages: int
    failed_pages: int

    def page_states(self) -> List[int]:
        return ([PageState.CAPTURED] * self.captured_pages
                + [PageState.FAILED] * self.failed_pages)


def _plan_segment_pages(seg: PtLoadSegment, info, page_size_log2: Optional[int],
                        actual: int) -> _SegmentPagePlan:
    """Decide CAPTURED/FAILED pages for a segment with *actual* stored bytes.

    Pages backed by stored bytes are CAPTURED; the [filesz, memsz) tail
    (e.g. .bss) is FAILED. On a *truncated* core (``actual < filesz``) the
    pages past the last fully-read page are also FAILED rather than
    fabricated as captured zero-fill.
    """
    log2 = _page_size_log2_for_segment(seg, info, page_size_log2)
    page_size = 1 << log2

    filesz = min(seg.filesz, seg.memsz)  # defensive: never store past memsz
    total_pages = ceil(seg.memsz / page_size) if seg.memsz else 0
    _check_region_pages(total_pages, seg.vaddr, "PT_LOAD")

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
    return _SegmentPagePlan(log2, captured_pages, failed_pages)


def _stored_segment_length(mapped: MappedFile, seg: PtLoadSegment) -> int:
    """Bytes of the segment actually present on disk (mirrors read_at clamp)."""
    filesz = min(seg.filesz, seg.memsz)
    if filesz == 0 or seg.file_offset < 0 or seg.file_offset >= mapped.size:
        return 0
    return min(seg.file_offset + filesz, mapped.size) - seg.file_offset


def _add_segment_region_streamed(writer: MslWriter, mapped: MappedFile,
                                 seg: PtLoadSegment, info,
                                 page_size_log2: Optional[int],
                                 region_type: Optional[int] = None):
    """Streaming twin of :func:`_add_segment_region` (byte-identical output).

    The CAPTURED stream is the segment's stored bytes sliced straight from
    the mapped file, zero-filled to the last CAPTURED page boundary.
    *region_type* overrides the segment's mapping-derived type (the import
    passes the classified :attr:`RegionInfo.region_type`, i.e. STACK for a thread
    stack). Returns (region_uuid, source) — *source* also serves key-hint
    search.
    """
    if region_type is None:
        region_type = _region_type_for_segment(seg, info.file_mappings)
    plan, source = _segment_stream(mapped, seg, info, page_size_log2)
    region_uuid = writer.add_memory_region_source(
        seg.vaddr, (plan.captured_pages + plan.failed_pages)
        * (1 << plan.page_size_log2), source,
        protection=_protection_from_flags(seg.flags),
        region_type=region_type,
        page_size_log2=plan.page_size_log2, page_states=plan.page_states(),
    )
    return region_uuid, source


def _segment_stream(mapped: MappedFile, seg: PtLoadSegment, info,
                    page_size_log2: Optional[int]):
    """(page plan, CAPTURED-byte RunSource) of one PT_LOAD segment."""
    actual = _stored_segment_length(mapped, seg)
    plan = _plan_segment_pages(seg, info, page_size_log2, actual)
    captured_len = plan.captured_pages * (1 << plan.page_size_log2)

    builder = RunBuilder()
    stored = min(actual, captured_len)
    builder.add_file(seg.file_offset, stored)
    builder.add_zeros(captured_len - stored)
    return plan, RunSource(mapped, builder.runs)


def _elf_selection_plan(reader: ElfCoreReader,
                        page_size_log2: Optional[int],
                        selection: Optional[RegionSelection]) -> _SelectionPlan:
    """Classify PT_LOAD segments exactly as the import preview does.

    Classified even without a *selection*: the infos also carry each
    region's stored type (STACK for a thread stack).
    """
    from .import_preview import elf_region_infos

    return _plan_selection(elf_region_infos(reader, page_size_log2),
                           selection)


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


def _add_key_hints(writer: MslWriter, region_uuid, data,
                   secrets: List[CryptoSecret]) -> int:
    """Scan a region's captured bytes for known secrets; add key hints.

    *data* is anything with ``bytes.find`` semantics: assembled bytes or a
    streaming :class:`RunSource` (which searches the mapped file in place).
    """
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
    selection: Optional[RegionSelection] = None,
) -> ImportResult:
    """Convert an ELF ET_CORE dump into an .msl memory slice.

    Emits ONE MSL memory region per PT_LOAD segment (never a spanning
    region across gaps), each with a real three-state page map: pages
    backed by stored bytes are CAPTURED, the [filesz, memsz) tail (e.g.
    .bss) is FAILED. NT_FILE mappings become a best-effort Module List
    Index. Provenance and End-of-Capture mirror import_raw_dump().

    With a *selection*, only segments it includes are written; the
    selection goes into provenance. The full layout (with NT_FILE names) is
    always written as a VAS_MAP block, marked ``region_names=1``.
    """
    elf_path = Path(elf_path)
    orig_size = elf_path.stat().st_size

    from .import_preview import elf_platform

    with ElfCoreReader(elf_path) as reader, MappedFile(elf_path) as mapped:
        info = reader.info
        writer = MslWriter(
            output_path,
            pid=info.pid or 0,
            os_type=_os_type_for_platform(elf_platform(reader)[0]),
            arch_type=machine_to_arch_type(info.machine),
        )

        _add_module_index(writer, info.file_mappings)
        # Thread contexts precede the first Memory Region (spec §5.7).
        add_thread_contexts(writer, elf_thread_contexts(info))
        plan = _elf_selection_plan(reader, page_size_log2, selection)

        regions_written = 0
        hints_written = 0
        for seg, region, keep in zip(info.segments, plan.infos, plan.keep):
            if not keep:
                continue
            region_uuid, source = _add_segment_region_streamed(
                writer, mapped, seg, info, page_size_log2,
                region_type=region.region_type,
            )
            regions_written += 1
            if secrets and source:
                # RunSource.find() searches the mapped file in place.
                hints_written += _add_key_hints(
                    writer, region_uuid, source, secrets,
                )

        _add_named_vas_map(writer, plan)
        hidden = _count_secrets_only_in_excluded(
            secrets, plan, lambda i: _segment_stream(
                mapped, info.segments[i], info, page_size_log2)[1])
        writer.add_import_provenance(
            source_format=SourceFormat.ELF_CORE,
            tool_name="memdiver",
            orig_file_size=orig_size,
            note=_provenance_note(_named_base_note(
                f"Imported from ELF core {elf_path.name}"), plan),
            source_path=elf_path,
        )
        writer.add_end_of_capture()
        writer.write()  # read_chunk runs here: keep the mmap open until done

    return _selection_result(ImportResult(
        source_path=elf_path,
        output_path=output_path,
        regions_written=regions_written,
        key_hints_written=hints_written,
        total_bytes=orig_size,
    ), plan, hidden)


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

    @property
    def data_len(self) -> int:
        return len(self.data)


@dataclass
class StreamedRegionSpec:
    """Streaming twin of :class:`RegionSpec`: CAPTURED bytes as file runs.

    ``runs`` describe the CAPTURED byte stream (file ranges, zero fill and
    small literal edge pages) over the mapped minidump, so the region is
    never materialised; ``data_len == captured * page_size``.
    """

    base: int
    page_states: List[int]
    runs: List[Run]
    protection: int
    region_type: int

    @property
    def data_len(self) -> int:
        return sum(r.length for r in self.runs)


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


def _derive_regions(reader: MinidumpReader, page_size_log2: int,
                    committed_spec=None, span_spec=None) -> List[RegionSpec]:
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

    *committed_spec* / *span_spec* select the spec builders (defaults: the
    in-memory :func:`_committed_region_spec` / :func:`_captured_span_spec`;
    the streaming importer passes their run-based twins).
    """
    committed_spec = committed_spec or _committed_region_spec
    span_spec = span_spec or _captured_span_spec
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
                specs.append(committed_spec(
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
                specs.append(span_spec(
                    reader, span_start, span_end, span_rva, page,
                ))
    else:
        logger.info(
            "Minidump has no MemoryInfoList; importing %d descriptors as "
            "all-CAPTURED regions (fallback mode)", len(spans),
        )
        for span_start, span_end, span_rva in spans:
            specs.append(span_spec(
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
        if captured * page != spec.data_len:
            raise ValueError(
                f"region base={spec.base:#x}: {captured} captured pages * "
                f"{page} != data length {spec.data_len}"
            )

    return specs


def _spans_overlap(spans) -> bool:
    """True if any two (start-sorted) descriptor spans overlap in VA."""
    return any(nxt[0] < prev[1] for prev, nxt in zip(spans, spans[1:]))


def _committed_region_stream_spec(reader: MinidumpReader, mem_info, spans,
                                  consumed: List[bool], page: int):
    """Streaming twin of :func:`_committed_region_spec` (same bytes/states).

    Pages a single span fully covers become one file run per span; the (at
    most two per span) partially covered edge pages are assembled into
    small literal buffers. Overlapping spans (last-writer-wins per page)
    are rare and fall back to the in-memory builder for exactness.
    """
    base = _align_down(mem_info.base, page)
    end = _align_up(mem_info.base + mem_info.region_size, page)
    n = (end - base) // page
    _check_region_pages(n, base, "committed")
    hits = [(idx, span) for idx, span in enumerate(spans)
            if max(span[0], base) < min(span[1], end)]
    if _spans_overlap([span for _, span in hits]):
        return _committed_region_spec(reader, mem_info, spans, consumed, page)

    states = [PageState.FAILED] * n
    full_runs: dict[int, tuple] = {}  # first page -> (page count, rva)
    edges: dict[int, bytearray] = {}
    for idx, (span_start, span_end, span_rva) in hits:
        consumed[idx] = True
        lo, hi = max(span_start, base), min(span_end, end)
        first_pg, last_pg = (lo - base) // page, (hi - 1 - base) // page
        full_lo, full_hi = -(-(lo - base) // page), (hi - base) // page
        if full_lo < full_hi:
            rva = span_rva + (base + full_lo * page - span_start)
            full_runs[full_lo] = (full_hi - full_lo, rva)
            states[full_lo:full_hi] = [PageState.CAPTURED] * (full_hi - full_lo)
        for pg in {first_pg, last_pg}:
            if full_lo <= pg < full_hi:
                continue
            _copy_edge_page(reader, edges, pg, base + pg * page, page,
                            (span_start, span_end, span_rva))
            states[pg] = PageState.CAPTURED

    return StreamedRegionSpec(
        base=base,
        page_states=states,
        runs=_runs_from_pages(full_runs, edges, page),
        protection=_map_protect(mem_info.protect or mem_info.alloc_protect),
        region_type=_map_type(mem_info.type),
    )


def _copy_edge_page(reader: MinidumpReader, edges: dict, pg: int, pva: int,
                    page: int, span) -> None:
    """Copy a span's slice of one partially covered page into *edges*."""
    span_start, span_end, span_rva = span
    lo, hi = max(pva, span_start), min(pva + page, span_end)
    buffer = edges.setdefault(pg, bytearray(page))
    buffer[lo - pva:hi - pva] = reader.read_at(
        span_rva + (lo - span_start), hi - lo,
    )


def _runs_from_pages(full_runs: dict, edges: dict, page: int) -> List[Run]:
    """Order full-page file runs and literal edge pages by page index."""
    builder = RunBuilder()
    for pg in sorted(set(full_runs) | set(edges)):
        if pg in full_runs:
            count, rva = full_runs[pg]
            builder.add_file(rva, count * page)
        else:
            builder.add_literal(edges[pg])
    return builder.runs


def _captured_span_stream_spec(reader: MinidumpReader, span_start: int,
                               span_end: int, span_rva: int,
                               page: int) -> StreamedRegionSpec:
    """Streaming twin of :func:`_captured_span_spec`: zeros | span | zeros."""
    base = _align_down(span_start, page)
    end = _align_up(span_end, page)
    builder = RunBuilder()
    builder.add_zeros(span_start - base)
    builder.add_file(span_rva, span_end - span_start)
    builder.add_zeros(end - span_end)
    return StreamedRegionSpec(
        base=base,
        page_states=[PageState.CAPTURED] * ((end - base) // page),
        runs=builder.runs,
        protection=int(Protection.READ | Protection.WRITE),
        region_type=int(RegionType.UNKNOWN),
    )


def _add_minidump_region(writer: MslWriter, mapped: MappedFile, spec,
                         page_size_log2: int,
                         region_type: Optional[int] = None) -> UUID:
    """Register one derived region: streamed when run-based, else in memory.

    *region_type* overrides ``spec.region_type`` (STACK for a thread stack).
    """
    if region_type is None:
        region_type = spec.region_type
    common = dict(protection=spec.protection, region_type=region_type,
                  page_size_log2=page_size_log2, page_states=spec.page_states)
    if isinstance(spec, StreamedRegionSpec):
        region_size = len(spec.page_states) << page_size_log2
        return writer.add_memory_region_source(
            spec.base, region_size, RunSource(mapped, spec.runs), **common)
    return writer.add_memory_region(spec.base, spec.data, **common)


def _minidump_searchable(mapped: MappedFile, spec):
    """``find``-able CAPTURED bytes of a spec (mmap-backed when streamed)."""
    if isinstance(spec, StreamedRegionSpec):
        return RunSource(mapped, spec.runs)
    return spec.data


def _minidump_selection_plan(info, specs, page_size_log2: int,
                             selection: Optional[RegionSelection]
                             ) -> _SelectionPlan:
    """Classify derived regions with the preview's inputs (thread stacks).

    Classified even without a *selection* (stored STACK type, see ELF).
    """
    from .import_preview import minidump_stack_ranges, region_infos

    raw = [(spec.base, len(spec.page_states) << page_size_log2,
            spec.protection, spec.region_type,
            sum(1 for s in spec.page_states
                if int(s) == int(PageState.CAPTURED)) << page_size_log2,
            None)
           for spec in specs]
    return _plan_selection(region_infos(raw, minidump_stack_ranges(info)),
                           selection)


@_reject_malformed_dump
def import_minidump(
    dmp_path: Path,
    output_path: Path,
    pid: int = 0,
    secrets: Optional[List[CryptoSecret]] = None,
    page_size_log2: int = 12,
    selection: Optional[RegionSelection] = None,
) -> ImportResult:
    """Convert a Windows Minidump (.dmp) into an .msl memory slice.

    *selection* (optional) keeps only the regions it includes; see
    :func:`import_elf_core`.

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

    with MinidumpReader(dmp_path) as reader, MappedFile(dmp_path) as mapped:
        info = reader.info
        os_type = OSType.WINDOWS
        arch = _map_minidump_arch(
            info.system_info.arch if info.system_info else None,
        )
        eff_pid = pid or info.pid or 0
        writer = MslWriter(
            output_path, pid=eff_pid, os_type=os_type, arch_type=arch,
        )

        regions = _derive_regions(
            reader, page_size_log2,
            committed_spec=_committed_region_stream_spec,
            span_spec=_captured_span_stream_spec,
        )
        plan = _minidump_selection_plan(info, regions, page_size_log2,
                                        selection)
        # Thread contexts precede the first Memory Region (spec §5.7).
        add_thread_contexts(writer, minidump_thread_contexts(reader, info))
        for spec, region, keep in zip(regions, plan.infos, plan.keep):
            if keep:
                _add_minidump_region(writer, mapped, spec, page_size_log2,
                                     region.region_type)

        # Module paths come from the minidump's module stream: source metadata.
        _add_vas_map_if_excluded(
            writer, plan, name_source_for_path=VasNameSource.SOURCE_METADATA)
        hidden = _count_secrets_only_in_excluded(
            secrets, plan, lambda i: _minidump_searchable(mapped, regions[i]))
        writer.add_import_provenance(
            source_format=SourceFormat.MINIDUMP,
            tool_name="memdiver",
            orig_file_size=orig_size,
            note=_provenance_note(
                f"Imported from minidump {dmp_path.name}", plan),
            source_path=dmp_path,
        )
        writer.add_end_of_capture()
        writer.write()  # read_chunk runs here: keep the mmap open until done

    return _selection_result(ImportResult(
        source_path=dmp_path,
        output_path=output_path,
        regions_written=sum(plan.keep),
        key_hints_written=0,
        total_bytes=orig_size,
    ), plan, hidden)


@_reject_malformed_dump
def import_raw_dump(
    raw_path: Path,
    output_path: Path,
    pid: int = 0,
    secrets: Optional[List[CryptoSecret]] = None,
    os_type: int = OSType.UNKNOWN,
    arch_type: int = ArchType.UNKNOWN,
    page_size_log2: int = 12,
    selection: Optional[RegionSelection] = None,
) -> ImportResult:
    """Convert a raw .dump file to .msl format.

    A raw dump is one UNCLASSIFIED region, so a *selection* either keeps it
    or (keeping 0 bytes) falls back to importing it with a warning; it is
    recorded in provenance either way. The stored region type is unchanged.

    Streams: the source is mmapped read-only and registered with
    ``MslWriter.add_memory_region_source``, so peak RAM is bounded by the
    writer's stream chunk, not the dump size.
    """
    writer = MslWriter(
        output_path, pid=pid, os_type=os_type, arch_type=arch_type
    )

    # MSL Specification v1.0.0 §5.1 mandates that RegionSize be a multiple
    # of PageSize. Raw .dump files are an arbitrary number of bytes, so we
    # zero-pad up to the next page boundary. Importer-injected padding is
    # transparent because the original size is recorded in the
    # IMPORT_PROVENANCE block's `orig_file_size` field. The padding is
    # synthesised inside read_chunk (a zero-fill run), never by copying the
    # dump into a padded buffer.
    page_size = 1 << page_size_log2
    with MappedFile(raw_path) as mapped:
        orig_size = mapped.size  # what was actually mapped (file may shrink)
        plan = _raw_selection_plan(orig_size, page_size, selection)
        source = _raw_region_source(mapped, page_size)
        region_uuid = writer.add_memory_region_source(
            0, source.length, source, page_size_log2=page_size_log2,
        )

        hints_written = 0
        for secret in secrets or ():
            # Search only the original bytes (key offsets reference the
            # original file, which equals the region offset at VA 0).
            offset = mapped.find(secret.secret_value, 0, orig_size)
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
            note=_provenance_note(f"Imported from {raw_path.name}", plan),
        )
        writer.add_end_of_capture()
        writer.write()  # read_chunk runs here: keep the mmap open until done

    return _selection_result(ImportResult(
        source_path=raw_path,
        output_path=output_path,
        regions_written=1,
        key_hints_written=hints_written,
        total_bytes=orig_size,
    ), plan)


def _raw_selection_plan(size: int, page_size: int,
                        selection: Optional[RegionSelection]
                        ) -> _SelectionPlan:
    """The raw region is always written: kept, or kept by zero-byte fallback."""
    if selection is None:
        return _plan_selection([None], None)
    from .import_preview import raw_region_info

    return _plan_selection([raw_region_info(size, page_size)], selection)


def _raw_region_source(mapped: MappedFile, page_size: int) -> RunSource:
    """Whole file at region offset 0, zero-padded to the next page boundary."""
    builder = RunBuilder()
    builder.add_file(0, mapped.size)
    builder.add_zeros((-mapped.size) % page_size)
    return RunSource(mapped, builder.runs)


# Regioned raw import (.bin + .maps sidecar) -----------------------------------


def _regioned_source(mapped: MappedFile, entry) -> RunSource:
    """An entry's stored bytes, zero-padded to its last CAPTURED page."""
    builder = RunBuilder()
    builder.add_file(entry.bin_offset, entry.stored_len)
    builder.add_zeros(entry.captured_len - entry.stored_len)
    return RunSource(mapped, builder.runs)


def _add_regioned_region(writer: MslWriter, mapped: MappedFile, entry):
    """Register one maps entry as a streamed region; (uuid, source)."""
    _check_region_pages(entry.captured_pages + entry.failed_pages,
                        entry.base_addr, "regioned raw")
    source = _regioned_source(mapped, entry)
    region_uuid = writer.add_memory_region_source(
        entry.base_addr, entry.region_size, source,
        protection=entry.protection, region_type=entry.region_type,
        page_size_log2=entry.page_size_log2, page_states=entry.page_states(),
    )
    return region_uuid, source


def _fallback_to_raw(bin_path: Path, output_path: Path, warning: str,
                     **raw_kwargs) -> ImportResult:
    """Plain raw import of *bin_path*, carrying the unusable-layout warning."""
    logger.warning(warning)
    result = import_raw_dump(bin_path, output_path, **raw_kwargs)
    result.warnings.insert(0, warning)
    return result


@_reject_malformed_dump
def import_regioned_raw(
    bin_path: Path,
    maps_path: Path,
    output_path: Path,
    pid: int = 0,
    secrets: Optional[List[CryptoSecret]] = None,
    selection: Optional[RegionSelection] = None,
    arch_type: int = ArchType.UNKNOWN,
) -> ImportResult:
    """Convert a flat ``.bin`` + ``/proc/<pid>/maps`` sidecar into an .msl.

    One MEMORY_REGION per maps entry at its real VA, typed from the entry's
    path (``[heap]`` -> HEAP, ``[stack]`` -> STACK, libraries -> IMAGE, ...)
    and protected from its ``perm`` column; a truncated last entry keeps its
    listed size with the missing pages FAILED. File-backed entries become a
    Module List Index. Streams through :class:`RunSource` (bounded RAM).
    Every entry's full path column is kept as its mapping name in an
    always-written VAS_MAP (``region_names=1`` in provenance); the header
    ``os_type`` is ANDROID when the names carry Android markers.

    When the sidecar does not describe the bin exactly (see
    :func:`msl.import_regioned.plan_regions`) the dump is imported as one
    plain raw region instead, with a warning on the result.
    """
    from .import_regioned import fallback_warning, plan_regioned_raw

    bin_path, maps_path = Path(bin_path), Path(maps_path)
    plan, reason = plan_regioned_raw(bin_path, maps_path)
    if plan is None:
        return _fallback_to_raw(
            bin_path, output_path, fallback_warning(maps_path, reason),
            pid=pid, secrets=secrets, selection=selection,
            arch_type=arch_type)
    result = _write_regioned(bin_path, output_path, plan, pid, secrets,
                             selection, arch_type)
    from memdiver.core.capture_manifest import manifest_warnings
    # Regions the capture could not take / an unnamed sidecar (dump_driver).
    result.warnings.extend(manifest_warnings(bin_path))
    return result


def _write_regioned(bin_path: Path, output_path: Path, layout, pid: int,
                    secrets, selection, arch_type: int) -> ImportResult:
    """Write a validated :class:`RegionedPlan` (see import_regioned_raw)."""
    writer = MslWriter(output_path, pid=pid,
                       os_type=_os_type_for_platform(layout.platform),
                       arch_type=arch_type)
    plan = _plan_selection(layout.infos(), selection)
    with MappedFile(bin_path) as mapped:
        _add_module_index(writer, layout.file_backed_regions())
        hints_written = 0
        for entry, keep in zip(layout.entries, plan.keep):
            if not keep:
                continue
            region_uuid, source = _add_regioned_region(writer, mapped, entry)
            if secrets:
                hints_written += _add_key_hints(writer, region_uuid, source,
                                                secrets)
        _add_named_vas_map(writer, plan)
        hidden = _count_secrets_only_in_excluded(
            secrets, plan,
            lambda i: _regioned_source(mapped, layout.entries[i]))
        writer.add_import_provenance(
            source_format=SourceFormat.REGIONED_RAW,
            tool_name="memdiver",
            orig_file_size=mapped.size,
            note=_provenance_note(_named_base_note(
                f"Imported from {bin_path.name} with memory map "
                f"{layout.maps_path.name}"), plan),
            source_path=bin_path,
        )
        writer.add_end_of_capture()
        writer.write()  # read_chunk runs here: keep the mmap open until done
        orig_size = mapped.size

    return _selection_result(ImportResult(
        source_path=bin_path,
        output_path=output_path,
        regions_written=sum(plan.keep),
        key_hints_written=hints_written,
        total_bytes=orig_size,
    ), plan, hidden)


@_reject_malformed_dump
def import_msl_passthrough(
    src_path: Path,
    output_path: Path,
    selection: Optional[RegionSelection] = None,
    materialize: bool = False,
    key_material: Optional[dict] = None,
    decrypt_output: bool = False,
) -> ImportResult:
    """Stage an already-MSL container unchanged (or, opt-in, region-filtered).

    A ``.msl`` source needs no conversion: it is already the target format.
    Routing it through :func:`import_raw_dump` (which is what happened before
    this branch existed) wrapped the whole container as ONE opaque region at
    VA 0 — a nested MSL blob, not a memory image, and useless for comparison.

    The source is validated by parsing it, then copied byte-for-byte. An
    encrypted container opened without key material is still a *valid* ``.msl``,
    so it is staged too; only its region walk is skipped (see below).

    Without *materialize*, a *selection* is not applied (the copy stays
    byte-identical); it is recorded on the result with a warning pointing at
    analysis-time filtering / materialize.

    With *materialize* and a selection that excludes something, the output is
    a rewritten copy holding only the selected regions (see
    :mod:`memdiver.msl.materialize`: same ``dump_uuid`` and header flags,
    non-region blocks preserved, key hints remapped or dropped, fresh VAS_MAP,
    provenance appended). An encrypted source needs *key_material*
    (``core.key_material`` dict; request-scoped, never cached or logged) and
    raises ``ValueError`` without it or on a wrong key (nothing is written).
    Its copy is re-encrypted with the same content key / key wrapping and a
    fresh nonce, unless *decrypt_output* opts into a plaintext copy (a warning
    is added to the result).
    *materialize* with no selection, ``all``, a selection that excludes
    nothing, or a zero-byte fallback still copies verbatim.
    """
    from .enums import TagStatus
    from .reader import MslReader

    # Validate BEFORE copying, so a malformed source leaves no partial output
    # and the only exception type that escapes is ValueError (MslParseError) —
    # the parser contract the fuzz suite pins.
    warnings: List[str] = []
    with MslReader(src_path, **(key_material or {})) as reader:
        plan = None
        if materialize and selection is not None and not selection.is_all:
            plan, regions = _msl_materialize_plan(reader, src_path, selection)
            if plan.excluded_count:
                return _materialize_result(reader, src_path, output_path,
                                           plan, regions, decrypt_output)
        if reader.tag_status in (TagStatus.NOT_ENCRYPTED, TagStatus.VALID):
            regions_written = len(reader.collect_regions())
            key_hints_written = len(reader.collect_key_hints())
        else:
            # Blocks live behind AEAD; without key material there is nothing to
            # count. The container is intact and still worth staging, so report
            # zero rather than failing the import.
            logger.info(
                "staging encrypted MSL %s (tag_status=%s); region counts "
                "unavailable without key material",
                src_path.name, reader.tag_status.value,
            )
            regions_written = 0
            key_hints_written = 0
            if key_material and reader.tag_status is TagStatus.CORRUPTED:
                warnings.append(_WRONG_KEY_WARNING)
        if decrypt_output and reader.file_header.encrypted:
            warnings.append(_DECRYPT_OUTPUT_IGNORED)

    _copy_msl_verbatim(src_path, output_path)
    result = ImportResult(
        source_path=src_path,
        output_path=output_path,
        regions_written=regions_written,
        key_hints_written=key_hints_written,
        total_bytes=src_path.stat().st_size,
    )
    for warning in warnings:
        logger.warning(warning)
    result.warnings.extend(warnings)
    if plan is not None:
        return _selection_result(result, plan)
    if selection is not None and not materialize:
        logger.warning(_MSL_SELECTION_WARNING)
        result.selection = selection.to_note()
        result.warnings.append(_MSL_SELECTION_WARNING)
    return result


def _copy_msl_verbatim(src_path: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Guard the degenerate in-place import: copyfile() truncates its destination
    # first, so src == dst would zero the very file being imported.
    if not (output_path.exists() and output_path.samefile(src_path)):
        # copyfile(), not copy2(): the destination wants a fresh mtime, which is
        # what the API's LRU quota prune orders on.
        shutil.copyfile(src_path, output_path)


def _msl_materialize_plan(reader, src_path: Path,
                          selection: RegionSelection):
    """(selection plan, stored regions) for materializing an open ``.msl``."""
    from .import_preview import msl_source_format
    from .materialize import require_decrypted, stored_regions

    require_decrypted(reader, src_path.name)
    regions = stored_regions(reader, msl_source_format(reader))
    return _plan_selection([r.info for r in regions], selection), regions


def _materialize_result(reader, src_path: Path, output_path: Path,
                        plan: _SelectionPlan, regions,
                        decrypt_output: bool = False) -> ImportResult:
    """Write the region-filtered copy and describe it as an ImportResult."""
    from .materialize import materialize_msl

    stats = materialize_msl(reader, src_path, output_path, regions,
                            plan.keep, _provenance_note("", plan),
                            decrypt_output=decrypt_output)
    result = _selection_result(ImportResult(
        source_path=src_path,
        output_path=output_path,
        regions_written=stats.regions_written,
        key_hints_written=stats.key_hints_written,
        total_bytes=src_path.stat().st_size,
    ), plan)
    result.materialized = True
    result.dropped_key_hints = stats.dropped_key_hints
    if reader.file_header.encrypted:
        result.decrypted_output = decrypt_output
        result.reencrypted = not decrypt_output
        if decrypt_output:
            logger.warning(DECRYPTED_OUTPUT_WARNING)
            result.warnings.append(DECRYPTED_OUTPUT_WARNING)
    if stats.dropped_key_hints:
        warning = (f"{stats.dropped_key_hints} key hint(s) referenced "
                   f"excluded regions and were dropped from the "
                   f"materialized copy")
        logger.warning(warning)
        result.warnings.append(warning)
    return result


RUN_DIRECTORY_DUMP_GLOBS = ("*.dump", "*.dmp", "*.core")
# Regioned raw dumps (flat .bin + .maps sidecar) the dataset corpus produces;
# always picked up (core.discovery.DATASET_DUMP_SUFFIXES knows them too).
RUN_DIRECTORY_REGIONED_GLOBS = ("*.gdb_raw.bin", "*.lldb_raw.bin")
# Any other .bin is only a dump when a memory map describes it.
RUN_DIRECTORY_BIN_GLOB = "*.bin"
#: Optional run ``meta.json`` key naming a .maps file (run-dir relative).
RUN_META_MAPS_KEY = "maps"


def run_directory_declared_maps(run_dir: Path) -> Optional[Path]:
    """The ``maps`` file a run's ``meta.json`` declares, if it exists.

    Resolved through :func:`core.dataset_metadata.resolve_declared_subpath`,
    so an absolute or escaping declaration is rejected (logged, ignored).
    """
    import json

    from memdiver.core.dataset_metadata import (META_FILENAME,
                                                resolve_declared_subpath)

    meta_path = Path(run_dir) / META_FILENAME
    try:
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    declared = payload.get(RUN_META_MAPS_KEY) if isinstance(payload, dict) \
        else None
    if not isinstance(declared, str):
        return None
    resolved = resolve_declared_subpath(Path(run_dir), declared,
                                        kind=RUN_META_MAPS_KEY)
    return resolved if resolved is not None and resolved.is_file() else None


def _has_memory_map(bin_path: Path, declared_maps: Optional[Path]) -> bool:
    from memdiver.core.regioned_layout import find_maps_sidecar

    return declared_maps is not None or find_maps_sidecar(bin_path) is not None


def run_directory_dump_files(run_dir: Path) -> List[Path]:
    """The dump files :func:`import_run_directory` imports, in import order.

    ``.dump`` / ``.dmp`` / ``.core``, gdb_raw / lldb_raw ``.bin`` files, and
    any other ``.bin`` that has a ``.maps`` sidecar (or a ``meta.json``
    ``maps`` declaration).
    """
    run_dir = Path(run_dir)
    found = set()
    for pattern in RUN_DIRECTORY_DUMP_GLOBS + RUN_DIRECTORY_REGIONED_GLOBS:
        found |= set(run_dir.glob(pattern))
    declared = run_directory_declared_maps(run_dir)
    found |= {p for p in run_dir.glob(RUN_DIRECTORY_BIN_GLOB)
              if _has_memory_map(p, declared)}
    return sorted(p for p in found if p.is_file())


def run_directory_maps_for(run_dir: Path, dump_file: Path) -> Optional[Path]:
    """Explicit maps :func:`import_run_directory` passes for *dump_file*.

    The run ``meta.json`` ``maps`` declaration, for a raw file without its own
    sidecar (a sidecar is auto-detected by :func:`import_dump` anyway).
    """
    return _run_file_maps(Path(dump_file), run_directory_declared_maps(run_dir))


def _run_file_maps(dump_file: Path,
                   declared: Optional[Path]) -> Optional[Path]:
    """Declared maps for a raw run file lacking its own sidecar, else None."""
    from memdiver.core.regioned_layout import find_maps_sidecar

    if declared is None or find_maps_sidecar(dump_file) is not None:
        return None
    if dump_file.suffix.lower() not in (".bin", ".dump"):
        return None  # .dmp / .core carry their own layout
    return declared


def import_run_directory(
    run_dir: Path,
    output_dir: Path,
    keylog_filename: str = "keylog.csv",
    selection: Optional[RegionSelection] = None,
    materialize: bool = False,
    key_material: Optional[dict] = None,
    decrypt_output: bool = False,
) -> List[ImportResult]:
    """Import all dump files in a run directory to .msl.

    See :func:`run_directory_dump_files` for which files count; raw files
    with a ``.maps`` sidecar (or the run ``meta.json`` ``maps`` key) are
    split into real regions.

    Each file is routed through :func:`import_dump`, which sniffs the format
    and dispatches to the raw, ELF-core, or minidump importer as appropriate.
    *materialize*, *key_material* and *decrypt_output* only affect ``.msl``
    inputs (see import_msl_passthrough); one key material is tried for every
    ``.msl`` in the run.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []

    secrets = None
    keylog_path = run_dir / keylog_filename
    if keylog_path.is_file():
        from memdiver.core.keylog import KeylogParser

        secrets = KeylogParser().parse(keylog_path)

    declared_maps = run_directory_declared_maps(run_dir)
    for dump_file in run_directory_dump_files(run_dir):
        out_path = output_dir / (dump_file.name + ".msl")
        result = import_dump(dump_file, out_path, secrets=secrets,
                             selection=selection, materialize=materialize,
                             key_material=key_material,
                             decrypt_output=decrypt_output,
                             maps_path=_run_file_maps(dump_file,
                                                      declared_maps))
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
    selection: Optional[RegionSelection] = None,
    materialize: bool = False,
    key_material: Optional[dict] = None,
    decrypt_output: bool = False,
    maps_path: Optional[Path] = None,
    **kwargs,
) -> ImportResult:
    """Import any supported dump into .msl, dispatching on detected format.

    Routes already-MSL containers to :func:`import_msl_passthrough` (a
    validated byte-for-byte copy — no conversion), minidumps to
    :func:`import_minidump`, ELF ET_CORE files to :func:`import_elf_core`
    (falling back to raw if the ELF is not a parseable core), and everything
    else to :func:`import_raw_dump`. The raw path is preserved unchanged so
    plain .dump imports are a no-op regression.

    *selection* (``None`` = import everything, byte-identical to before)
    restricts conversion imports to the regions it includes. For ``.msl``
    input it is only applied when *materialize* is True (otherwise the copy
    stays verbatim); other formats ignore *materialize*. *key_material* and
    *decrypt_output* only apply to encrypted ``.msl`` input.

    A raw input with a memory map — *maps_path*, or else an auto-detected
    ``.maps`` sidecar (``foo.gdb_raw.bin`` -> ``foo.gdb_raw.maps``, else
    ``foo.maps``) — goes to :func:`import_regioned_raw` and is split into
    real regions. Formats with their own layout ignore *maps_path* (with a
    warning on the result).
    """
    src_path = Path(src_path)
    with open(src_path, "rb") as fh:
        head = fh.read(512)
    fmt = detect_format(head)

    if fmt == "msl":
        # Already the target format — stage it, do not re-wrap it.
        return _ignore_maps_for_native(src_path, maps_path, import_msl_passthrough(
            src_path, output_path, selection=selection,
            materialize=materialize, key_material=key_material,
            decrypt_output=decrypt_output))

    if fmt == "minidump":
        return _ignore_maps_for_native(src_path, maps_path, import_minidump(
            src_path, output_path, pid=pid, secrets=secrets,
            selection=selection,
        ))

    if fmt in ("elf64", "elf32", "elf"):
        if _is_et_core(head):
            try:
                return _ignore_maps_for_native(
                    src_path, maps_path, import_elf_core(
                        src_path, output_path, secrets=secrets,
                        selection=selection,
                    ))
            except ValueError as exc:
                logger.info(
                    "ELF ET_CORE parse failed (%s); falling back to raw "
                    "import", exc,
                )
        # Not a core (or unparseable) => raw fallback below.

    return _import_raw_input(src_path, output_path, pid, secrets, selection,
                             maps_path, kwargs)


def _ignore_maps_for_native(src_path: Path, maps_path: Optional[Path],
                            result: ImportResult) -> ImportResult:
    """Warn when a maps file was given for a format with its own layout."""
    if maps_path is not None:
        warning = (f"maps file {Path(maps_path).name} ignored: "
                   f"{Path(src_path).name} carries its own memory layout")
        logger.warning(warning)
        result.warnings.append(warning)
    return result


def _import_raw_input(src_path: Path, output_path: Path, pid: int, secrets,
                      selection, maps_path: Optional[Path],
                      kwargs: dict) -> ImportResult:
    """Raw input: regioned when a memory map is known, else one raw region."""
    from .import_regioned import resolve_maps_path

    resolved = resolve_maps_path(src_path, maps_path)
    if resolved is not None:
        return import_regioned_raw(
            src_path, resolved, output_path, pid=pid, secrets=secrets,
            selection=selection,
            **{k: v for k, v in kwargs.items() if k == "arch_type"})
    raw_kwargs = {
        k: v for k, v in kwargs.items()
        if k in ("os_type", "arch_type", "page_size_log2")
    }
    return import_raw_dump(
        src_path, output_path, pid=pid, secrets=secrets,
        selection=selection, **raw_kwargs,
    )
