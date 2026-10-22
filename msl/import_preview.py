"""Metadata-only import preview: which regions would an import emit?

:func:`preview_import` sniffs a source exactly like
:func:`msl.importer.import_dump` and lists the regions the matching importer
would write — base, size, protection, stored region type, selection category,
module path and captured bytes — without reading any page data. It reuses
the importer's own pure helpers (page planning, protection/type mapping) so
the preview cannot drift from what an import actually stores.

Limits (documented, intentional):

* ``.msl`` regions are decoded from their header + page map only; compressed
  region blocks are decompressed one at a time (no random access) and
  dropped. An encrypted ``.msl`` opened without key material yields no
  regions and a note explaining why.
* ``.msl`` sources carry no thread stack ranges here, so STACK there comes
  only from a stored ``RegionType.STACK``.
* ``.msl`` files whose IMPORT_PROVENANCE says they came from a raw dump are
  UNCLASSIFIED throughout (their stored ANONYMOUS type is a writer default,
  not an observation); see :func:`region_select.classify_stored`.
* Minidump regions carry no module path (the reader parses no module list).
* Mapping names (``RegionInfo.name``) refine categories (Android heaps,
  stacks and the ``runtime`` category, see :mod:`msl.region_names`). Raw
  inputs take them from the maps path column, ELF cores from NT_FILE; an
  ``.msl`` only when :func:`msl_classification_context` trusts its VAS_MAP
  names, so files written before names were stored classify unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from memdiver.core.binary_formats.elf_core_reader import ElfCoreReader
from memdiver.core.binary_formats.minidump_reader import (
    MEM_COMMIT, MinidumpReader)
from memdiver.core.format_detect import detect_format

from .enums import BlockType, HeaderFlag, OSType, Protection, RegionType, TagStatus
from .importer import (_align_down, _align_up, _is_et_core, _map_protect,
                       _map_type, _plan_segment_pages, _protection_from_flags,
                       _region_type_for_segment, _stored_segment_length)
from .page_map import count_captured_pages
from .region_names import MappingNameIndex, platform_for_names
from .region_select import (DEFAULT_INTERACTIVE_CATEGORIES, RegionCategory,
                            RegionInfo, RegionSelection, StackRange, classify,
                            classify_stored, parse_provenance_note,
                            stored_region_type)

_RAW_PAGE_SIZE = 4096        # import_raw_dump default page_size_log2=12
_MINIDUMP_PAGE_SIZE = 4096   # import_minidump default page_size_log2=12
_ELF_FORMATS = ("elf64", "elf32", "elf")

LAYOUT_NATIVE = "native"
LAYOUT_MAPS = "maps"
LAYOUT_NONE = "none"
NO_LAYOUT_NOTE = ("layout=none: raw dump without a memory map; regions cannot "
                  "be categorised. Provide a .maps sidecar (same name) to "
                  "split it into regions.")

# (base, size, protection, region_type, captured_bytes, module_path)
_RawRegion = Tuple[int, int, int, int, int, Optional[str]]

# Where ImportPreview.platform came from.
PLATFORM_SOURCE_NAMES = "mapping_names"   # Android markers in mapping names
PLATFORM_SOURCE_HEADER = "header"         # .msl file header os_type
PLATFORM_SOURCE_FORMAT = "format"         # implied by the source format


@dataclass
class ImportPreview:
    """Regions a given source would import as, plus selection totals."""

    format: str
    is_msl: bool
    regions: List[RegionInfo]
    notes: List[str] = field(default_factory=list)
    # .msl only: the container is AEAD-encrypted / it was opened (tag verified)
    # with the key material the caller supplied.
    encrypted: bool = False
    decrypted: bool = False
    # Where the region layout came from: "native" (the format records it),
    # "maps" (raw bytes + a .maps sidecar), "none" (raw: one VA-0 region whose
    # categories cannot be separated). Machine-readable twin of the notes.
    layout: str = LAYOUT_NATIVE
    maps_path: Optional[str] = None
    # Target platform ("android", "linux", "windows", ...) and how it was
    # determined (PLATFORM_SOURCE_*); None when unknown (plain raw dump).
    platform: Optional[str] = None
    platform_source: Optional[str] = None

    @property
    def runtime_count(self) -> int:
        """Regions classified RUNTIME (by mapping name)."""
        return sum(1 for r in self.regions
                   if r.category is RegionCategory.RUNTIME)

    @property
    def runtime_bytes(self) -> int:
        """Captured bytes of the RUNTIME regions."""
        return sum(r.captured_bytes for r in self.regions
                   if r.category is RegionCategory.RUNTIME)

    @property
    def totals(self) -> Dict[RegionCategory, Tuple[int, int]]:
        """Per category: (region count, captured bytes)."""
        totals: Dict[RegionCategory, Tuple[int, int]] = {}
        for region in self.regions:
            count, size = totals.get(region.category, (0, 0))
            totals[region.category] = (count + 1, size + region.captured_bytes)
        return totals

    def summarize(self, selection: Optional[RegionSelection]
                  ) -> Tuple[int, int, int, int]:
        """(included_count, included_bytes, excluded_count, excluded_bytes)."""
        selection = selection or RegionSelection.all()
        inc = [r for r in self.regions if selection.includes(r)]
        exc = [r for r in self.regions if not selection.includes(r)]
        return (len(inc), sum(r.captured_bytes for r in inc),
                len(exc), sum(r.captured_bytes for r in exc))

    def to_dict(self, selection: Optional[RegionSelection] = None) -> dict:
        """JSON-friendly form (category keys are their string values)."""
        inc_n, inc_b, exc_n, exc_b = self.summarize(selection)
        return {
            "format": self.format,
            "is_msl": self.is_msl,
            "regions": [r.to_dict() for r in self.regions],
            "totals": {cat.value: {"count": n, "bytes": b}
                       for cat, (n, b) in sorted(self.totals.items(),
                                                 key=lambda kv: kv[0].value)},
            "summary": {"included_count": inc_n, "included_bytes": inc_b,
                        "excluded_count": exc_n, "excluded_bytes": exc_b},
            "notes": list(self.notes),
            "encrypted": self.encrypted,
            "decrypted": self.decrypted,
            "layout": self.layout,
            "maps_path": self.maps_path,
            "platform": self.platform,
            "platform_source": self.platform_source,
            "runtime_count": self.runtime_count,
            "runtime_bytes": self.runtime_bytes,
        }


# -- shared -------------------------------------------------------------------


def _build_info(region: _RawRegion,
                stack_ranges: Sequence[StackRange]) -> RegionInfo:
    """Classify one region; ``region_type`` is the type the import stores.

    The module path doubles as the mapping name (ELF NT_FILE). The stored
    type is derived from the name-free category, so a name never changes
    what is written (alignment keys depend on it).
    """
    base, size, prot, rtype, captured, path = region
    type_category = classify(rtype, prot, base, size, stack_ranges, path)
    category = classify(rtype, prot, base, size, stack_ranges, path,
                        name=path)
    return RegionInfo(base, size, prot,
                      stored_region_type(rtype, type_category),
                      category, path, captured, name=path)


def runtime_note(preview: "ImportPreview") -> Optional[str]:
    """English note on what the default selection drops (RUNTIME), if any."""
    count = preview.runtime_count
    if not count or RegionCategory.RUNTIME in DEFAULT_INTERACTIVE_CATEGORIES:
        return None
    platform = "Android " if preview.platform == "android" else ""
    return (f"{count} region(s) ({preview.runtime_bytes} bytes) classified "
            f"'runtime' by mapping name ({platform}runtime: zygote / boot "
            f"image ART spaces, GC metadata, JIT caches, kernel and device "
            f"mappings); the default selection (heap, stack, unclassified) "
            f"excludes them")


def _platform_fields(platform: Tuple[Optional[str], Optional[str]]) -> dict:
    return {"platform": platform[0], "platform_source": platform[1]}


def _finish(preview: "ImportPreview") -> "ImportPreview":
    """Append the runtime note (see :func:`runtime_note`) and return."""
    note = runtime_note(preview)
    if note:
        preview.notes.append(note)
    return preview


def _build_infos(raw: Iterable[_RawRegion],
                 stack_ranges: Sequence[StackRange]) -> List[RegionInfo]:
    return [_build_info(region, stack_ranges) for region in raw]


def _module_for(base: int, size: int,
                modules: Sequence[Tuple[int, int, str]]) -> Optional[str]:
    """Path of the first module whose [start, end) overlaps the region."""
    end = base + size
    for start, stop, path in modules:
        if path and start < end and base < stop:
            return path
    return None


# -- raw ----------------------------------------------------------------------


def raw_region_info(size: int, page_size: int = _RAW_PAGE_SIZE) -> RegionInfo:
    """The single VA-0 region a raw import emits, as a selection sees it.

    A raw dump carries no layout metadata, so its region is UNCLASSIFIED
    regardless of the (writer-default) region type actually stored.
    """
    padded = size + (-size) % page_size
    prot = int(Protection.READ | Protection.WRITE)
    return RegionInfo(0, padded, prot, int(RegionType.UNKNOWN),
                      RegionCategory.UNCLASSIFIED, None, padded)


def _preview_plain_raw(path: Path, fmt: str,
                       notes: Sequence[str] = ()) -> ImportPreview:
    region = raw_region_info(path.stat().st_size)
    return ImportPreview(format=fmt, is_msl=False, regions=[region],
                         notes=[*notes, NO_LAYOUT_NOTE], layout=LAYOUT_NONE)


def _preview_raw(path: Path, fmt: str,
                 maps_path: Optional[Path] = None) -> ImportPreview:
    """Raw input: regioned when a memory map is known (import_dump rule)."""
    from .import_regioned import (fallback_warning, plan_regioned_raw,
                                  resolve_maps_path)

    from memdiver.core.capture_manifest import manifest_warnings

    # Gaps / unnamed sidecar recorded by the capture (core.dump_driver).
    capture_notes = manifest_warnings(path)
    resolved = resolve_maps_path(path, maps_path)
    if resolved is None:
        return _preview_plain_raw(path, fmt, capture_notes)
    plan, reason = plan_regioned_raw(path, resolved)
    if plan is None:
        return _preview_plain_raw(path, fmt,
                                  [fallback_warning(resolved, reason),
                                   *capture_notes])
    return _finish(ImportPreview(
        format=fmt, is_msl=False, regions=plan.infos(),
        notes=[f"layout=maps: {resolved.name}", *capture_notes],
        layout=LAYOUT_MAPS,
        maps_path=str(resolved),
        **_platform_fields(names_platform(e.region.path
                                          for e in plan.entries))))


# -- ELF core -----------------------------------------------------------------


def _elf_regions(reader: ElfCoreReader,
                 page_size_log2: Optional[int] = None) -> List[_RawRegion]:
    info = reader.info
    mappings = [(m.start, m.end, m.path) for m in info.file_mappings]
    regions = []
    for seg in info.segments:
        plan = _plan_segment_pages(seg, info, page_size_log2,
                                   _stored_segment_length(reader, seg))
        pages = plan.captured_pages + plan.failed_pages
        size = pages << plan.page_size_log2
        regions.append((
            seg.vaddr, size, _protection_from_flags(seg.flags),
            _region_type_for_segment(seg, info.file_mappings),
            plan.captured_pages << plan.page_size_log2,
            _module_for(seg.vaddr, size, mappings),
        ))
    return regions


def _elf_stack_ranges(regions: Sequence[_RawRegion],
                      sps: Iterable[Optional[int]]) -> List[StackRange]:
    """The region containing each thread's saved SP is that thread's stack."""
    ranges = []
    for sp in sps:
        if sp is None:
            continue
        ranges.extend((base, size) for base, size, *_ in regions
                      if base <= sp < base + size)
    return ranges


def elf_region_infos(reader: ElfCoreReader,
                     page_size_log2: Optional[int] = None) -> List[RegionInfo]:
    """One :class:`RegionInfo` per PT_LOAD segment, in segment order.

    Shared by the preview and :func:`msl.importer.import_elf_core` so both
    classify with identical inputs (stack = region containing a thread SP).
    """
    regions = _elf_regions(reader, page_size_log2)
    stacks = _elf_stack_ranges(regions, [t.sp for t in reader.info.threads])
    return _build_infos(regions, stacks)


def names_platform(names: Iterable[Optional[str]]) -> Tuple[str, str]:
    """(platform, platform_source) of a Linux-family source by its names.

    ``("android", "mapping_names")`` when a name carries an Android marker,
    else ``("linux", "format")`` (ELF cores / maps listings are Linux-style).
    """
    if platform_for_names(names, default=None) is None:
        return "linux", PLATFORM_SOURCE_FORMAT
    return "android", PLATFORM_SOURCE_NAMES


def elf_platform(reader: ElfCoreReader) -> Tuple[str, str]:
    """(platform, platform_source) of an ELF core from its NT_FILE paths."""
    return names_platform(m.path for m in reader.info.file_mappings)


def _preview_elf(path: Path, fmt: str) -> ImportPreview:
    with ElfCoreReader(path) as reader:
        infos = elf_region_infos(reader)
        platform, source = elf_platform(reader)
    return _finish(ImportPreview(format="elf_core", is_msl=False,
                                 regions=infos, platform=platform,
                                 platform_source=source))


# -- minidump -----------------------------------------------------------------


def _window(start: int, end: int, page: int) -> Tuple[int, int]:
    """Page-aligned [base, end) enclosing [start, end) (importer rule)."""
    return _align_down(start, page), _align_up(end, page)


def _captured_pages(base: int, end: int, spans, consumed: List[bool],
                    page: int) -> int:
    """Pages of [base, end) a descriptor span backs; marks spans consumed."""
    pages = set()
    for idx, (s_start, s_end) in enumerate(spans):
        lo, hi = max(s_start, base), min(s_end, end)
        if lo >= hi:
            continue
        consumed[idx] = True
        pages.update(range((lo - base) // page, (hi - 1 - base) // page + 1))
    return len(pages)


def _committed_regions(info, spans, consumed, page) -> List[_RawRegion]:
    regions = []
    for mi in sorted(info.memory_info, key=lambda m: m.base):
        if mi.state != MEM_COMMIT:
            continue  # free/reserved/unknown: importer emits no region
        base, end = _window(mi.base, mi.base + mi.region_size, page)
        captured = _captured_pages(base, end, spans, consumed, page) * page
        regions.append((base, end - base,
                        _map_protect(mi.protect or mi.alloc_protect),
                        _map_type(mi.type), captured, None))
    return regions


def _span_regions(spans, consumed, page) -> List[_RawRegion]:
    """Safety-net / fallback all-CAPTURED spans (importer: RW, UNKNOWN)."""
    prot = int(Protection.READ | Protection.WRITE)
    regions = []
    for idx, (s_start, s_end) in enumerate(spans):
        if consumed[idx]:
            continue
        base, end = _window(s_start, s_end, page)
        regions.append((base, end - base, prot, int(RegionType.UNKNOWN),
                        end - base, None))
    return regions


def _minidump_regions(info, page: int) -> List[_RawRegion]:
    """Metadata twin of ``importer._derive_regions`` (no bytes read)."""
    spans = [(d.start, d.start + d.size)
             for d in sorted(info.memory_descriptors, key=lambda d: d.start)]
    consumed = [False] * len(spans)
    regions = []
    if info.has_memory_info_list:
        regions = _committed_regions(info, spans, consumed, page)
    return regions + _span_regions(spans, consumed, page)


def minidump_stack_ranges(info) -> List[StackRange]:
    """Thread stack ranges recorded in a minidump's ThreadList."""
    return [(t.stack_start, t.stack_size) for t in info.threads
            if t.stack_size]


def region_infos(regions: Iterable[_RawRegion],
                 stack_ranges: Sequence[StackRange]) -> List[RegionInfo]:
    """Classify ``(base, size, prot, type, captured, path)`` tuples."""
    return _build_infos(regions, stack_ranges)


def _preview_minidump(path: Path, fmt: str) -> ImportPreview:
    with MinidumpReader(path) as reader:
        info = reader.info
        regions = _minidump_regions(info, _MINIDUMP_PAGE_SIZE)
        stacks = minidump_stack_ranges(info)
    return ImportPreview(format=fmt, is_msl=False,
                         regions=_build_infos(regions, stacks),
                         platform="windows",
                         platform_source=PLATFORM_SOURCE_FORMAT)


# -- .msl ---------------------------------------------------------------------


def _msl_modules(reader) -> List[Tuple[int, int, str]]:
    from .decoders import decode_module_entry, decode_module_list_index

    modules = []
    for hdr, payload in reader.iter_blocks_of_type(
            BlockType.MODULE_ENTRY, BlockType.MODULE_LIST_INDEX):
        try:
            if hdr.block_type == BlockType.MODULE_ENTRY:
                entries = [decode_module_entry(hdr, payload, reader._byte_order)]
            else:
                entries = decode_module_list_index(
                    hdr, payload, reader._byte_order).entries
        except (ValueError, IndexError, OverflowError):
            continue  # best-effort metadata only
        modules.extend((e.base_addr, e.base_addr + e.module_size, e.path)
                       for e in entries)
    return modules


def _msl_regions(reader) -> List[_RawRegion]:
    modules = _msl_modules(reader)
    return [
        (r.base_addr, r.region_size, r.protection, r.region_type,
         count_captured_pages(r.page_intervals) * r.page_size,
         _module_for(r.base_addr, r.region_size, modules))
        for r in reader.iter_region_headers()
    ]


def msl_source_format(reader) -> Optional[int]:
    """IMPORT_PROVENANCE ``source_format`` of an open ``.msl`` (or None).

    Reads only the (small) provenance block, never region payloads.
    """
    from .decoders import decode_import_provenance

    for hdr, payload in reader.iter_blocks_of_type(
            BlockType.IMPORT_PROVENANCE):
        try:
            return decode_import_provenance(
                hdr, payload, reader._byte_order).source_format
        except (ValueError, IndexError, OverflowError):
            return None  # best-effort metadata only
    return None


def msl_classification_context(reader) -> Tuple[
        Optional[int], Optional[MappingNameIndex], bool]:
    """``(source_format, names_index, live_named)`` of an open ``.msl``.

    Trust rule for VAS_MAP mapping names (``names_index`` is ``None`` when
    they must not be used, which keeps older files' classification
    byte-identical):

    * with IMPORT_PROVENANCE, names are trusted only when its note carries
      the ``region_names=1`` marker (written by MemDiver's ELF / regioned
      importers and propagated by materialize);
    * without provenance and with the IMPORTED header flag clear (a live
      memslicer capture), names are trusted whenever a VAS_MAP exists.

    ``live_named`` is True for a trusted, non-IMPORTED (live) file: its
    stored types come from name rules and alignment folds them back
    (:func:`region_names.legacy_live_region_type`). Reads only provenance
    and VAS_MAP payloads, never region payloads.
    """
    from .decoders import decode_import_provenance, decode_vas_map

    provenance, entries, has_provenance = None, [], False
    for hdr, payload in reader.iter_blocks_of_type(
            BlockType.IMPORT_PROVENANCE, BlockType.VAS_MAP):
        try:
            if hdr.block_type == BlockType.VAS_MAP:
                entries.extend(decode_vas_map(hdr, payload,
                                              reader._byte_order).entries)
            elif not has_provenance:
                has_provenance = True
                provenance = decode_import_provenance(hdr, payload,
                                                      reader._byte_order)
        except (ValueError, IndexError, OverflowError):
            continue  # best-effort metadata only
    imported = bool(reader.file_header.flags & HeaderFlag.IMPORTED)
    if has_provenance:
        trusted = provenance is not None and \
            parse_provenance_note(provenance.note).region_names
    else:
        trusted = not imported and bool(entries)
    source_format = provenance.source_format if provenance else None
    names = MappingNameIndex.from_vas_entries(entries) if trusted else None
    return source_format, names, bool(trusted and not imported)


def msl_region_infos(regions: Iterable[_RawRegion],
                     source_format: Optional[int],
                     names: Optional[MappingNameIndex] = None
                     ) -> List[RegionInfo]:
    """Classify stored ``.msl`` regions, honouring their import provenance.

    Single home of the stored-region rule (see
    :func:`region_select.classify_stored`), shared by the preview, the
    analysis-time view filter and materialize. *names* (trusted VAS_MAP
    names, :func:`msl_classification_context`) sets ``RegionInfo.name``
    and lets the name rules refine the category.
    """
    infos = []
    for base, size, prot, rtype, captured, path in regions:
        name = names.name_for(base) if names is not None else None
        name = name or None
        infos.append(RegionInfo(
            base, size, prot, rtype,
            classify_stored(rtype, prot, base, size, (), path,
                            source_format=source_format, name=name),
            path, captured, name=name))
    return infos


def msl_platform(reader) -> Tuple[Optional[str], Optional[str]]:
    """(platform, platform_source) from the ``.msl`` header ``os_type``."""
    try:
        os_type = OSType(reader.file_header.os_type)
    except ValueError:
        return None, None
    if os_type is OSType.UNKNOWN:
        return None, None
    return os_type.name.lower(), PLATFORM_SOURCE_HEADER


def _preview_msl(path: Path, fmt: str,
                 key_material: Optional[dict] = None) -> ImportPreview:
    from .reader import MslReader

    notes = []
    with MslReader(path, **(key_material or {})) as reader:
        status = reader.tag_status
        if status is TagStatus.CORRUPTED:
            notes.append("encrypted container: decryption failed (wrong key "
                         "material or tampered file); regions unavailable")
        elif status not in (TagStatus.NOT_ENCRYPTED, TagStatus.VALID):
            notes.append(f"encrypted container (tag_status="
                         f"{status.value}); regions unavailable "
                         f"without key material")
        regions = _msl_regions(reader)
        source_format, names, _ = msl_classification_context(reader)
        platform, platform_source = msl_platform(reader)
    return _finish(ImportPreview(
        format=fmt, is_msl=True,
        regions=msl_region_infos(regions, source_format, names),
        notes=notes, encrypted=status is not TagStatus.NOT_ENCRYPTED,
        decrypted=status is TagStatus.VALID, platform=platform,
        platform_source=platform_source))


# -- dispatch -----------------------------------------------------------------


def preview_import(path, key_material: Optional[dict] = None,
                   maps_path=None) -> ImportPreview:
    """Metadata-only preview of what :func:`import_dump` would emit.

    *key_material* (``core.key_material`` dict) opens an encrypted ``.msl`` so
    its regions can be listed; other formats ignore it. Never cached/logged.
    *maps_path* (or an auto-detected ``.maps`` sidecar) splits a raw input
    into its real regions, exactly as :func:`import_dump` would.
    """
    preview = _preview_by_format(path, key_material, maps_path)
    if maps_path is not None and preview.layout == LAYOUT_NATIVE:
        preview.notes.append(f"maps file {Path(maps_path).name} ignored: the "
                             f"source carries its own memory layout")
    return preview


def _preview_by_format(path, key_material: Optional[dict],
                       maps_path) -> ImportPreview:
    path = Path(path)
    with open(path, "rb") as fh:
        head = fh.read(512)
    fmt = detect_format(head)
    if fmt == "msl":
        return _preview_msl(path, fmt, key_material)
    if fmt == "minidump":
        return _preview_minidump(path, fmt)
    if fmt in _ELF_FORMATS and _is_et_core(head):
        try:
            return _preview_elf(path, fmt)
        except ValueError:
            pass  # import_dump falls back to raw for an unparseable core
    return _preview_raw(path, fmt or "raw",
                        Path(maps_path) if maps_path is not None else None)
