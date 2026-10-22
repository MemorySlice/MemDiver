"""Human-readable region tables and import summaries for ``memdiver import``.

Pure formatting: every function returns lines (or writes to a given stream),
so the interactive prompt, ``--list-regions`` and the post-import summary all
render categories the same way.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, TextIO

from memdiver.msl.import_preview import ImportPreview
from memdiver.msl.region_select import RegionCategory, RegionSelection
from memdiver.ui.components.html_builder import format_size

#: Display order of categories (numbering in the prompt follows it).
CATEGORY_ORDER: Sequence[RegionCategory] = tuple(RegionCategory)

CATEGORY_DESCRIPTIONS: Dict[RegionCategory, str] = {
    RegionCategory.HEAP: "private anonymous memory (malloc arenas, heap segments)",
    RegionCategory.STACK: "thread stacks",
    RegionCategory.IMAGE_CODE: "read-only/executable pages of loaded images",
    RegionCategory.IMAGE_DATA: "writable file-backed pages (.data/.bss of images)",
    RegionCategory.MAPPED_FILE: "other read-only file mappings",
    RegionCategory.SHARED: "shared memory",
    RegionCategory.UNCLASSIFIED: "no layout metadata (raw dumps, unknown types)",
    RegionCategory.RUNTIME: ("by mapping name: Android zygote/boot-image/ART "
                             "metadata, JIT caches, kernel/device maps "
                             "([vdso], [vvar], /dev/*); not preselected"),
}

_MARK_SELECTED = "[x]"
_MARK_UNSELECTED = "[ ]"


def _category_line(index: int, category: RegionCategory, count: int,
                   size: int, marker: Optional[str]) -> str:
    prefix = f"{marker} " if marker is not None else ""
    noun = "region " if count == 1 else "regions"
    return (f"  {prefix}{index}) {category.value:<13} {count:>6} {noun} "
            f"{format_size(size):>10}  {CATEGORY_DESCRIPTIONS[category]}")


def category_table(preview: ImportPreview,
                   selected: Optional[RegionSelection] = None) -> List[str]:
    """One numbered line per category with region count and captured bytes.

    With *selected*, each line starts with ``[x]`` / ``[ ]``.
    """
    totals = preview.totals
    lines = []
    for index, category in enumerate(CATEGORY_ORDER, start=1):
        count, size = totals.get(category, (0, 0))
        marker = None
        if selected is not None:
            marker = (_MARK_SELECTED if category in selected.categories
                      else _MARK_UNSELECTED)
        lines.append(_category_line(index, category, count, size, marker))
    return lines


def region_list(preview: ImportPreview,
                selection: Optional[RegionSelection] = None) -> List[str]:
    """One line per region (base, size, category, kept/excluded, module)."""
    selection = selection or RegionSelection.all()
    lines = []
    for region in sorted(preview.regions, key=lambda r: r.base_addr):
        state = "keep" if selection.includes(region) else "drop"
        module = f"  {region.module_path}" if region.module_path else ""
        line = (f"  {state} 0x{region.base_addr:016x} "
                f"{format_size(region.captured_bytes):>10} "
                f"{region.category.value:<13}{module}")
        lines.append(line.rstrip())
    return lines


def platform_line(preview: ImportPreview) -> Optional[str]:
    """``platform: <platform> (<platform_source>)``, or None when unknown."""
    if not preview.platform:
        return None
    source = preview.platform_source or "unknown"
    return f"platform: {preview.platform} ({source})"


def selection_totals_line(preview: ImportPreview,
                          selection: Optional[RegionSelection]) -> str:
    """``keep N regions (X), exclude M regions (Y)`` for *selection*."""
    inc_n, inc_b, exc_n, exc_b = preview.summarize(selection)
    return (f"selection keeps {inc_n} region(s) ({format_size(inc_b)}), "
            f"excludes {exc_n} region(s) ({format_size(exc_b)})")


def preview_report(preview: ImportPreview, source: str,
                   selection: Optional[RegionSelection] = None,
                   verbose: bool = False) -> List[str]:
    """The ``--list-regions`` text block for one source file."""
    lines = [f"{source}  (format: {preview.format}, "
             f"{len(preview.regions)} region(s))"]
    platform = platform_line(preview)
    if platform:
        lines.append("  " + platform)
    lines.extend(category_table(preview, selection))
    lines.append("  " + selection_totals_line(preview, selection))
    if preview.is_msl:
        lines.append("  note: .msl input is copied verbatim unless "
                     "--materialize is given; the selection then applies "
                     "at analysis time")
    lines.extend(f"  note: {note}" for note in preview.notes)
    if verbose:
        lines.extend(region_list(preview, selection))
    return lines


def write_import_summary(result, out: TextIO) -> None:
    """Human summary of one import's selection outcome (no-op without one)."""
    if not result.has_selection_info:
        return
    if result.selection is not None:
        print(f"memdiver: imported {result.regions_written} region(s) to "
              f"{result.output_path} with {result.selection}; excluded "
              f"{result.excluded_region_count} region(s) "
              f"({format_size(result.excluded_bytes)})", file=out)
    if result.materialized:
        print(f"memdiver: wrote a filtered (materialized) copy; dropped "
              f"{result.dropped_key_hints} key hint(s)", file=out)
    for warning in result.warnings:
        print(f"memdiver: WARNING — {warning}", file=out)


def _provenance_selection_line(record: dict) -> str:
    categories = record.get("selected_categories")
    if categories is None:
        return "  regions kept:   (no region selection recorded)"
    kept = "all" if record.get("selection_all") else ", ".join(categories)
    if record.get("writable_only"):
        kept += " (writable only)"
    if record.get("module_globs"):
        kept += " + modules " + "|".join(record["module_globs"])
    return f"  regions kept:   {kept}"


def _provenance_excluded_line(record: dict) -> Optional[str]:
    regions, size = record.get("excluded_regions"), record.get("excluded_bytes")
    if regions is None and size is None:
        return None
    noun = "region" if regions == 1 else "regions"
    return (f"  excluded:       {regions or 0} {noun}, "
            f"{format_size(size or 0)}")


def provenance_lines(records: Sequence[dict]) -> List[str]:
    """Human-readable lines for ``inspect provenance --text``.

    *records* are the dicts ``import_provenance_result`` produces.
    """
    if not records:
        return ["No import provenance (not an imported or materialized .msl)."]
    lines: List[str] = []
    for index, record in enumerate(records, 1):
        lines.append(f"Import provenance #{index}")
        lines.append(f"  source format:  {record['source_format_name']}")
        lines.append(f"  tool:           {record['tool_name']}")
        lines.append(f"  original size:  {format_size(record['orig_file_size'])}")
        lines.append(_provenance_selection_line(record))
        excluded = _provenance_excluded_line(record)
        if excluded:
            lines.append(excluded)
        if record.get("fallback_all"):
            lines.append("  note:           selection matched nothing; kept all")
        if record.get("materialized"):
            lines.append("  materialized:   yes (filtered copy of an .msl)")
            lines.append("  original hash:  "
                         + (record.get("orig_eoc_hash") or "(not recorded)"))
        lines.append(f"  raw note:       {record['note']}")
    return lines
