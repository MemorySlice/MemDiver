"""MSL import tool controls: region-category selection, preview, results.

Pure helpers (no marimo import at module level) so the marimo cells in
``run.py`` stay thin and the logic is unit-testable without a runtime.
"""

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional

from memdiver.msl.region_select import (
    DEFAULT_INTERACTIVE_CATEGORIES,
    RegionCategory,
)
from memdiver.ui.locales import _

logger = logging.getLogger("memdiver.ui.controls.import_panel")

_CATEGORY_LABEL_KEYS: Dict[RegionCategory, str] = {
    RegionCategory.HEAP: "Heap",
    RegionCategory.STACK: "Stack",
    RegionCategory.IMAGE_CODE: "Image code",
    RegionCategory.IMAGE_DATA: "Image data",
    RegionCategory.MAPPED_FILE: "Mapped file",
    RegionCategory.SHARED: "Shared memory",
    RegionCategory.UNCLASSIFIED: "Unclassified",
    RegionCategory.RUNTIME: "Runtime (ART/JIT/kernel maps, not default)",
}


def category_label(category: RegionCategory) -> str:
    """Localized display label for one region category."""
    return _(_CATEGORY_LABEL_KEYS[category])


def category_options() -> Dict[str, str]:
    """Multiselect options: localized label -> category value (enum order)."""
    return {category_label(cat): cat.value for cat in RegionCategory}


def default_category_labels() -> List[str]:
    """Labels pre-selected by default (heap + stack + unclassified)."""
    return [category_label(cat) for cat in RegionCategory
            if cat in DEFAULT_INTERACTIVE_CATEGORIES]


def selection_spec(selected_values: Iterable[str]) -> Optional[str]:
    """Selection spec for ``app.tools.import_dump``; ``None`` means "all".

    Raises ``ValueError`` when nothing is selected.
    """
    chosen = [cat.value for cat in RegionCategory
              if cat.value in set(selected_values)]
    if not chosen:
        raise ValueError(_("Select at least one region category."))
    if len(chosen) == len(RegionCategory):
        return None
    return ",".join(chosen)


def output_path_for(raw: Path) -> Path:
    """Target ``.msl`` path; never the source itself for ``.msl`` inputs."""
    if raw.suffix.lower() == ".msl":
        return raw.with_name(f"{raw.stem}.filtered.msl")
    return raw.with_suffix(".msl")


def create_import_controls(mo, initial_path: str) -> SimpleNamespace:
    """Build the import widgets (file browser, categories, materialize, button)."""
    return SimpleNamespace(
        file_browser=mo.ui.file_browser(
            initial_path=initial_path, selection_mode="file", multiple=False,
            label=_("Raw dump file to convert"),
        ),
        categories=mo.ui.multiselect(
            options=category_options(), value=default_category_labels(),
            label=_("Region categories to import"),
        ),
        materialize=mo.ui.checkbox(
            value=False, label=_("Materialize filtered copy"),
        ),
        btn=mo.ui.button(
            label=_("Import to MSL"), value=0, on_click=lambda v: v + 1,
            kind="neutral",
        ),
    )


def _format_bytes(n_bytes: int) -> str:
    size = float(n_bytes)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n_bytes} B"


def preview_rows(preview: Dict[str, Any], selected_values: Iterable[str]
                 ) -> List[Dict[str, Any]]:
    """Per-category table rows from ``ImportPreview.to_dict()``."""
    selected = set(selected_values)
    rows = []
    for cat in RegionCategory:
        totals = preview.get("totals", {}).get(cat.value)
        if not totals:
            continue
        rows.append({
            _("Category"): category_label(cat),
            _("Regions"): totals["count"],
            _("Captured"): _format_bytes(totals["bytes"]),
            _("Included"): _("Yes") if cat.value in selected else _("No"),
        })
    return rows


def load_preview(path: Path) -> Dict[str, Any]:
    """Metadata-only preview of *path* (no region payloads are read)."""
    from memdiver.msl.import_preview import preview_import
    return preview_import(path).to_dict()


def platform_markdown(preview: Dict[str, Any]) -> Optional[str]:
    """``Platform: **android** (header)`` line, or None when unknown."""
    platform = preview.get("platform")
    if not platform:
        return None
    return _("Platform: **{platform}** ({source})").format(
        platform=platform, source=preview.get("platform_source") or "?")


def runtime_notice(preview: Dict[str, Any],
                   selected_values: Iterable[str]) -> Optional[str]:
    """Localized notice on the name-classified ``runtime`` regions, if any.

    Built from the preview's ``platform`` / ``runtime_count`` /
    ``runtime_bytes``; says whether the current selection keeps them.
    """
    count = preview.get("runtime_count") or 0
    if not count:
        return None
    fields = {"count": count,
              "size": _format_bytes(preview.get("runtime_bytes") or 0)}
    if preview.get("platform") == "android":
        text = _("Android dump: {count} runtime region(s) ({size}) — zygote / "
                 "boot-image / ART metadata, JIT caches and kernel/device "
                 "maps — were classified by mapping name.").format(**fields)
    else:
        text = _("{count} runtime region(s) ({size}) — JIT caches and "
                 "kernel/device maps such as [vdso] / [vvar] — were "
                 "classified by mapping name.").format(**fields)
    if RegionCategory.RUNTIME.value in set(selected_values):
        return text + " " + _("They are included in this import.")
    return text + " " + _("They are not selected by default; add the "
                          "Runtime category to import them.")


def _is_runtime_note(note: str) -> bool:
    # The preview's English runtime note is replaced by runtime_notice().
    return "classified 'runtime' by mapping name" in note


def render_preview(mo, preview: Dict[str, Any], selected_values,
                   materialize_cb) -> Any:
    """Preview table, plus the materialize option for ``.msl`` inputs."""
    items = [
        mo.md(_("Detected format: **{format}**").format(
            format=preview.get("format", "?"))),
    ]
    platform = platform_markdown(preview)
    if platform:
        items.append(mo.md(platform))
    items.append(mo.ui.table(preview_rows(preview, selected_values),
                             selection=None, label=_("Import preview")))
    notice = runtime_notice(preview, selected_values)
    if notice:
        items.append(mo.callout(mo.md(notice), kind="info"))
    items.extend(mo.md(f"- {note}") for note in preview.get("notes", [])
                 if not (notice and _is_runtime_note(note)))
    if preview.get("is_msl"):
        items.append(materialize_cb)
        items.append(mo.callout(mo.md(_(
            "This file is already .msl. Without materialize the copy stays "
            "verbatim and the region selection is applied at analysis time; "
            "with materialize a filtered copy containing only the selected "
            "regions is written.")), kind="info"))
    return mo.vstack(items)


def result_markdown(res: Dict[str, Any], raw: Path, out: Path) -> str:
    """Success summary incl. selection outcome (excluded counts, warnings)."""
    lines = [
        _("Imported **{src}** -> **{dst}**").format(src=raw.name, dst=out.name),
        _("Regions: {regions}, Key hints: {hints}").format(
            regions=res["regions_written"], hints=res["key_hints_written"]),
    ]
    if "excluded_region_count" in res:
        lines.append(_("Excluded regions: {count} ({size})").format(
            count=res["excluded_region_count"],
            size=_format_bytes(res.get("excluded_bytes", 0))))
    if res.get("materialized"):
        lines.append(_("Dropped key hints: {count}").format(
            count=res.get("dropped_key_hints", 0)))
    if res.get("secrets_only_in_excluded"):
        lines.append(_("Secrets only in excluded regions: {count}").format(
            count=res["secrets_only_in_excluded"]))
    lines.extend(_("Warning: {msg}").format(msg=w)
                 for w in res.get("warnings", []))
    return "  \n".join(lines)
