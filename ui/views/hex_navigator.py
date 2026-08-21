"""Enhanced hex viewer with pagination, search, and bookmarks."""

import logging
from typing import Any, List, Optional

from memdiver.ui.components.hex_pager import compute_page, total_pages, offset_to_page
from memdiver.ui.components.hex_renderer import render_hex_dump
from memdiver.ui.components.bookmark_store import BookmarkStore
from memdiver.ui.components import color_scheme as cs
from memdiver.ui.locales import _
# TODO(single-source): _search_dump() below merges an ASCII-literal search with
# a hex-byte search over the in-memory `dump_data` page. The shared producer
# app.tools_inspect.search_bytes_result is path-based and hex-only (it re-opens
# the dump and calls source.find_all on a hex needle), so routing through it
# would both re-read the file and silently drop the ASCII interpretation —
# a behavior change. Kept on the core find_pattern/parse_hex_pattern primitives.
from memdiver.core.region_analysis import find_pattern, parse_hex_pattern

logger = logging.getLogger("memdiver.ui.views.hex_navigator")


def create_hex_controls(mo, dump_size: int, rows_per_page: int = 64) -> dict:
    """Create Marimo control widgets for the hex navigator."""
    max_page = max(0, total_pages(dump_size, rows_per_page) - 1)
    max_offset = max(0, dump_size - 1)
    return {
        "page": mo.ui.slider(start=0, stop=max_page, value=0, label=_("Page")),
        "offset_input": mo.ui.text(value="0", label=_("Jump to offset (hex)")),
        "jump_btn": mo.ui.button(label=_("Jump"), value=0),
        "search_input": mo.ui.text(value="", label=_("Search (hex or ASCII)")),
        "search_btn": mo.ui.button(label=_("Search"), value=0),
        "inspect_offset": mo.ui.number(
            start=0, stop=max_offset, value=0, label=_("Inspect offset"),
        ),
        "bookmark_label": mo.ui.text(value="", label=_("Bookmark label")),
        "bookmark_btn": mo.ui.button(label=_("Bookmark"), value=0),
    }


def _build_legend() -> str:
    """Build the color legend HTML."""
    items = [
        (cs.COLOR_KEY, _("Key")), (cs.COLOR_SAME, _("Static")),
        (cs.COLOR_DIFFERENT, _("Dynamic")), (cs.COLOR_ZERO, _("Zero")),
        (cs.COLOR_ASCII, _("ASCII")), (cs.COLOR_BOOKMARK, _("Bookmark")),
        (cs.COLOR_SEARCH_HIT, _("Search")),
    ]
    return " ".join(
        f'<span style="color:{c};margin-right:12px;">&#9632; {l}</span>'
        for c, l in items
    )


def _search_dump(dump_data: bytes, search_text: str) -> tuple:
    """Search dump for the given term.

    Disambiguation rules (single text control, label "hex or ASCII"):
      * A leading "0x"/"0X" prefix forces a hex-byte interpretation, so a
        term that also reads as ASCII (e.g. "0xcafe") is searched as bytes
        only.
      * Otherwise the term is searched as literal ASCII first; if it is also
        valid even-length hex (e.g. "cafe", "deadbeef") the byte
        interpretation is searched as well and the offsets are merged, so
        neither reading is silently dropped.
    """
    stripped = search_text.strip()
    if not stripped:
        return (b"", [])

    forced_hex = stripped[:2].lower() == "0x"
    if forced_hex:
        pattern = parse_hex_pattern(stripped[2:])
        if pattern is None:
            # Bad hex after "0x" -> nothing to search rather than guessing.
            logger.debug("invalid forced-hex search %r", search_text)
            return (b"", [])
        offsets = find_pattern(dump_data, pattern)
        logger.debug(
            "hex search for %r found %d results", search_text, len(offsets),
        )
        return (pattern, offsets)

    ascii_pattern = stripped.encode("utf-8", errors="replace")
    merged = set(find_pattern(dump_data, ascii_pattern))
    primary = ascii_pattern

    hex_pattern = parse_hex_pattern(stripped)
    if hex_pattern is not None and hex_pattern != ascii_pattern:
        merged |= set(find_pattern(dump_data, hex_pattern))

    offsets = sorted(merged)
    logger.debug(
        "search for %r found %d results (ascii+hex merged)",
        search_text, len(offsets),
    )
    return (primary, offsets)


def _render_search_results(
    offsets: List[int], pattern: bytes,
    rows_per_page: int, bytes_per_row: int,
) -> str:
    """Build HTML for search result listing."""
    if not offsets:
        return (
            f'<div style="color:{cs.TEXT_SECONDARY};font-size:12px;">'
            f'{_("No matches found.")}</div>'
        )
    count = len(offsets)
    shown = min(count, 20)
    rows_html = []
    for off in offsets[:shown]:
        pg = offset_to_page(off, rows_per_page, bytes_per_row)
        page_label = _("Page {page}").format(page=pg)
        rows_html.append(
            f"<tr>"
            f'<td style="padding:2px 8px;color:{cs.ACCENT_CYAN}">'
            f"0x{off:08x}</td>"
            f'<td style="padding:2px 8px;color:{cs.TEXT_SECONDARY}">'
            f"{page_label}</td></tr>"
        )
    table = "".join(rows_html)
    header = (
        _("{count} match").format(count=count) if count == 1
        else _("{count} matches").format(count=count)
    )
    if count > shown:
        header += _(" (showing first {shown})").format(shown=shown)
    return (
        f'<div style="margin-top:8px;">'
        f'<div style="color:{cs.ACCENT_BLUE};font-size:12px;'
        f'font-weight:600;margin-bottom:4px;">{header}</div>'
        f'<table style="font-size:11px;font-family:monospace;">'
        f"{table}</table></div>"
    )


def render_hex_navigator(
    mo, dump_data: bytes, controls: dict,
    byte_classes: Optional[List[str]] = None,
    highlight_offsets: Optional[set] = None,
    bookmarks: Optional[BookmarkStore] = None,
    title: str = _("Hex Navigator"),
    bytes_per_row: int = 16, rows_per_page: int = 64,
) -> Any:
    """Render the enhanced hex viewer with pagination and controls."""
    if not dump_data:
        return mo.md(_("*No dump data to display.*"))

    page = controls["page"].value
    start, end = compute_page(
        len(dump_data), page, rows_per_page, bytes_per_row,
    )
    page_data = dump_data[start:end]
    page_classes = byte_classes[start:end] if byte_classes else None

    # Merge bookmark offsets into highlights
    merged = set(highlight_offsets) if highlight_offsets else set()
    if bookmarks:
        merged |= bookmarks.to_highlight_offsets()

    hex_html = render_hex_dump(
        page_data, start_offset=start, byte_classes=page_classes,
        highlight_offsets=merged if merged else None,
        bytes_per_row=bytes_per_row, max_rows=rows_per_page,
    )

    # Info bar
    n_pages = total_pages(len(dump_data), rows_per_page, bytes_per_row)
    info = _(
        "Page {page}/{n_pages} | "
        "Offset 0x{start:04X}\u20130x{end:04X} | "
        "{n_bytes} bytes"
    ).format(page=page + 1, n_pages=n_pages, start=start, end=end,
             n_bytes=len(dump_data))
    legend = _build_legend()

    # Jump hint
    jump_hint = ""
    jump_text = controls["offset_input"].value.strip()
    if jump_text:
        try:
            target = int(jump_text, 16)
            target_page = offset_to_page(target, rows_per_page, bytes_per_row)
            if target_page != page:
                jump_hint = (
                    f'<div style="color:{cs.ACCENT_ORANGE};font-size:11px;'
                    f'margin-top:4px;">'
                    + _("Navigate to page {page} for offset 0x{offset:X}").format(
                        page=target_page + 1, offset=target,
                    )
                    + "</div>"
                )
        except ValueError:
            jump_hint = (
                f'<div style="color:{cs.ACCENT_RED};font-size:11px;'
                f'margin-top:4px;">{_("Invalid hex offset")}</div>'
            )

    # Search results
    search_section = ""
    search_text = controls["search_input"].value
    if search_text.strip():
        pattern, offsets = _search_dump(dump_data, search_text)
        search_section = _render_search_results(
            offsets, pattern, rows_per_page, bytes_per_row,
        )

    html = (
        f"{cs.BASE_CSS}"
        f'<div class="memdiver-panel">'
        f'<div class="memdiver-header">{title}</div>'
        f'<div style="font-size:11px;color:{cs.TEXT_SECONDARY};'
        f'margin-bottom:6px;">{info}</div>'
        f'<div style="font-size:11px;margin-bottom:8px;">{legend}</div>'
        f"{jump_hint}{hex_html}{search_section}"
        f"</div>"
    )
    return mo.Html(html)
