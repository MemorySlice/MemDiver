"""Enhanced hex viewer with pagination, search, and bookmarks."""

import logging
from typing import Any, List, Optional

from ui.components.hex_pager import compute_page, total_pages, offset_to_page
from ui.components.hex_renderer import render_hex_dump
from ui.components.bookmark_store import BookmarkStore
from ui.components import color_scheme as cs
from core.region_analysis import find_pattern, parse_hex_pattern

logger = logging.getLogger("memdiver.ui.views.hex_navigator")


def create_hex_controls(mo, dump_size: int, rows_per_page: int = 64) -> dict:
    """Create Marimo control widgets for the hex navigator."""
    max_page = max(0, total_pages(dump_size, rows_per_page) - 1)
    max_offset = max(0, dump_size - 1)
    return {
        "page": mo.ui.slider(start=0, stop=max_page, value=0, label="Page"),
        "offset_input": mo.ui.text(value="0", label="Jump to offset (hex)"),
        "jump_btn": mo.ui.button(label="Jump", value=0),
        "search_input": mo.ui.text(value="", label="Search (hex or ASCII)"),
        "search_btn": mo.ui.button(label="Search", value=0),
        "inspect_offset": mo.ui.number(
            start=0, stop=max_offset, value=0, label="Inspect offset",
        ),
        "bookmark_label": mo.ui.text(value="", label="Bookmark label"),
        "bookmark_btn": mo.ui.button(label="Bookmark", value=0),
    }


def _build_legend() -> str:
    """Build the color legend HTML."""
    items = [
        (cs.COLOR_KEY, "Key"), (cs.COLOR_SAME, "Static"),
        (cs.COLOR_DIFFERENT, "Dynamic"), (cs.COLOR_ZERO, "Zero"),
        (cs.COLOR_ASCII, "ASCII"), (cs.COLOR_BOOKMARK, "Bookmark"),
        (cs.COLOR_SEARCH_HIT, "Search"),
    ]
    return " ".join(
        f'<span style="color:{c};margin-right:12px;">&#9632; {l}</span>'
        for c, l in items
    )


def _search_dump(dump_data: bytes, search_text: str) -> tuple:
    """Search dump; tries hex parse first, falls back to ASCII."""
    if not search_text.strip():
        return (b"", [])
    pattern = parse_hex_pattern(search_text)
    if pattern is None:
        pattern = search_text.encode("utf-8", errors="replace")
    offsets = find_pattern(dump_data, pattern)
    logger.debug("search for %r found %d results", search_text, len(offsets))
    return (pattern, offsets)


def _render_search_results(
    offsets: List[int], pattern: bytes,
    rows_per_page: int, bytes_per_row: int,
) -> str:
    """Build HTML for search result listing."""
    if not offsets:
        return (
            f'<div style="color:{cs.TEXT_SECONDARY};font-size:12px;">'
            "No matches found.</div>"
        )
    count = len(offsets)
    shown = min(count, 20)
    rows_html = []
    for off in offsets[:shown]:
        pg = offset_to_page(off, rows_per_page, bytes_per_row)
        rows_html.append(
            f"<tr>"
            f'<td style="padding:2px 8px;color:{cs.ACCENT_CYAN}">'
            f"0x{off:08x}</td>"
            f'<td style="padding:2px 8px;color:{cs.TEXT_SECONDARY}">'
            f"Page {pg}</td></tr>"
        )
    table = "".join(rows_html)
    header = f"{count} match{'es' if count != 1 else ''}"
    if count > shown:
        header += f" (showing first {shown})"
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
    title: str = "Hex Navigator",
    bytes_per_row: int = 16, rows_per_page: int = 64,
) -> Any:
    """Render the enhanced hex viewer with pagination and controls."""
    if not dump_data:
        return mo.md("*No dump data to display.*")

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
    info = (
        f"Page {page + 1}/{n_pages} | "
        f"Offset 0x{start:04X}\u20130x{end:04X} | "
        f"{len(dump_data)} bytes"
    )
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
                    f'margin-top:4px;">Navigate to page {target_page + 1} '
                    f"for offset 0x{target:X}</div>"
                )
        except ValueError:
            jump_hint = (
                f'<div style="color:{cs.ACCENT_RED};font-size:11px;'
                f'margin-top:4px;">Invalid hex offset</div>'
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
