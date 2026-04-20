"""Color-coded hex dump viewer."""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("memdiver.ui.views.hex_viewer")


def render_hex_viewer(
    mo,
    dump_data: bytes,
    start_offset: int = 0,
    byte_classes: Optional[List[str]] = None,
    highlight_offsets: Optional[set] = None,
    title: str = "Hex Viewer",
    bytes_per_row: int = 16,
    max_rows: int = 64,
    interactive: bool = False,
    controls: Optional[Any] = None,
    bookmarks: Optional[Any] = None,
) -> Any:
    """Render a hex dump viewer with color-coded bytes.

    Args:
        mo: marimo module.
        dump_data: Raw bytes to display.
        start_offset: Offset of first byte in the dump.
        byte_classes: Per-byte classification ('key', 'same', 'different').
        highlight_offsets: Specific offsets to highlight.
        title: Panel title.
        bytes_per_row: Bytes per row.
        max_rows: Maximum rows to render.
        interactive: If True, use the enhanced hex navigator with pagination.
        controls: Widget dict from create_hex_controls (required when interactive=True).
        bookmarks: BookmarkStore instance (optional, for interactive mode).

    Returns:
        mo.Html with the rendered hex dump.
    """
    if interactive and controls is not None:
        from ui.views.hex_navigator import render_hex_navigator
        return render_hex_navigator(
            mo, dump_data, controls,
            byte_classes=byte_classes,
            highlight_offsets=highlight_offsets,
            bookmarks=bookmarks,
            title=title,
            bytes_per_row=bytes_per_row,
        )
    from ui.components.hex_renderer import render_hex_dump
    from ui.components import color_scheme as cs

    if not dump_data:
        return mo.md("*No dump data to display.*")

    hex_html = render_hex_dump(
        dump_data,
        start_offset=start_offset,
        byte_classes=byte_classes,
        highlight_offsets=highlight_offsets,
        bytes_per_row=bytes_per_row,
        max_rows=max_rows,
    )

    # Legend
    legend_items = [
        (cs.COLOR_KEY, "Key"),
        (cs.COLOR_SAME, "Static"),
        (cs.COLOR_DIFFERENT, "Dynamic"),
        (cs.COLOR_ZERO, "Zero"),
        (cs.COLOR_ASCII, "ASCII"),
    ]
    legend = " ".join(
        f'<span style="color:{color};margin-right:12px;">&#9632; {label}</span>'
        for color, label in legend_items
    )

    info = f"{len(dump_data)} bytes from offset 0x{start_offset:x}"

    html = (
        f'{cs.BASE_CSS}'
        f'<div class="memdiver-panel">'
        f'<div class="memdiver-header">{title}</div>'
        f'<div style="font-size:11px;color:{cs.TEXT_SECONDARY};margin-bottom:6px;">'
        f'{info}</div>'
        f'<div style="font-size:11px;margin-bottom:8px;">{legend}</div>'
        f'{hex_html}'
        f'</div>'
    )
    return mo.Html(html)


def render_hit_details(mo, hits: List[Any], dump_data: bytes) -> Any:
    """Render detailed view of specific hits in the hex dump.

    Args:
        mo: marimo module.
        hits: List of engine.results.SecretHit instances.
        dump_data: Raw dump bytes for hex preview extraction.

    Returns:
        mo.Html with a table of hit details.
    """
    from ui.components.html_builder import table
    from ui.components import color_scheme as cs

    if not hits:
        return mo.md("*No hits to display.*")

    headers = ["Type", "Offset", "Length", "Hex Preview"]
    rows = []
    for hit in hits[:20]:  # Limit to 20
        preview = dump_data[hit.offset:hit.offset + min(hit.length, 16)]
        hex_str = " ".join(f"{b:02x}" for b in preview)
        if hit.length > 16:
            hex_str += " ..."
        rows.append([
            hit.secret_type,
            f"0x{hit.offset:x}",
            str(hit.length),
            f'<code style="color:{cs.COLOR_KEY}">{hex_str}</code>',
        ])

    html = table(headers, rows, title=f"Secret Hits ({len(hits)} total)")
    return mo.Html(html)
