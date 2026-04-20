"""Synchronized side-by-side hex comparison view."""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("memdiver.ui.views.hex_comparison")


def create_comparison_controls(
    mo,
    dump_size_a: int,
    dump_size_b: int,
    rows_per_page: int = 32,
    bytes_per_row: int = 16,
) -> dict:
    """Create shared controls for synchronized comparison.

    Returns dict with page slider and offset jump for both panels.
    """
    from ui.components.hex_pager import total_pages

    max_size = max(dump_size_a, dump_size_b)
    max_page = max(0, total_pages(max_size, rows_per_page, bytes_per_row) - 1)

    return {
        "page": mo.ui.slider(start=0, stop=max_page, value=0, label="Page"),
        "offset_input": mo.ui.text(value="0", label="Jump to offset (hex)"),
        "jump_btn": mo.ui.button(label="Jump", value=0),
        "highlight_diffs": mo.ui.switch(value=True, label="Highlight differences"),
    }


def render_hex_comparison(
    mo,
    dump_a: bytes,
    dump_b: bytes,
    label_a: str = "Dump A",
    label_b: str = "Dump B",
    controls: Optional[dict] = None,
    bytes_per_row: int = 16,
    rows_per_page: int = 32,
) -> Any:
    """Render two hex panels side by side, same page, with diff highlighting.

    Args:
        mo: marimo module.
        dump_a: First dump bytes.
        dump_b: Second dump bytes.
        label_a: Label for first panel.
        label_b: Label for second panel.
        controls: Controls dict from create_comparison_controls.
        bytes_per_row: Bytes per hex line.
        rows_per_page: Rows per page (per panel).

    Returns:
        mo.Html with side-by-side hex comparison.
    """
    from ui.components.hex_pager import compute_page
    from ui.components.hex_renderer import render_hex_dump
    from ui.components import color_scheme as cs

    page = controls["page"].value if controls else 0
    highlight_diffs = controls["highlight_diffs"].value if controls else True

    page_bytes = rows_per_page * bytes_per_row

    # Compute page range
    start_a, end_a = compute_page(len(dump_a), page, rows_per_page, bytes_per_row)
    start_b, end_b = compute_page(len(dump_b), page, rows_per_page, bytes_per_row)

    page_data_a = dump_a[start_a:end_a]
    page_data_b = dump_b[start_b:end_b]

    # Build diff classes
    diff_classes_a = None
    diff_classes_b = None
    diff_offsets = set()

    if highlight_diffs:
        min_len = min(len(page_data_a), len(page_data_b))
        diff_classes_a = []
        diff_classes_b = []
        for i in range(max(len(page_data_a), len(page_data_b))):
            if i < min_len and page_data_a[i] == page_data_b[i]:
                diff_classes_a.append("same")
                diff_classes_b.append("same")
            else:
                diff_classes_a.append("different")
                diff_classes_b.append("different")
                diff_offsets.add(start_a + i)

    hex_a = render_hex_dump(
        page_data_a, start_a, diff_classes_a, None, bytes_per_row, rows_per_page,
    )
    hex_b = render_hex_dump(
        page_data_b, start_b, diff_classes_b, None, bytes_per_row, rows_per_page,
    )

    diff_count = len(diff_offsets)
    info = f"Page {page} | Offset 0x{start_a:x} | {diff_count} differing bytes"

    html = (
        f'{cs.BASE_CSS}'
        f'<div class="memdiver-panel">'
        f'<div class="memdiver-header">Side-by-Side Comparison</div>'
        f'<div style="font-size:11px;color:{cs.TEXT_SECONDARY};margin-bottom:8px;">{info}</div>'
        f'<div style="display:flex;gap:12px;">'
        f'<div style="flex:1;min-width:0;">'
        f'<div style="color:{cs.ACCENT_BLUE};font-size:12px;font-weight:600;margin-bottom:4px;">'
        f'{label_a}</div>{hex_a}</div>'
        f'<div style="flex:1;min-width:0;">'
        f'<div style="color:{cs.ACCENT_BLUE};font-size:12px;font-weight:600;margin-bottom:4px;">'
        f'{label_b}</div>{hex_b}</div>'
        f'</div></div>'
    )
    return mo.Html(html)
