"""Differential diff view - two-run XOR comparison."""

import logging
from typing import Any, Optional

logger = logging.getLogger("memdiver.ui.views.differential_diff")


def render_differential_diff(
    mo,
    dump_a: bytes,
    dump_b: bytes,
    label_a: str = "Run 1",
    label_b: str = "Run 2",
    max_rows: int = 64,
    bytes_per_row: int = 16,
) -> Any:
    """Render a two-run XOR diff with color-coded changed bytes.

    Args:
        mo: marimo module.
        dump_a: First dump bytes.
        dump_b: Second dump bytes.
        label_a: Label for first dump.
        label_b: Label for second dump.
        max_rows: Maximum rows to display.
        bytes_per_row: Bytes per row.

    Returns:
        mo.Html with the diff view.
    """
    from ui.components import color_scheme as cs

    if not dump_a or not dump_b:
        return mo.md("*Need two dumps for differential comparison.*")

    min_len = min(len(dump_a), len(dump_b))
    max_bytes = max_rows * bytes_per_row

    # Compute XOR diff
    diff_count = 0
    lines = []
    for row_start in range(0, min(min_len, max_bytes), bytes_per_row):
        row_end = min(row_start + bytes_per_row, min_len)
        parts = [f'<span style="color:{cs.TEXT_SECONDARY}">{row_start:08x}</span>  ']

        for i in range(row_start, row_end):
            a, b = dump_a[i], dump_b[i]
            if a != b:
                diff_count += 1
                color = cs.COLOR_DIFFERENT
            elif a == 0:
                color = cs.COLOR_ZERO
            else:
                color = cs.TEXT_PRIMARY
            parts.append(f'<span style="color:{color}">{a:02x}</span> ')
            if (i - row_start) == 7:
                parts.append(" ")

        # Second dump in parallel
        parts.append(" | ")
        for i in range(row_start, row_end):
            a, b = dump_a[i], dump_b[i]
            if a != b:
                color = cs.COLOR_KEY
            elif b == 0:
                color = cs.COLOR_ZERO
            else:
                color = cs.TEXT_PRIMARY
            parts.append(f'<span style="color:{color}">{b:02x}</span> ')
            if (i - row_start) == 7:
                parts.append(" ")

        lines.append("".join(parts))

    content = "\n".join(lines)
    pct = (diff_count / min_len * 100) if min_len > 0 else 0

    html = (
        f'{cs.BASE_CSS}'
        f'<div class="memdiver-panel">'
        f'<div class="memdiver-header">Differential Diff</div>'
        f'<div style="font-size:11px;color:{cs.TEXT_SECONDARY};margin-bottom:6px;">'
        f'{label_a} vs {label_b} | {diff_count} bytes differ ({pct:.1f}%) | '
        f'{min_len} bytes compared</div>'
        f'<pre style="font-family:monospace;font-size:12px;line-height:1.4;'
        f'background:{cs.BG_PRIMARY};padding:12px;border-radius:4px;overflow-x:auto;">'
        f'{content}</pre></div>'
    )
    return mo.Html(html)
