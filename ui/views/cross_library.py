"""Cross-library comparison view - side-by-side hex panels."""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("memdiver.ui.views.cross_library")


def render_cross_library(
    mo,
    library_data: Dict[str, bytes],
    secret_type: str,
    offset: int,
    length: int = 32,
    context: int = 64,
) -> Any:
    """Render side-by-side hex panels for the same region across libraries.

    Args:
        mo: marimo module.
        library_data: {library_name: dump_bytes}.
        secret_type: Secret type being compared.
        offset: Offset of the region in each dump.
        length: Length of the key region.
        context: Context bytes before/after.

    Returns:
        mo.Html with side-by-side comparison.
    """
    from ui.components.hex_renderer import render_hex_dump
    from ui.components import color_scheme as cs

    if not library_data:
        return mo.md("*No library data for comparison.*")

    panels = []
    for lib_name, data in sorted(library_data.items()):
        start = max(0, offset - context)
        end = min(len(data), offset + length + context)
        region = data[start:end]

        # Classify bytes: key region highlighted
        classes = []
        for i in range(len(region)):
            abs_pos = start + i
            if offset <= abs_pos < offset + length:
                classes.append("key")
            else:
                classes.append(None)

        hex_html = render_hex_dump(
            region, start_offset=start, byte_classes=classes, max_rows=16,
        )
        panels.append(
            f'<div style="flex:1;min-width:300px;">'
            f'<div style="color:{cs.ACCENT_BLUE};font-size:13px;font-weight:600;'
            f'margin-bottom:4px;">{lib_name}</div>'
            f'{hex_html}</div>'
        )

    html = (
        f'{cs.BASE_CSS}'
        f'<div class="memdiver-panel">'
        f'<div class="memdiver-header">Cross-Library Comparison: {secret_type}</div>'
        f'<div style="display:flex;gap:12px;overflow-x:auto;">'
        + "".join(panels)
        + '</div></div>'
    )
    return mo.Html(html)
