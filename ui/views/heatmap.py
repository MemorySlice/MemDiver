"""Key presence heatmap visualization."""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("memdiver.ui.views.heatmap")


def render_heatmap(
    mo,
    libraries: List[str],
    secret_types: List[str],
    presence_data: Dict[str, Dict[str, bool]],
    tls_version: str = "13",
) -> Any:
    """Render a key presence heatmap showing which secrets survive at which phase.

    Args:
        mo: marimo module.
        libraries: List of library names (rows).
        secret_types: List of secret type labels (columns).
        presence_data: {library: {secret_type: True/False}}.
        tls_version: TLS version for display labels.

    Returns:
        mo.Html with the rendered heatmap.
    """
    from ui.components import color_scheme as cs
    from core.display_labels import get_short_label

    if not libraries or not secret_types:
        return mo.md("*No data for heatmap.*")

    rows_html = []
    for lib in libraries:
        cells = []
        lib_data = presence_data.get(lib, {})
        for st in secret_types:
            present = lib_data.get(st, False)
            bg = cs.HEATMAP_PRESENT if present else cs.HEATMAP_ABSENT
            symbol = "&#10003;" if present else "&#10007;"
            cells.append(
                f'<td style="background:{bg};color:{cs.TEXT_BRIGHT};text-align:center;'
                f'padding:6px 10px;font-size:14px;">{symbol}</td>'
            )
        rows_html.append(
            f'<tr><td style="padding:6px 10px;color:{cs.TEXT_PRIMARY};'
            f'font-weight:500;white-space:nowrap;">{lib}</td>'
            + "".join(cells) + "</tr>"
        )

    # Header row
    header_cells = [
        f'<th style="padding:6px 10px;color:{cs.TEXT_SECONDARY};font-weight:normal;'
        f'font-size:12px;text-align:center;min-width:60px;">'
        f'{get_short_label(st, tls_version)}</th>'
        for st in secret_types
    ]
    header = (
        f'<tr><th style="padding:6px 10px;color:{cs.TEXT_SECONDARY};">Library</th>'
        + "".join(header_cells) + "</tr>"
    )

    html = (
        f'{cs.BASE_CSS}'
        f'<div class="memdiver-panel">'
        f'<div class="memdiver-header">Key Presence Heatmap</div>'
        f'<table style="border-collapse:collapse;width:100%;">'
        f'<thead>{header}</thead>'
        f'<tbody>{"".join(rows_html)}</tbody>'
        f'</table></div>'
    )
    return mo.Html(html)


def build_presence_data(
    library_reports: List[Any],
    secret_types: List[str],
) -> Dict[str, Dict[str, bool]]:
    """Build presence_data dict from LibraryReport objects.

    Args:
        library_reports: List of engine.results.LibraryReport.
        secret_types: Secret types to check.

    Returns:
        {library: {secret_type: bool}}.
    """
    result = {}
    for report in library_reports:
        found_types = set()
        for hit in report.hits:
            found_types.add(hit.secret_type)
        result[report.library] = {
            st: st in found_types for st in secret_types
        }
    return result
