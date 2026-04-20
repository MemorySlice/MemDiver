"""Phase lifecycle view - key presence across ALL phases for one library."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger("memdiver.ui.views.phase_lifecycle")


def render_phase_lifecycle(
    mo,
    library: str,
    phases: List[str],
    secret_types: List[str],
    phase_presence: Dict[str, Dict[str, bool]],
    tls_version: str = "13",
) -> Any:
    """Render a grid showing key presence across all lifecycle phases.

    Reveals zeroing behavior: which keys disappear at which phase.

    Args:
        mo: marimo module.
        library: Library name.
        phases: Ordered list of phase names.
        secret_types: Secret types to track.
        phase_presence: {phase: {secret_type: True/False}}.
        tls_version: TLS version for labels.

    Returns:
        mo.Html with the lifecycle grid.
    """
    from ui.components import color_scheme as cs
    from core.display_labels import get_short_label

    if not phases or not secret_types:
        return mo.md("*No lifecycle data available.*")

    # Build header
    header_cells = "".join(
        f'<th style="padding:4px 8px;color:{cs.TEXT_SECONDARY};font-size:11px;'
        f'text-align:center;writing-mode:vertical-lr;transform:rotate(180deg);'
        f'min-width:40px;height:80px;">{p}</th>'
        for p in phases
    )
    header = f'<tr><th style="padding:4px 8px;"></th>{header_cells}</tr>'

    # Build rows (one per secret type)
    rows = []
    for st in secret_types:
        label = get_short_label(st, tls_version)
        cells = []
        for phase in phases:
            present = phase_presence.get(phase, {}).get(st, False)
            bg = cs.HEATMAP_PRESENT if present else cs.HEATMAP_ABSENT
            cells.append(
                f'<td style="background:{bg};text-align:center;padding:4px;'
                f'min-width:40px;font-size:11px;color:{cs.TEXT_BRIGHT};">'
                f'{"&#10003;" if present else ""}</td>'
            )
        rows.append(
            f'<tr><td style="padding:4px 8px;color:{cs.TEXT_PRIMARY};'
            f'font-size:12px;white-space:nowrap;">{label}</td>'
            + "".join(cells) + "</tr>"
        )

    html = (
        f'{cs.BASE_CSS}'
        f'<div class="memdiver-panel">'
        f'<div class="memdiver-header">Phase Lifecycle: {library}</div>'
        f'<div style="overflow-x:auto;">'
        f'<table style="border-collapse:collapse;">'
        f'<thead>{header}</thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        f'</table></div></div>'
    )
    return mo.Html(html)
