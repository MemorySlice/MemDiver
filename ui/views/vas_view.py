"""Virtual Address Space navigator view."""

import logging
from typing import Any, Dict, List

from ui.components import color_scheme as _cs
from ui.components.html_builder import format_size as _format_size

logger = logging.getLogger("memdiver.ui.views.vas_view")

# RegionType enum value -> (label, color)
_REGION_COLORS: Dict[int, tuple] = {
    0x00: ("Unknown", _cs.TEXT_SECONDARY),
    0x01: ("Heap", _cs.VAS_HEAP),
    0x02: ("Stack", _cs.VAS_STACK),
    0x03: ("Image", _cs.VAS_IMAGE),
    0x04: ("Mapped", _cs.VAS_MAPPED),
    0x05: ("Anonymous", _cs.VAS_ANONYMOUS),
    0x06: ("Shared", _cs.VAS_SHARED),
    0xFF: ("Other", _cs.TEXT_SECONDARY),
}


def _region_label(region_type: int) -> str:
    return _REGION_COLORS.get(region_type, ("Unknown", "#808080"))[0]


def _region_color(region_type: int) -> str:
    return _REGION_COLORS.get(region_type, ("Unknown", "#808080"))[1]


def _protection_str(prot: int) -> str:
    """Format protection flags as RWX string."""
    r = "R" if prot & 0x01 else "-"
    w = "W" if prot & 0x02 else "-"
    x = "X" if prot & 0x04 else "-"
    return f"{r}{w}{x}"


def _is_captured(entry_base: int, entry_size: int, regions) -> bool:
    """Check if a VAS entry overlaps with any captured memory region."""
    entry_end = entry_base + entry_size
    for r in regions:
        r_end = r.base_addr + r.region_size
        if entry_base < r_end and entry_end > r.base_addr:
            return True
    return False


def render_vas_map(mo, vas_entries, regions=None) -> Any:
    """Render VAS layout as a Plotly horizontal bar chart.

    Args:
        mo: marimo module.
        vas_entries: List of MslVasEntry objects.
        regions: Optional list of MslMemoryRegion for captured overlay.

    Returns:
        Plotly figure wrapped in mo.ui.plotly, or fallback message.
    """
    if not vas_entries:
        return mo.md("*No VAS map data available.*")

    try:
        import plotly.graph_objects as go
    except ImportError:
        return mo.md("*Plotly required for VAS map visualization.*")

    if regions is None:
        regions = []

    sorted_entries = sorted(vas_entries, key=lambda e: e.base_addr)
    labels, sizes, colors, hovers = [], [], [], []

    for entry in sorted_entries:
        rtype = _region_label(entry.region_type)
        captured = _is_captured(entry.base_addr, entry.region_size, regions)
        prot = _protection_str(entry.protection)
        color = _region_color(entry.region_type)
        if not captured:
            color = color + "40"  # 25% opacity

        labels.append(f"0x{entry.base_addr:X} [{rtype}]")
        sizes.append(entry.region_size)
        colors.append(color)
        hovers.append(
            f"Base: 0x{entry.base_addr:X}<br>"
            f"Size: {_format_size(entry.region_size)}<br>"
            f"Type: {rtype}<br>"
            f"Protection: {prot}<br>"
            f"Path: {entry.mapped_path or '—'}<br>"
            f"Status: {'Captured' if captured else 'Not captured'}"
        )

    fig = go.Figure(go.Bar(
        y=labels, x=sizes, orientation="h",
        marker_color=colors, hovertext=hovers, hoverinfo="text",
    ))
    fig.update_layout(
        title="Virtual Address Space Layout",
        xaxis_title="Region Size (bytes)",
        yaxis_title="",
        template="plotly_dark",
        paper_bgcolor="#1e1e1e",
        plot_bgcolor="#252526",
        font=dict(family="Cascadia Code, Fira Code, monospace", size=11),
        height=max(300, len(sorted_entries) * 28),
        margin=dict(l=180, r=20, t=40, b=40),
        yaxis=dict(autorange="reversed"),
    )
    return mo.ui.plotly(fig)


def render_vas_table(mo, vas_entries, regions=None) -> Any:
    """Render VAS details as an HTML table.

    Args:
        mo: marimo module.
        vas_entries: List of MslVasEntry objects.
        regions: Optional list of MslMemoryRegion for captured status.

    Returns:
        mo.Html with the VAS detail table.
    """
    from ui.components import color_scheme as cs

    if not vas_entries:
        return mo.md("*No VAS map data available.*")

    if regions is None:
        regions = []

    sorted_entries = sorted(vas_entries, key=lambda e: e.base_addr)
    th = f'padding:4px 8px;color:{cs.TEXT_SECONDARY};'
    header = (
        f'<tr>'
        f'<th style="{th}text-align:left;">Base Address</th>'
        f'<th style="{th}text-align:left;">End Address</th>'
        f'<th style="{th}text-align:right;">Size</th>'
        f'<th style="{th}text-align:center;">Type</th>'
        f'<th style="{th}text-align:center;">Prot</th>'
        f'<th style="{th}text-align:left;">Mapped Path</th>'
        f'<th style="{th}text-align:center;">Captured</th>'
        f'</tr>'
    )

    rows = []
    for entry in sorted_entries:
        end_addr = entry.base_addr + entry.region_size
        rtype = _region_label(entry.region_type)
        color = _region_color(entry.region_type)
        prot = _protection_str(entry.protection)
        captured = _is_captured(entry.base_addr, entry.region_size, regions)
        cap_icon = "&#10003;" if captured else "&#10007;"
        cap_color = cs.ACCENT_GREEN if captured else cs.ACCENT_RED

        rows.append(
            f'<tr>'
            f'<td style="padding:3px 8px;color:{cs.ACCENT_CYAN};'
            f'font-family:monospace;">0x{entry.base_addr:X}</td>'
            f'<td style="padding:3px 8px;color:{cs.ACCENT_CYAN};'
            f'font-family:monospace;">0x{end_addr:X}</td>'
            f'<td style="padding:3px 8px;color:{cs.TEXT_PRIMARY};'
            f'text-align:right;">{_format_size(entry.region_size)}</td>'
            f'<td style="padding:3px 8px;color:{color};'
            f'text-align:center;">{rtype}</td>'
            f'<td style="padding:3px 8px;color:{cs.TEXT_PRIMARY};'
            f'text-align:center;font-family:monospace;">{prot}</td>'
            f'<td style="padding:3px 8px;color:{cs.TEXT_MUTED};">'
            f'{entry.mapped_path or "—"}</td>'
            f'<td style="padding:3px 8px;color:{cap_color};'
            f'text-align:center;">{cap_icon}</td>'
            f'</tr>'
        )

    html = (
        f'{cs.BASE_CSS}'
        f'<div class="memdiver-panel">'
        f'<div class="memdiver-header">VAS Map Details</div>'
        f'<table style="border-collapse:collapse;width:100%;">'
        f'<thead>{header}</thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        f'</table></div>'
    )
    return mo.Html(html)
