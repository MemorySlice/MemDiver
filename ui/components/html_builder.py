"""HTML builder utilities for constructing UI elements."""

from typing import Any, Dict, List, Optional

from . import color_scheme as cs


def table(
    headers: List[str],
    rows: List[List[Any]],
    title: Optional[str] = None,
    col_styles: Optional[Dict[int, str]] = None,
) -> str:
    """Build an HTML table with dark theme styling."""
    parts = [cs.BASE_CSS]
    if title:
        parts.append(f'<div class="memdiver-header">{title}</div>')

    parts.append(
        '<table style="width:100%; border-collapse:collapse; font-size:13px;">'
    )
    # Header
    parts.append("<thead><tr>")
    for h in headers:
        parts.append(
            f'<th style="text-align:left; padding:6px 10px; color:{cs.TEXT_SECONDARY}; '
            f'border-bottom:1px solid {cs.BG_TERTIARY}; font-weight:normal;">{h}</th>'
        )
    parts.append("</tr></thead>")

    # Body
    parts.append("<tbody>")
    for row in rows:
        parts.append("<tr>")
        for i, cell in enumerate(row):
            style = col_styles.get(i, "") if col_styles else ""
            parts.append(
                f'<td style="padding:4px 10px; border-bottom:1px solid {cs.BG_TERTIARY}; '
                f'color:{cs.TEXT_PRIMARY}; {style}">{cell}</td>'
            )
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


def panel(content: str, title: Optional[str] = None) -> str:
    """Wrap content in a styled panel div."""
    parts = [cs.BASE_CSS, '<div class="memdiver-panel">']
    if title:
        parts.append(f'<div class="memdiver-header">{title}</div>')
    parts.append(content)
    parts.append("</div>")
    return "".join(parts)


def stat_row(label: str, value: Any, color: str = "") -> str:
    """Single label: value row."""
    val_color = color or cs.TEXT_PRIMARY
    return (
        f'<div style="display:flex; justify-content:space-between; padding:2px 0;">'
        f'<span class="memdiver-label">{label}</span>'
        f'<span style="color:{val_color}">{value}</span>'
        f'</div>'
    )


def badge(text: str, color: str = "") -> str:
    """Colored badge/pill."""
    bg = color or cs.ACCENT_BLUE
    return (
        f'<span style="background:{bg}; color:{cs.TEXT_BRIGHT}; padding:2px 8px; '
        f'border-radius:10px; font-size:11px;">{text}</span>'
    )


def color_cell(value: Any, color: str) -> str:
    """Wrap a value in a colored span."""
    return f'<span style="color:{color}">{value}</span>'


def format_size(size_bytes: int) -> str:
    """Format byte size as human-readable string (B/KB/MB/GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
