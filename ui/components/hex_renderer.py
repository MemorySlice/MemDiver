"""Hex rendering utilities for dump visualization."""

from typing import Dict, List, Optional, Tuple

from . import color_scheme as cs


def render_hex_line(
    data: bytes,
    offset: int,
    byte_classes: Optional[List[str]] = None,
    highlight_offsets: Optional[set] = None,
    bytes_per_row: int = 16,
) -> str:
    """Render a single line of hex dump as HTML.

    Args:
        data: Raw bytes for this line.
        offset: Starting offset of this line in the dump.
        byte_classes: Classification for each byte ('key', 'same', 'different').
        highlight_offsets: Set of absolute offsets to highlight.
        bytes_per_row: Bytes per row (default 16).

    Returns:
        HTML string for one hex line.
    """
    parts = []
    # Offset column
    parts.append(f'<span style="color:{cs.TEXT_SECONDARY}">{offset:08x}</span>  ')

    # Hex bytes
    for i, byte in enumerate(data):
        abs_offset = offset + i
        color = _byte_color(
            byte,
            byte_classes[i] if byte_classes and i < len(byte_classes) else None,
        )
        highlighted = highlight_offsets and abs_offset in highlight_offsets
        bg = cs.BG_SELECTED if highlighted else "transparent"
        parts.append(
            f'<span style="color:{color};background:{bg}">{byte:02x}</span>'
        )
        if i == 7:
            parts.append(" ")
        parts.append(" ")

    # Padding if line is short
    pad = bytes_per_row - len(data)
    parts.append("   " * pad)
    if len(data) <= 8:
        parts.append(" ")

    parts.append(" |")
    # ASCII column
    for i, byte in enumerate(data):
        color = _byte_color(
            byte,
            byte_classes[i] if byte_classes and i < len(byte_classes) else None,
        )
        char = chr(byte) if 32 <= byte < 127 else "."
        parts.append(f'<span style="color:{color}">{_html_escape(char)}</span>')
    parts.append("|")

    return "".join(parts)


def render_hex_dump(
    data: bytes,
    start_offset: int = 0,
    byte_classes: Optional[List[str]] = None,
    highlight_offsets: Optional[set] = None,
    bytes_per_row: int = 16,
    max_rows: int = 64,
) -> str:
    """Render a full hex dump as an HTML block."""
    lines = []
    for row in range(0, min(len(data), max_rows * bytes_per_row), bytes_per_row):
        end = min(row + bytes_per_row, len(data))
        row_data = data[row:end]
        row_classes = byte_classes[row:end] if byte_classes else None
        lines.append(render_hex_line(
            row_data, start_offset + row, row_classes,
            highlight_offsets, bytes_per_row,
        ))

    content = "\n".join(lines)
    return (
        f'<pre style="font-family: monospace; font-size: 12px; line-height: 1.4; '
        f'background: {cs.BG_PRIMARY}; padding: 12px; border-radius: 4px; '
        f'overflow-x: auto;">{content}</pre>'
    )


def _byte_color(byte_val: int, classification: Optional[str] = None) -> str:
    """Determine the display color for a byte."""
    if classification == "key":
        return cs.COLOR_KEY
    elif classification == "same":
        return cs.COLOR_SAME
    elif classification == "different":
        return cs.COLOR_DIFFERENT
    elif byte_val == 0:
        return cs.COLOR_ZERO
    elif 32 <= byte_val < 127:
        return cs.COLOR_ASCII
    else:
        return cs.TEXT_PRIMARY


def _html_escape(char: str) -> str:
    """Escape HTML special characters."""
    return (
        char.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
