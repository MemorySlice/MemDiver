"""Investigation detail panel for a selected offset in the hex viewer."""

import logging
from typing import Any

logger = logging.getLogger("memdiver.ui.views.investigation_panel")

_ENT_COLORS: dict = {}
_VAR_COLORS: dict = {}


def _init_colors(cs):
    """Populate color maps lazily from color_scheme module."""
    if not _ENT_COLORS:
        _ENT_COLORS.update({"low": cs.ACCENT_GREEN, "medium": cs.ACCENT_YELLOW,
                            "high": cs.ACCENT_ORANGE, "random": cs.ACCENT_RED})
        _VAR_COLORS.update({"static": cs.VARIANCE_INVARIANT,
                            "invariant": cs.VARIANCE_INVARIANT,
                            "key_candidate": cs.VARIANCE_KEY_CANDIDATE,
                            "high": cs.VARIANCE_KEY_CANDIDATE})


def _badge(label: str, color: str, bg: str) -> str:
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:3px;'
            f'font-size:11px;color:{color};background:{bg};">{label}</span>')


def render_investigation(
    mo, dump_data: bytes, offset: int,
    variance: list = None, hits: list = None, title: str = "Investigation",
) -> Any:
    """Render an investigation panel for a specific byte offset.

    Args:
        mo: marimo module.
        dump_data: Raw dump bytes.
        offset: Byte offset to investigate.
        variance: Optional per-byte variance values.
        hits: Optional list of SecretHit matches.
        title: Panel title.

    Returns:
        mo.Html with the rendered investigation panel.
    """
    from core.region_analysis import RegionReport, analyze_region
    from ui.components import color_scheme as cs
    from ui.components.hex_renderer import render_hex_line

    if offset < 0 or offset >= len(dump_data):
        return mo.md("*Offset out of range*")

    _init_colors(cs)
    rpt: RegionReport = analyze_region(dump_data, offset, variance=variance, hits=hits)
    s: list[str] = []

    # Title row
    s.append(f'<div class="memdiver-header">{title} &mdash; '
             f'0x{offset:08x} ({offset})</div>')

    # Byte value
    bv = rpt.byte_value
    asc = f'<code>{chr(bv)}</code>' if 32 <= bv < 127 else "non-printable"
    s.append(f'<div style="margin-bottom:8px;font-size:12px;">'
             f'<span style="color:{cs.TEXT_SECONDARY};">Byte:</span> '
             f'<code style="color:{cs.ACCENT_CYAN};">0x{bv:02x}</code> '
             f'({bv}) &mdash; {asc}</div>')

    # Entropy gauge
    ec = _ENT_COLORS.get(rpt.entropy_level, cs.TEXT_PRIMARY)
    pct = min(rpt.entropy / 8.0 * 100, 100)
    s.append(
        f'<div style="margin-bottom:8px;">'
        f'<span style="color:{cs.TEXT_SECONDARY};font-size:12px;">Entropy:</span> '
        f'<span style="display:inline-block;width:120px;height:10px;'
        f'background:{cs.BG_TERTIARY};border-radius:3px;vertical-align:middle;'
        f'margin:0 6px;overflow:hidden;">'
        f'<span style="display:block;width:{pct:.0f}%;height:100%;'
        f'background:{ec};border-radius:3px;"></span></span>'
        f'<span style="color:{ec};font-size:12px;">'
        f'{rpt.entropy:.2f} ({rpt.entropy_level})</span></div>')

    # Variance badge
    if rpt.variance_at_offset is not None:
        vc = rpt.variance_class or ""
        vcol = _VAR_COLORS.get(vc, cs.TEXT_SECONDARY)
        s.append(f'<div style="margin-bottom:8px;">'
                 f'<span style="color:{cs.TEXT_SECONDARY};font-size:12px;">'
                 f'Variance:</span> {rpt.variance_at_offset:.1f} '
                 f'{_badge(vc, vcol, cs.BG_TERTIARY)}</div>')

    # Matching secrets table
    if rpt.matching_secrets:
        rows = "".join(
            f'<tr><td style="padding:2px 8px;color:{cs.ACCENT_CYAN};">'
            f'{h.secret_type}</td><td style="padding:2px 8px;color:{cs.TEXT_PRIMARY};">'
            f'0x{h.offset:x}&ndash;0x{h.offset + h.length:x}</td></tr>'
            for h in rpt.matching_secrets)
        s.append(f'<div style="margin-bottom:8px;">'
                 f'<span style="color:{cs.TEXT_SECONDARY};font-size:12px;">'
                 f'Matching Secrets:</span>'
                 f'<table style="border-collapse:collapse;margin-top:4px;">'
                 f'{rows}</table></div>')

    # Strings found nearby
    if rpt.strings:
        items = ", ".join(f'<code style="color:{cs.ACCENT_GREEN};">'
                          f'{st.value[:40]}</code>' for st in rpt.strings[:8])
        s.append(f'<div style="margin-bottom:8px;">'
                 f'<span style="color:{cs.TEXT_SECONDARY};font-size:12px;">'
                 f'Strings nearby:</span> {items}</div>')

    # 16-byte context: line before + line containing offset
    row_start = (offset // 16) * 16
    for ctx in (max(0, row_start - 16), row_start):
        if ctx + 16 <= len(dump_data):
            chunk = dump_data[ctx:ctx + 16]
            hl = {offset} if ctx == row_start else None
            line = render_hex_line(chunk, ctx, highlight_offsets=hl)
            s.append(f'<pre style="font-family:monospace;font-size:12px;'
                     f'line-height:1.4;margin:0;padding:2px 0;">{line}</pre>')

    return mo.Html(f'{cs.BASE_CSS}<div class="memdiver-panel">{"".join(s)}</div>')
