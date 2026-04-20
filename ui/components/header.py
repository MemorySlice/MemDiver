"""Branded header component with MemDiver logo."""

import base64
import logging
from pathlib import Path

logger = logging.getLogger("memdiver.ui.components.header")

_LOGO_RELATIVE = "misc/memdiver_icon_final.svg"


_logo_cache = None


def load_logo_b64():
    """Load SVG logo as base64 string (cached). Returns None on failure."""
    global _logo_cache
    if _logo_cache is not None:
        return _logo_cache
    project_root = Path(__file__).parent.parent.parent
    logo_path = project_root / _LOGO_RELATIVE
    try:
        _logo_cache = base64.b64encode(logo_path.read_bytes()).decode("ascii")
        return _logo_cache
    except OSError as e:
        logger.warning("Failed to load logo: %s", e)
        return None


def render_header(mo):
    """Render a branded header with the MemDiver logo and metallic blue title.

    Args:
        mo: The marimo runtime module.

    Returns:
        A marimo Html element with logo, title, and subtitle.
    """
    b64 = load_logo_b64()
    logo_html = ""
    if b64:
        logo_html = (
            f'<img src="data:image/svg+xml;base64,{b64}" '
            f'alt="MemDiver" height="48" '
            f'style="vertical-align: middle; flex-shrink: 0;" />'
        )
    title_style = (
        "background: linear-gradient(135deg, #4A90D9, #7BB3F0, #4A90D9);"
        " -webkit-background-clip: text; -webkit-text-fill-color: transparent;"
        " background-clip: text; font-size: 40px; font-weight: 800;"
        " font-family: Inter, 'Segoe UI', system-ui, sans-serif;"
        " line-height: 1; margin: 0;"
    )
    subtitle_style = (
        "font-size: 14px; color: #808080; margin: 2px 0 0 0;"
        " font-family: Inter, 'Segoe UI', system-ui, sans-serif;"
    )
    html = (
        f'<div style="display:flex; align-items:center; gap:8px;">'
        f'{logo_html}'
        f'<div>'
        f'<div style="{title_style}">MemDiver</div>'
        f'<div style="{subtitle_style}">Memory Dump Analysis Platform</div>'
        f'</div>'
        f'</div>'
    )
    return mo.Html(html)
