"""Framework-agnostic rendering adapters.

Views call these helpers instead of framework-specific APIs.
The active framework is auto-detected at import time.
"""

import logging

logger = logging.getLogger("memdiver.ui.adapters")

# Detect available frameworks
_NICEGUI = False
_MARIMO = False

try:
    from nicegui import ui as _nui
    _NICEGUI = True
except ImportError:
    pass

try:
    import marimo as _mo
    _MARIMO = True
except ImportError:
    pass


def render_html(html_content: str, framework: str = "auto"):
    """Render an HTML string in the active UI framework."""
    fw = _resolve(framework)
    if fw == "nicegui":
        _nui.html(html_content)
    elif fw == "marimo":
        return _mo.Html(html_content)
    return html_content


def render_plotly(fig, framework: str = "auto"):
    """Render a Plotly figure in the active UI framework."""
    fw = _resolve(framework)
    if fw == "nicegui":
        _nui.plotly(fig).classes("w-full")
    elif fw == "marimo":
        return _mo.ui.plotly(fig)
    return fig


def _resolve(framework: str) -> str:
    """Resolve 'auto' to the available framework."""
    if framework != "auto":
        return framework
    if _NICEGUI:
        return "nicegui"
    if _MARIMO:
        return "marimo"
    return "raw"
