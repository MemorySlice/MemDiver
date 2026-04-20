"""MemDiver theme for NiceGUI with light/dark mode toggle."""

from nicegui import ui

from ui.components.color_scheme import BASE_CSS


# Single-user desktop app: one dark_mode binding cached for the process.
# Multi-user deployments would need per-session storage instead.
_dark_mode = None


def apply_theme(dark: bool = True):
    """Apply MemDiver theme. Call once per page."""
    global _dark_mode
    if _dark_mode is None:
        _dark_mode = ui.dark_mode(dark)
    ui.add_css(BASE_CSS)
    ui.add_css(_EXTRA_CSS)


def toggle_dark_mode() -> bool:
    """Toggle between light and dark mode. Returns new dark state."""
    if _dark_mode is not None:
        _dark_mode.value = not _dark_mode.value
        return _dark_mode.value
    return True


def is_dark() -> bool:
    """Return current dark mode state."""
    if _dark_mode is not None:
        return _dark_mode.value
    return True


def create_theme_toggle():
    """Create a dark/light mode toggle button with reactive icon update."""
    icon = 'dark_mode' if is_dark() else 'light_mode'
    btn = ui.button(icon=icon).props('flat dense').tooltip('Toggle light/dark mode')

    def _on_click():
        new_dark = toggle_dark_mode()
        new_icon = 'dark_mode' if new_dark else 'light_mode'
        btn.props(f'icon={new_icon}')

    btn.on_click(_on_click)
    return btn


_EXTRA_CSS = """
body {
    font-family: 'Segoe UI', system-ui, sans-serif;
}
.hex-panel {
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 13px;
    line-height: 1.4;
    overflow-x: auto;
}
.panel-header {
    font-weight: 600;
    font-size: 14px;
    padding: 8px 12px;
    border-bottom: 1px solid #3d3d3d;
}
.memdiver-splitter .q-splitter__separator {
    background-color: #3d3d3d;
}
.memdiver-toolbar {
    padding: 4px 12px;
    border-bottom: 1px solid #3d3d3d;
}
"""
