"""IDA-Pro-style workspace layout for MemDiver."""

import logging
from pathlib import Path

from nicegui import ui

from engine.session_store import SessionStore, snapshot_from_state
from ui.components.header import load_logo_b64
from ui.locales import _

logger = logging.getLogger("memdiver.ui.nicegui.workspace")


def _save_session(state) -> None:
    """Persist current AppState to a timestamped .memdiver session file."""
    try:
        snapshot = snapshot_from_state(state)
        save_path = SessionStore.auto_save_path("manual")
        SessionStore.save(snapshot, save_path)
        ui.notify(_("Session saved to {path}").format(path=save_path))
    except Exception as exc:  # noqa: BLE001 - surfaced to user
        logger.exception("Manual session save failed")
        ui.notify(_("Save failed: {error}").format(error=exc), type='negative')


def _render_toolbar(state, mode_mgr):
    """Top toolbar with logo, mode indicator, and action buttons."""
    with ui.row().classes('w-full items-center memdiver-toolbar'):
        b64 = load_logo_b64()
        if b64:
            ui.image(f'data:image/svg+xml;base64,{b64}').classes('w-8 h-8')
        ui.label(_('MemDiver')).classes('text-xl font-bold')
        ui.space()
        mode_label = _('Research') if mode_mgr.is_research else _('Testing')
        ui.badge(mode_label, color='blue' if mode_mgr.is_research else 'green')
        if state.dataset_root:
            ui.label(f'{state.input_mode}').classes('text-sm text-gray-400')
        ui.space()
        ui.button(_('Save'), icon='save', on_click=lambda: _save_session(state)).props('flat dense')
        ui.button(_('New'), icon='add', on_click=lambda: ui.navigate.to('/wizard')).props('flat dense')
        from ui.nicegui.theme import create_theme_toggle
        create_theme_toggle()


def _render_left_panel(state):
    """Left navigation panel -- data tree and secrets list."""
    with ui.column().classes('w-full h-full p-2'):
        ui.label(_('Navigation')).classes('panel-header')
        with ui.expansion(_('Data Selection'), icon='folder_open').classes('w-full'):
            ui.label(_('Input: {mode}').format(mode=state.input_mode)).classes('text-sm')
            if state.dataset_root:
                ui.label(_('Root: {name}').format(name=Path(state.dataset_root).name)).classes('text-sm text-gray-400')
            if state.protocol_version:
                ui.label(_('Protocol: {name} {version}').format(name=state.protocol_name, version=state.protocol_version)).classes('text-sm')
            if state.scenario:
                ui.label(_('Scenario: {scenario}').format(scenario=state.scenario)).classes('text-sm')


def _render_bottom_panel(state, mode_mgr):
    """Bottom panel -- pointer to the React workspace for analysis tabs."""
    with ui.column().classes('w-full h-full items-center justify-center p-6'):
        ui.label(
            _('Analysis tabs have moved to the React workspace. Run `memdiver web` for interactive charts.')
        ).classes('text-gray-400 italic text-center')


async def render_workspace(state, mode_mgr):
    """Render the full IDA-Pro-style workspace layout.

    Args:
        state: AppState instance with current selections.
        mode_mgr: ModeManager controlling Testing/Research mode.
    """
    _render_toolbar(state, mode_mgr)

    # Main area: left navigation column + banner pointing at the React workspace.
    with ui.splitter(value=25).classes(
        'w-full memdiver-splitter'
    ).style('height: calc(100vh - 140px)') as main_split:
        with main_split.before:
            _render_left_panel(state)
        with main_split.after:
            _render_bottom_panel(state, mode_mgr)
