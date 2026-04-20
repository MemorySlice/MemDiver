"""IDA-Pro-style workspace layout for MemDiver."""

import logging
from pathlib import Path

from nicegui import ui

from ui.components.header import load_logo_b64

logger = logging.getLogger("memdiver.ui.nicegui.workspace")


def _render_toolbar(state, mode_mgr):
    """Top toolbar with logo, mode indicator, and action buttons."""
    with ui.row().classes('w-full items-center memdiver-toolbar'):
        b64 = load_logo_b64()
        if b64:
            ui.image(f'data:image/svg+xml;base64,{b64}').classes('w-8 h-8')
        ui.label('MemDiver').classes('text-xl font-bold')
        ui.space()
        mode_label = 'Research' if mode_mgr.is_research else 'Testing'
        ui.badge(mode_label, color='blue' if mode_mgr.is_research else 'green')
        if state.dataset_root:
            ui.label(f'{state.input_mode}').classes('text-sm text-gray-400')
        ui.space()
        ui.button('Save', icon='save', on_click=lambda: ui.notify('Session saved')).props('flat dense')
        ui.button('New', icon='add', on_click=lambda: ui.navigate.to('/wizard')).props('flat dense')
        ui.button('Sandbox', icon='science', on_click=lambda: ui.notify('Sandbox coming soon')).props('flat dense')
        from ui.nicegui.theme import create_theme_toggle
        create_theme_toggle()


def _render_left_panel(state):
    """Left navigation panel -- data tree and secrets list."""
    with ui.column().classes('w-full h-full p-2'):
        ui.label('Navigation').classes('panel-header')
        with ui.expansion('Data Selection', icon='folder_open').classes('w-full'):
            ui.label(f'Input: {state.input_mode}').classes('text-sm')
            if state.dataset_root:
                ui.label(f'Root: {Path(state.dataset_root).name}').classes('text-sm text-gray-400')
            if state.protocol_version:
                ui.label(f'Protocol: {state.protocol_name} {state.protocol_version}').classes('text-sm')
            if state.scenario:
                ui.label(f'Scenario: {state.scenario}').classes('text-sm')
        with ui.expansion('Secrets', icon='vpn_key').classes('w-full'):
            ui.label('Run analysis to discover secrets').classes('text-sm text-gray-400 italic')
        with ui.expansion('Bookmarks', icon='bookmark').classes('w-full'):
            ui.label('No bookmarks yet').classes('text-sm text-gray-400 italic')


def _render_center_panel(state):
    """Center panel -- hex viewer placeholder (wired in Phase B)."""
    with ui.column().classes('w-full h-full'):
        ui.label('Hex Viewer').classes('panel-header')
        if state.selected_phase:
            ui.label(f'Phase: {state.selected_phase}').classes('text-sm text-gray-400 px-3')
        with ui.element('div').classes('hex-panel p-3 flex-grow'):
            ui.html(
                '<pre style="color: #d4d4d4;">Select a dump file to view hex data.\n\n'
                'Use the wizard to load a dataset,\n'
                'then select a library and phase.</pre>'
            )


def _render_right_panel(state):
    """Right panel -- investigation details placeholder."""
    with ui.column().classes('w-full h-full p-2'):
        ui.label('Investigation').classes('panel-header')
        ui.html(
            '<div style="color: #808080; padding: 12px; font-size: 13px;">'
            'Click an offset in the hex view<br>to investigate byte details.<br><br>'
            '<b>Features:</b><br>'
            '- Byte value &amp; entropy<br>'
            '- Variance classification<br>'
            '- Matching secrets<br>'
            '- Nearby strings</div>'
        )


def _render_bottom_panel(state, mode_mgr):
    """Bottom panel -- analysis view tabs."""
    tabs = ['Results', 'Heatmap']
    if mode_mgr.is_research:
        tabs.extend([
            'Entropy', 'Variance', 'Consensus',
            'Phase Lifecycle', 'Cross-Library', 'Comparison', 'VAS',
        ])

    with ui.tabs().classes('w-full') as tab_bar:
        tab_refs = {name: ui.tab(name) for name in tabs}

    with ui.tab_panels(tab_bar).classes('w-full'):
        for name in tabs:
            with ui.tab_panel(name):
                ui.label(f'{name} view -- run analysis to populate').classes(
                    'text-gray-400 italic p-4')


async def render_workspace(state, mode_mgr):
    """Render the full IDA-Pro-style workspace layout.

    Args:
        state: AppState instance with current selections.
        mode_mgr: ModeManager controlling Testing/Research mode.
    """
    _render_toolbar(state, mode_mgr)

    # Main area: left | center | right via nested splitters
    with ui.splitter(value=80).classes(
        'w-full memdiver-splitter'
    ).style('height: calc(100vh - 140px)') as main_split:
        with main_split.before:
            with ui.splitter(value=20).classes('h-full memdiver-splitter') as top_split:
                with top_split.before:
                    _render_left_panel(state)
                with top_split.after:
                    with ui.splitter(value=75).classes('h-full memdiver-splitter') as center_split:
                        with center_split.before:
                            _render_center_panel(state)
                        with center_split.after:
                            _render_right_panel(state)
        with main_split.after:
            _render_bottom_panel(state, mode_mgr)
