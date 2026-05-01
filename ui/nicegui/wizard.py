"""Wizard-driven onboarding for MemDiver."""

import logging
from pathlib import Path

from nicegui import ui

from ui.locales import _

logger = logging.getLogger("memdiver.ui.nicegui.wizard")


async def render_wizard(state, mode_mgr):
    """Render the 4-step onboarding wizard.

    Populates state fields and redirects to /workspace on completion.
    """
    from core.constants import INPUT_FILE, INPUT_DIRECTORY, INPUT_DATASET

    with ui.row().classes('w-full justify-end'):
        from ui.nicegui.theme import create_theme_toggle
        create_theme_toggle()

    with ui.stepper().props('vertical animated').classes('w-full max-w-2xl mx-auto') as stepper:

        # Step 1: Input type
        with ui.step(_('Input Type')):
            ui.label(_('What would you like to analyze?')).classes('text-lg mb-4')
            input_type = ui.radio(
                {
                    INPUT_FILE: _('Single File'),
                    INPUT_DIRECTORY: _('Run Directory'),
                    INPUT_DATASET: _('Research Dataset'),
                },
                value=state.input_mode or INPUT_DATASET,
            ).props('inline')
            with ui.stepper_navigation():
                ui.button(_('Next'), on_click=stepper.next).props('color=primary')

        # Step 2: Data selection
        with ui.step(_('Select Data')):
            ui.label(_('Choose your data source')).classes('text-lg mb-4')
            data_path = ui.input(_('Path'), placeholder=_('/path/to/dataset or file')).classes('w-full')
            # Pre-fill from state if available
            if state.dataset_root:
                data_path.value = state.dataset_root
            with ui.stepper_navigation():
                ui.button(_('Back'), on_click=stepper.previous).props('flat')
                ui.button(_('Next'), on_click=stepper.next).props('color=primary')

        # Step 3: Ground truth
        with ui.step(_('Ground Truth')):
            ui.label(_('Configure ground truth (optional)')).classes('text-lg mb-4')
            gt_mode = ui.radio(
                {
                    'auto': _('Auto-detect'),
                    'keylog': _('Specify keylog file'),
                    'none': _('Skip'),
                },
                value='auto',
            )
            keylog_input = ui.input(
                _('Keylog filename'),
                value='keylog.csv',
                placeholder='keylog.csv',
            ).classes('w-full')
            keylog_input.bind_visibility_from(gt_mode, 'value', value='keylog')
            with ui.stepper_navigation():
                ui.button(_('Back'), on_click=stepper.previous).props('flat')
                ui.button(_('Next'), on_click=stepper.next).props('color=primary')

        # Step 4: Analysis mode
        with ui.step(_('Analysis Mode')):
            ui.label(_('Select your workflow')).classes('text-lg mb-4')
            mode_radio = ui.radio(
                {
                    'testing': _('Testing -- focused key search'),
                    'research': _('Research -- full analysis suite'),
                },
                value=state.mode or 'testing',
            )
            with ui.stepper_navigation():
                ui.button(_('Back'), on_click=stepper.previous).props('flat')

                async def _launch():
                    # Populate state from wizard selections
                    state.input_mode = input_type.value
                    path_val = data_path.value.strip() if data_path.value else ''
                    if input_type.value == INPUT_DATASET:
                        state.dataset_root = path_val
                    elif input_type.value == INPUT_FILE:
                        state.single_file_path = path_val
                        state.input_path = path_val
                    else:
                        state.input_path = path_val
                    state.ground_truth_mode = gt_mode.value
                    if gt_mode.value == 'keylog':
                        state.keylog_filename = keylog_input.value or 'keylog.csv'
                    state.mode = mode_radio.value
                    mode_mgr.mode = mode_radio.value
                    logger.info("Wizard complete: mode=%s input=%s", state.mode, state.input_mode)
                    ui.navigate.to('/workspace')

                ui.button(_('Launch'), on_click=_launch).props('color=positive icon=rocket')
