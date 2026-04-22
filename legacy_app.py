"""MemDiver -- NiceGUI entry point (legacy).

Usage: python legacy_app.py
"""

import asyncio
import sys
from pathlib import Path

# Ensure memdiver root is on the path
_root = Path(__file__).parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from nicegui import ui, app  # noqa: E402

from core.log import setup_logging  # noqa: E402
from ui.state import AppState  # noqa: E402
from ui.mode import ModeManager  # noqa: E402


def _detect_startup(state):
    """Detect startup scenario and return (scenario, sessions).

    Returns:
        Tuple of (scenario_str, session_list). scenario_str is one of
        'first_run', 'restore', or 'normal'. session_list may be non-empty
        when scenario is 'restore' (avoids re-listing later).
    """
    if state.dataset_root and state.input_mode:
        return 'normal', []
    try:
        from engine.session_store import SessionStore
        sessions = SessionStore.list_sessions()
        if sessions and sessions[0].get('input_mode'):
            return 'restore', sessions
    except (ImportError, OSError):
        pass
    try:
        from engine.project_db import default_db_path
        if not default_db_path().exists():
            return 'first_run', []
    except ImportError:
        pass
    return 'normal', []


def main():
    """Initialize and start the MemDiver NiceGUI application."""
    config_path = _root / "config.json"
    logger = setup_logging(config_path=config_path)
    logger.info("MemDiver starting (NiceGUI)")

    state = AppState(config_path=config_path)
    mode_mgr = ModeManager(initial_mode=state.mode)

    startup, cached_sessions = _detect_startup(state)
    logger.info("Startup scenario: %s", startup)

    def _on_shutdown():
        try:
            from engine.session_store import snapshot_from_state, SessionStore
            snapshot = snapshot_from_state(state)
            save_path = SessionStore.auto_save_path("autosave")
            SessionStore.save(snapshot, save_path)
            logger.info("Session autosaved to %s", save_path)
        except Exception as exc:
            logger.warning("Autosave failed: %s", exc)
        logger.info("MemDiver shutting down")

    app.on_shutdown(_on_shutdown)

    from ui.nicegui.theme import apply_theme
    from ui.nicegui.api_routes import register_api_routes
    register_api_routes()

    @ui.page("/")
    async def index():
        """Splash screen with logo and spinner, then redirect."""
        apply_theme()
        from ui.components.header import load_logo_b64
        with ui.column().classes('w-full h-screen items-center justify-center'):
            with ui.row().classes('items-center gap-4'):
                b64 = load_logo_b64()
                if b64:
                    ui.image(f'data:image/svg+xml;base64,{b64}').classes('w-20 h-20')
                ui.label('MemDiver').classes('text-4xl font-bold')
            ui.spinner('dots', size='xl').classes('mt-8')
            messages = {
                'first_run': 'Setting up for first use...',
                'restore': 'Restoring previous session...',
                'normal': 'Starting...',
            }
            ui.label(messages.get(startup, 'Starting...')).classes('text-gray-400 mt-4')

        if startup == 'restore':
            try:
                from engine.session_store import SessionStore, restore_state
                sessions = cached_sessions or SessionStore.list_sessions()
                if sessions:
                    snapshot = SessionStore.load(Path(sessions[0]['path']))
                    restore_state(state, snapshot, mode_mgr)
                    logger.info("Session restored from %s", sessions[0]['path'])
            except Exception as exc:
                logger.warning("Session restore failed: %s", exc)
            target = '/workspace' if (state.input_mode and state.dataset_root) else '/wizard'
            delay = 1.0
        elif startup == 'first_run':
            target = '/wizard'
            delay = 1.5
        else:
            target = '/workspace' if (state.input_mode and state.dataset_root) else '/wizard'
            delay = 0.5

        await asyncio.sleep(delay)
        ui.navigate.to(target)

    @ui.page("/wizard")
    async def wizard_page():
        """Onboarding wizard."""
        apply_theme()
        from ui.nicegui.wizard import render_wizard
        await render_wizard(state, mode_mgr)

    @ui.page("/workspace")
    async def workspace_page():
        """Main analysis workspace."""
        apply_theme()
        from ui.nicegui.workspace import render_workspace
        await render_workspace(state, mode_mgr)

    try:
        ui.run(
            title="MemDiver",
            port=8080,
            reload=False,
            show=True,
        )
    except KeyboardInterrupt:
        _on_shutdown()


if __name__ == "__main__":
    main()
