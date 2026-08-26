"""Setup wizard for optional dependency onboarding."""

import json
import logging
import subprocess
import sys
from pathlib import Path

from memdiver.ui.locales import _

logger = logging.getLogger("memdiver.ui.components.setup_wizard")


def _config_path() -> Path:
    """Return the path to user preferences config file."""
    from memdiver.core.constants import memdiver_home
    return memdiver_home() / "config.json"


def _load_prefs() -> dict:
    """Load user preferences from ~/.memdiver/config.json."""
    p = _config_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_prefs(prefs: dict) -> None:
    """Save user preferences."""
    p = _config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(prefs, indent=2))


def should_show_wizard() -> bool:
    """Check if the wizard should be shown.

    Shows when DuckDB is not installed and user hasn't opted to skip.
    """
    from memdiver.engine.project_db import check_deps
    if check_deps().get("ready"):
        return False
    prefs = _load_prefs()
    return not prefs.get("skip_duckdb_setup", False)


def _run_install() -> tuple[bool, str]:
    """Run pip install and return (success, output).

    Reinstalls forcibly, and runs the same command ``install_hint()`` shows: the
    wizard only fires when a BASE dependency (DuckDB/Ibis) is absent, and a
    plain ``pip install memdiver`` would report "already satisfied" and repair
    nothing.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--force-reinstall", "memdiver"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return True, _("Installation successful! Please restart MemDiver to activate.")
        return False, _("Installation failed:\n{error}").format(error=result.stderr[-500:])
    except subprocess.TimeoutExpired:
        return False, _("Installation timed out after 120 seconds.")
    except Exception as e:
        return False, _("Installation error: {error}").format(error=e)


def render_setup_wizard(mo, install_btn, skip_btn):
    """Render the full wizard banner.

    Args:
        mo: marimo module
        install_btn: mo.ui.button for install action
        skip_btn: mo.ui.button for skip/dismiss action

    Returns:
        mo.callout element or None if wizard shouldn't show
    """
    if not should_show_wizard():
        return None

    from memdiver.engine.project_db import install_hint

    hint = install_hint()

    # Check if install was clicked
    if install_btn.value > 0:
        success, message = _run_install()
        if success:
            return mo.callout(
                mo.vstack([
                    mo.md(_("**Analysis history is ready!**")),
                    mo.md(message),
                ]),
                kind="success",
            )
        else:
            return mo.callout(
                mo.vstack([
                    mo.md(_("**Installation issue**")),
                    mo.md(message),
                    mo.md(_("You can also install manually: `{hint}`").format(hint=hint)),
                ]),
                kind="danger",
            )

    # Check if skip was clicked
    if skip_btn.value > 0:
        prefs = _load_prefs()
        prefs["skip_duckdb_setup"] = True
        _save_prefs(prefs)
        return None

    # Default: show the wizard
    content = mo.vstack([
        mo.md(_("**Unlock persistent analysis history**")),
        mo.md(
            _(
                "MemDiver can save your analysis results across sessions using a "
                "local database. This requires two optional packages (DuckDB + "
                "Ibis) — a one-time install, no configuration needed."
            )
        ),
        mo.hstack(
            [
                install_btn,
                mo.md(_("&nbsp; or install manually: `{hint}`").format(hint=hint)),
            ],
            justify="start",
            gap=0.5,
        ),
        mo.hstack(
            [
                skip_btn,
                mo.md(_("&nbsp; _(you can enable this later in settings)_")),
            ],
            justify="start",
            gap=0.5,
        ),
    ])
    return mo.callout(content, kind="info")


def create_wizard_buttons(mo):
    """Create the wizard's interactive buttons.

    Returns (install_btn, skip_btn) -- must be created in a separate cell
    from rendering to enable Marimo's reactivity.
    """
    install_btn = mo.ui.button(
        value=0,
        on_click=lambda v: v + 1,
        label=_("Install now"),
        kind="success",
    )
    skip_btn = mo.ui.button(
        value=0,
        on_click=lambda v: v + 1,
        label=_("Skip for now"),
        kind="warn",
    )
    return install_btn, skip_btn
