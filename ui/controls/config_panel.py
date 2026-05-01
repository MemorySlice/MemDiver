"""Dataset configuration control panel."""

import logging
from pathlib import Path
from typing import Any, Tuple

from ui.locales import _

logger = logging.getLogger("memdiver.ui.controls.config")


def create_config_controls(mo, state: Any) -> Tuple:
    """Create the dataset configuration UI controls.

    Args:
        mo: The marimo runtime module (passed at runtime, not imported).
        state: An AppState instance holding current configuration values.

    Returns:
        Tuple of (dataset_browser, keylog_input, template_dropdown, scan_button).
    """
    from core.keylog_templates import list_template_names

    dataset_browser = mo.ui.file_browser(
        initial_path=state.dataset_root or str(Path.home()),
        selection_mode="directory",
        multiple=False,
        label=_("Dataset Root"),
    )
    keylog_input = mo.ui.text(
        value=state.keylog_filename,
        label=_("Keylog Filename (optional)"),
        placeholder=_("Leave empty to skip"),
    )
    template_dropdown = mo.ui.dropdown(
        options=list_template_names(),
        value=state.template_name,
        label=_("Keylog Template"),
    )
    scan_button = mo.ui.button(
        value=0,
        on_click=lambda v: v + 1,
        label=_("Scan Dataset"),
        kind="success",
    )
    return dataset_browser, keylog_input, template_dropdown, scan_button


def render_config_panel(
    mo,
    dataset_browser,
    keylog_input,
    template_dropdown,
    scan_button,
) -> Any:
    """Render the config panel layout.

    Args:
        mo: The marimo runtime module.
        dataset_browser: File browser for selecting the dataset root directory.
        keylog_input: Text input for the keylog filename.
        template_dropdown: Dropdown for keylog template selection.
        scan_button: Button to trigger dataset scanning.

    Returns:
        A marimo vstack layout element.
    """
    return mo.vstack([
        dataset_browser,
        mo.hstack([keylog_input, template_dropdown], justify="start", gap=1),
        scan_button,
    ])


def render_scan_results(mo, dataset_info) -> Any:
    """Render dataset scan results as markdown.

    Args:
        mo: The marimo runtime module.
        dataset_info: A DatasetInfo instance from DatasetScanner, or None.

    Returns:
        A marimo markdown element summarizing the scan results.
    """
    if dataset_info is None:
        return mo.md(
            "*No dataset scanned yet. Click 'Scan Dataset' to begin.*"
        )

    lines = [
        f"**Protocol Versions**: {', '.join(sorted(dataset_info.protocol_versions))}",
        f"**Total Runs**: {dataset_info.total_runs}",
    ]
    for ver in sorted(dataset_info.protocol_versions):
        scenarios = dataset_info.scenarios.get(ver, [])
        lines.append(f"- TLS {ver}: {len(scenarios)} scenario(s)")
        for sc in scenarios:
            libs = dataset_info.libraries.get(sc, set())
            lines.append(f"  - {sc}: {len(libs)} libraries")

    return mo.md("\n".join(lines))
