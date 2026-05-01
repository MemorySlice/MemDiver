"""Analysis control panel - algorithm selection, run button, mode toggle."""

import logging
from typing import Any, Tuple

from ui.locales import _
from ui.mode import ModeManager

logger = logging.getLogger("memdiver.ui.controls.analysis")


def create_analysis_controls(mo, mode_manager: ModeManager) -> Tuple:
    """Create analysis control UI elements.

    Args:
        mo: The marimo runtime module (passed at runtime, not imported).
        mode_manager: A ModeManager instance providing algorithm lists
            and mode state.

    Returns:
        Tuple of (algorithm_dropdown, run_button, mode_toggle).
    """
    algorithms = mode_manager.get_algorithms()

    algo_dropdown = mo.ui.dropdown(
        options=algorithms,
        value=algorithms[0] if algorithms else "exact_match",
        label=_("Algorithm"),
    )
    run_button = mo.ui.button(
        value=0,
        on_click=lambda v: v + 1,
        label=_("Run Analysis"),
        kind="success",
    )
    mode_toggle = mo.ui.switch(
        value=mode_manager.is_research,
        label=_("Research Mode"),
    )
    return algo_dropdown, run_button, mode_toggle


def render_analysis_panel(
    mo,
    algo_dropdown,
    run_button,
    mode_toggle,
    mode_manager: ModeManager,
) -> Any:
    """Render the analysis panel layout with mode info.

    Args:
        mo: The marimo runtime module.
        algo_dropdown: Dropdown for algorithm selection.
        run_button: Button to trigger analysis.
        mode_toggle: Switch for Testing/Research mode.
        mode_manager: A ModeManager instance for summary display.

    Returns:
        A marimo vstack layout element.
    """
    mode_info = mode_manager.summary()
    return mo.vstack([
        mo.md("### Analysis"),
        mo.hstack([
            algo_dropdown,
            run_button,
            mode_toggle,
        ], justify="start", gap=1),
        mo.md(
            f"**Mode**: {mode_info['mode']} - {mode_info['description']}"
        ),
    ])


def render_mode_banner(mo, mode_manager: ModeManager) -> Any:
    """Render a mode indicator banner.

    Args:
        mo: The marimo runtime module.
        mode_manager: A ModeManager instance.

    Returns:
        A marimo callout element showing active mode and features.
    """
    if mode_manager.is_research:
        return mo.callout(
            mo.md(
                "**Research Mode** -- Full analysis suite active: "
                "entropy profiling, variance mapping, consensus matrix, "
                "cross-library comparison, differential analysis, "
                "pattern architect, derived key expansion"
            ),
            kind="info",
        )
    return mo.callout(
        mo.md("**Testing Mode** -- Validate patterns against dumps"),
        kind="neutral",
    )


def render_results_summary(mo, analysis_result) -> Any:
    """Render a summary table of analysis results.

    Args:
        mo: The marimo runtime module.
        analysis_result: An analysis result object with a `libraries`
            attribute containing per-library report objects, or None.

    Returns:
        A marimo Html element with the results table, or a placeholder
        markdown element when no results are available.
    """
    if analysis_result is None:
        return mo.md("*No analysis results yet.*")

    from ui.components.html_builder import table, badge, color_cell
    from ui.components import color_scheme as cs

    headers = ["Library", "Phase", "Runs", "Hits", "Status"]
    rows = []
    for report in analysis_result.libraries:
        hit_count = len(report.hits)
        if hit_count > 0:
            status = badge("Found", cs.ACCENT_GREEN)
        else:
            status = badge("None", cs.ACCENT_RED)

        hit_color = cs.ACCENT_CYAN if hit_count else cs.TEXT_MUTED
        rows.append([
            report.library,
            report.phase,
            str(report.num_runs),
            color_cell(str(hit_count), hit_color),
            status,
        ])

    html = table(headers, rows, title="Analysis Results")
    return mo.Html(html)
