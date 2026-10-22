"""Plotly-based entropy profile chart."""

import logging
from typing import Any, List, Optional, Tuple

from memdiver.ui.locales import _

logger = logging.getLogger("memdiver.ui.views.entropy_chart")


def render_entropy_chart(
    mo,
    profile: List[Tuple[int, float]],
    key_offsets: Optional[List[Tuple[int, int, str]]] = None,
    threshold: Optional[float] = None,
    title: str = _("Entropy Profile"),
    window: Optional[int] = None,
) -> Any:
    """Render an interactive entropy profile chart using Plotly.

    Args:
        mo: marimo module.
        profile: List of (offset, entropy) tuples.
        key_offsets: Optional list of (start, end, label) for key regions.
        threshold: Entropy threshold line. ``None`` = the window-aware default
            (4.5 at the 32-byte window; the former 7.5 was above the 5.0 a
            32-byte window can reach, so the line sat off the data).
        title: Chart title.
        window: Window size of *profile* (default 32); sets the default
            threshold and the y-axis top (the achievable maximum).

    Returns:
        mo.ui.plotly chart or mo.md fallback.
    """
    try:
        import plotly.graph_objects as go
    except ImportError:
        return mo.md(_("*Plotly not available for entropy chart.*"))

    if not profile:
        return mo.md(_("*No entropy data to display.*"))

    from memdiver.core.entropy import (
        DEFAULT_ENTROPY_WINDOW, default_entropy_threshold, max_window_entropy,
    )

    window = window or DEFAULT_ENTROPY_WINDOW
    if threshold is None:
        threshold = default_entropy_threshold(window)
    y_top = max(max_window_entropy(window), threshold) + 0.5
    offsets = [p[0] for p in profile]
    entropies = [p[1] for p in profile]

    fig = go.Figure()

    # Main entropy trace
    fig.add_trace(go.Scatter(
        x=offsets, y=entropies,
        mode="lines",
        name=_("Entropy"),
        line=dict(color="#569cd6", width=1),
        fill="tozeroy",
        fillcolor="rgba(86, 156, 214, 0.1)",
    ))

    # Threshold line
    fig.add_hline(
        y=threshold,
        line_dash="dash",
        line_color="#f44747",
        annotation_text=_("Threshold ({threshold})").format(threshold=threshold),
    )

    # Key region markers
    if key_offsets:
        for start, end, label in key_offsets:
            fig.add_vrect(
                x0=start, x1=end,
                fillcolor="rgba(255, 107, 107, 0.15)",
                line_width=0,
                annotation_text=label,
                annotation_position="top",
            )

    fig.update_layout(
        title=title,
        xaxis_title=_("Offset (bytes)"),
        yaxis_title=_("Entropy (bits/byte)"),
        yaxis_range=[0, y_top],
        template="plotly_dark",
        paper_bgcolor="#1e1e1e",
        plot_bgcolor="#252526",
        height=350,
        margin=dict(l=50, r=20, t=40, b=40),
    )

    return mo.ui.plotly(fig)
