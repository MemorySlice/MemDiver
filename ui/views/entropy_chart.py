"""Plotly-based entropy profile chart."""

import logging
from typing import Any, List, Optional, Tuple

logger = logging.getLogger("memdiver.ui.views.entropy_chart")


def render_entropy_chart(
    mo,
    profile: List[Tuple[int, float]],
    key_offsets: Optional[List[Tuple[int, int, str]]] = None,
    threshold: float = 7.5,
    title: str = "Entropy Profile",
) -> Any:
    """Render an interactive entropy profile chart using Plotly.

    Args:
        mo: marimo module.
        profile: List of (offset, entropy) tuples.
        key_offsets: Optional list of (start, end, label) for key regions.
        threshold: Entropy threshold line.
        title: Chart title.

    Returns:
        mo.ui.plotly chart or mo.md fallback.
    """
    try:
        import plotly.graph_objects as go
    except ImportError:
        return mo.md("*Plotly not available for entropy chart.*")

    if not profile:
        return mo.md("*No entropy data to display.*")

    offsets = [p[0] for p in profile]
    entropies = [p[1] for p in profile]

    fig = go.Figure()

    # Main entropy trace
    fig.add_trace(go.Scatter(
        x=offsets, y=entropies,
        mode="lines",
        name="Entropy",
        line=dict(color="#569cd6", width=1),
        fill="tozeroy",
        fillcolor="rgba(86, 156, 214, 0.1)",
    ))

    # Threshold line
    fig.add_hline(
        y=threshold,
        line_dash="dash",
        line_color="#f44747",
        annotation_text=f"Threshold ({threshold})",
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
        xaxis_title="Offset (bytes)",
        yaxis_title="Entropy (bits/byte)",
        yaxis_range=[0, 8.5],
        template="plotly_dark",
        paper_bgcolor="#1e1e1e",
        plot_bgcolor="#252526",
        height=350,
        margin=dict(l=50, r=20, t=40, b=40),
    )

    return mo.ui.plotly(fig)
