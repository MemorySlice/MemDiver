"""Cross-run variance map visualization."""

import logging
from typing import Any, List, Optional

logger = logging.getLogger("memdiver.ui.views.variance_map")


def render_variance_map(
    mo,
    variance_data: List[float],
    classifications: Optional[List[str]] = None,
    title: str = "Cross-Run Variance Map",
    step: int = 1,
) -> Any:
    """Render variance map using Plotly.

    Args:
        mo: marimo module.
        variance_data: Per-byte variance values.
        classifications: Per-byte classification labels.
        title: Chart title.
        step: Subsample step for large datasets.

    Returns:
        mo.ui.plotly chart.
    """
    try:
        import plotly.graph_objects as go
    except ImportError:
        return mo.md("*Plotly not available for variance map.*")

    if not variance_data:
        return mo.md("*No variance data to display.*")

    # Subsample for performance
    offsets = list(range(0, len(variance_data), step))
    values = [variance_data[i] for i in offsets]

    # Color by classification
    from ui.components import color_scheme as cs
    from core.variance import ByteClass
    class_colors = {
        ByteClass.INVARIANT: cs.VARIANCE_INVARIANT,
        ByteClass.STRUCTURAL: cs.VARIANCE_STRUCTURAL,
        ByteClass.POINTER: cs.VARIANCE_POINTER,
        ByteClass.KEY_CANDIDATE: cs.VARIANCE_KEY_CANDIDATE,
    }

    colors = None
    if classifications:
        colors = [class_colors.get(classifications[i], cs.TEXT_MUTED) for i in offsets]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=offsets, y=values,
        marker_color=colors or "#569cd6",
        name="Variance",
    ))

    # Classification threshold lines
    fig.add_hline(y=100, line_dash="dot", line_color=cs.VARIANCE_STRUCTURAL,
                  annotation_text="Structural")
    fig.add_hline(y=3000, line_dash="dot", line_color=cs.VARIANCE_POINTER,
                  annotation_text="Pointer")

    fig.update_layout(
        title=title,
        xaxis_title="Offset (bytes)",
        yaxis_title="Variance",
        yaxis_type="log",
        template="plotly_dark",
        paper_bgcolor="#1e1e1e",
        plot_bgcolor="#252526",
        height=350,
        margin=dict(l=50, r=20, t=40, b=40),
        bargap=0,
    )

    return mo.ui.plotly(fig)
