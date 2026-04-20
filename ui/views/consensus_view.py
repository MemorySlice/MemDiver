"""Consensus matrix visualization."""

import logging
from typing import Any, Optional

logger = logging.getLogger("memdiver.ui.views.consensus_view")


def render_consensus_view(
    mo,
    consensus,
    title: str = "Consensus Matrix",
) -> Any:
    """Render the consensus matrix classification overview.

    Args:
        mo: marimo module.
        consensus: engine.consensus.ConsensusVector instance.
        title: Panel title.

    Returns:
        mo.Html with consensus summary and classification chart.
    """
    from ui.components import color_scheme as cs
    from ui.components.html_builder import stat_row

    if not consensus or consensus.size == 0:
        return mo.md("*No consensus data. Need >= 2 dumps at the same phase.*")

    counts = consensus.classification_counts()
    total = consensus.size

    # Classification bars
    bars = []
    class_info = [
        ("invariant", cs.VARIANCE_INVARIANT, "Identical across all runs"),
        ("structural", cs.VARIANCE_STRUCTURAL, "Low variance (< 100)"),
        ("pointer", cs.VARIANCE_POINTER, "Medium variance (< 3000)"),
        ("key_candidate", cs.VARIANCE_KEY_CANDIDATE, "High variance (key material)"),
    ]
    for cls_name, color, desc in class_info:
        count = counts.get(cls_name, 0)
        pct = (count / total * 100) if total > 0 else 0
        bars.append(
            f'<div style="display:flex;align-items:center;gap:8px;margin:4px 0;">'
            f'<div style="width:12px;height:12px;background:{color};'
            f'border-radius:2px;"></div>'
            f'<span style="color:{cs.TEXT_PRIMARY};font-size:12px;'
            f'min-width:100px;">{cls_name}</span>'
            f'<div style="flex:1;background:{cs.BG_TERTIARY};height:16px;'
            f'border-radius:3px;overflow:hidden;">'
            f'<div style="background:{color};width:{pct}%;height:100%;"></div>'
            f'</div>'
            f'<span style="color:{cs.TEXT_SECONDARY};font-size:11px;'
            f'min-width:80px;">{count:,} ({pct:.1f}%)</span></div>'
        )

    stats = (
        stat_row("Total bytes", f"{total:,}")
        + stat_row("Dumps analyzed", str(consensus.num_dumps))
    )

    html = (
        f'{cs.BASE_CSS}'
        f'<div class="memdiver-panel">'
        f'<div class="memdiver-header">{title}</div>'
        f'{stats}'
        f'<div style="margin-top:12px;">{"".join(bars)}</div>'
        f'</div>'
    )
    return mo.Html(html)
