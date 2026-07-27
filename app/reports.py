"""Report-artifact writers for the pipeline producers.

These compose engine result data (``result.to_dict()``) with the pure
text/HTML builders in :mod:`memdiver.presentation.reports` and perform the
file IO. They live in the ``app`` layer — the use-case layer that is allowed
to depend on both ``engine`` (down) and ``presentation`` (side) — so the
engine modules stay pure compute and never import *up* into presentation.

Relocated here from ``engine/{nsweep,auto_floor,candidate_stats}.py`` to break
the ``engine → presentation`` layering cycle (P1.2). Output is byte-for-byte
identical to the pre-relocation writers; ``report.json`` in particular keeps
``headline`` in its original key position (it is read back by the pipeline
runner and consumed by the frontend).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from memdiver.presentation.reports import (
    auto_floor_report_lines,
    candidate_report_md,
    nsweep_headline,
    nsweep_markdown,
    nsweep_plotly_html,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from memdiver.engine.auto_floor import AutoFloorResult
    from memdiver.engine.candidate_stats import PhaseAResult
    from memdiver.engine.nsweep import NSweepResult


# ─────────────────────────────────────────────────────────────────────
# n-sweep
# ─────────────────────────────────────────────────────────────────────
def write_nsweep_artifacts(
    result: "NSweepResult",
    output_dir: Path,
    *,
    headline: Optional[str] = None,
) -> dict:
    """Write report.json, report.md, report.html under ``output_dir``.

    ``headline`` (the presentation one-liner) is computed once by the caller
    and re-injected into ``report.json`` at its original key position so the
    file stays byte-identical to the pre-relocation writer even though
    ``NSweepResult.to_dict()`` is now pure (headline-free).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if headline is None:
        headline = nsweep_headline(result)

    data = result.to_dict()
    report = {
        "total_dumps": data["total_dumps"],
        "first_hit_n": data["first_hit_n"],
        "first_hit_offset": data["first_hit_offset"],
        "headline": headline,
        "points": data["points"],
    }
    # Additive: present only when escalation was requested/reached, matching the
    # legacy ``to_dict`` ordering so the default report stays byte-identical.
    if "escalation" in data:
        report["escalation"] = data["escalation"]

    json_path = output_dir / "report.json"
    html_path = output_dir / "report.html"
    md_path = output_dir / "report.md"
    json_path.write_text(json.dumps(report, indent=2))
    html_path.write_text(nsweep_plotly_html(result))
    md_path.write_text(nsweep_markdown(result, plot_href="report.html"))
    return {"json": json_path, "html": html_path, "md": md_path}


# ─────────────────────────────────────────────────────────────────────
# auto-floor
# ─────────────────────────────────────────────────────────────────────
def write_auto_floor_artifacts(result: "AutoFloorResult", output_dir: Path) -> dict:
    """Write verdict.json + report.md. Returns paths written."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    vjson = output_dir / "verdict.json"
    vjson.write_text(json.dumps(result.to_dict(), indent=2))

    # Markdown line assembly lives in the presentation layer; the file IO
    # (join + trailing newline + write) stays here.
    lines = auto_floor_report_lines(result)
    md_path = output_dir / "report.md"
    md_path.write_text("\n".join(lines) + "\n")
    return {"verdict_json": str(vjson), "report_md": str(md_path)}


# ─────────────────────────────────────────────────────────────────────
# candidate-stats (Phase A experiment)
# ─────────────────────────────────────────────────────────────────────
def render_candidate_report(result: "PhaseAResult") -> str:
    """Render the Phase-A experiment markdown report."""
    return candidate_report_md(result)
