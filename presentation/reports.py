"""Human-facing report/text builders for MemDiver.

Relocated from the engine/ compute modules (nsweep, candidate_stats,
auto_floor) so wording, markdown structure, and plotly HTML/titles live at
the presentation edge — decoupled from the numeric compute. The engine
modules keep thin delegators that lazy-import these functions, so every
caller and the wire/progress output remain byte-for-byte identical.

Functions duck-type the engine dataclasses' fields; engine types are
imported only under ``TYPE_CHECKING`` and runtime constants are lazy-imported
inside the function bodies to avoid any circular import at module load.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import cycle
    from memdiver.engine.auto_floor import AutoFloorResult
    from memdiver.engine.candidate_stats import PhaseAResult
    from memdiver.engine.nsweep import NSweepResult


# ─────────────────────────────────────────────────────────────────────
# n-sweep
# ─────────────────────────────────────────────────────────────────────
def nsweep_headline(result: "NSweepResult") -> str:
    """Prose one-liner summarizing an n-sweep run."""
    if result.first_hit_n is None:
        last = result.points[-1] if result.points else None
        if last:
            return (
                f"Exhausted {result.total_dumps} dumps without a hit; "
                f"smallest survivor set at N={last.n}: "
                f"{last.stages.get('high_entropy', 0)} candidates."
            )
        return "n-sweep ran on zero dumps."
    point = next(p for p in result.points if p.n == result.first_hit_n)
    return (
        f"At N={result.first_hit_n}, {point.stages.get('high_entropy', 0)} "
        f"candidates survived, {point.hits} decrypted in "
        f"{point.timing.brute_force_ms / 1000:.2f}s at offset "
        f"0x{result.first_hit_offset:x}."
    )


def nsweep_markdown(result: "NSweepResult", plot_href: Optional[str] = None) -> str:
    """Build the ``# N-sweep report`` markdown for an n-sweep run."""
    lines: List[str] = ["# N-sweep report", "", f"**{nsweep_headline(result)}**", ""]
    if plot_href:
        lines.append(f"![reduction curve]({plot_href})")
        lines.append("")
    lines.append(
        "| N | variance | aligned | high_entropy | tried | hits | t_cons ms | t_red ms | t_bf ms |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for p in result.points:
        s = p.stages
        lines.append(
            f"| {p.n} | {s.get('variance', 0)} | {s.get('aligned', 0)} | "
            f"{s.get('high_entropy', 0)} | {p.candidates_tried} | {p.hits} | "
            f"{p.timing.consensus_ms:.0f} | {p.timing.reduce_ms:.0f} | "
            f"{p.timing.brute_force_ms:.0f} |"
        )
    return "\n".join(lines) + "\n"


def nsweep_plotly_html(result: "NSweepResult") -> str:
    """Build the standalone plotly HTML (survivors + timing) for an n-sweep run."""
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    ns = [p.n for p in result.points]
    fig = make_subplots(
        rows=2, cols=1, shared_xaxes=True,
        subplot_titles=("Survivors vs N", "Wall-clock per stage (ms)"),
    )
    for stage in ("variance", "aligned", "high_entropy"):
        fig.add_trace(
            go.Scatter(
                x=ns, y=[max(1, p.stages.get(stage, 0)) for p in result.points],
                mode="lines+markers", name=stage,
            ),
            row=1, col=1,
        )
    fig.add_trace(
        go.Scatter(
            x=ns, y=[max(1, p.hits) for p in result.points],
            mode="lines+markers", name="hits",
        ),
        row=1, col=1,
    )
    fig.update_yaxes(type="log", row=1, col=1)
    for name, attr in (("consensus", "consensus_ms"), ("reduce", "reduce_ms"),
                       ("brute_force", "brute_force_ms")):
        fig.add_trace(
            go.Bar(
                x=ns, y=[getattr(p.timing, attr) for p in result.points],
                name=name,
            ),
            row=2, col=1,
        )
    fig.update_layout(
        title=f"N-sweep: {nsweep_headline(result)}",
        height=700, showlegend=True,
    )
    return fig.to_html(full_html=True, include_plotlyjs="cdn")


# ─────────────────────────────────────────────────────────────────────
# candidate_stats — Phase A offline experiments
# ─────────────────────────────────────────────────────────────────────
def candidate_report_md(result: "PhaseAResult") -> str:
    """Multi-section markdown for a Phase-A offline auto-floor result."""
    from memdiver.engine.auto_floor import SIGMA_K2

    o, f = result.ordering, result.floor
    lines = [
        "# Phase A — offline auto-floor experiments (zero oracle)", "",
        f"key offset `0x{result.key_offset:x}`  size {result.key_size}  "
        f"maximal candidates **{o.maximal}**", "",
        "## A1 — ordering gate", "",
        f"- baseline **R_var = {o.r_var}** (candidates with window-variance ≥ key)",
        f"- composite **R_composite = {o.r_composite}** (uniformity gate × variance)",
        f"- fresh-clutter floor (wvar ≥ 0.9·σ_k²): **{o.clutter_at_ceiling}** "
        "— irreducible; only the oracle separates these from the key",
        f"- key passes uniformity gate: **{o.key_passes_gate}**  "
        f"(gate-pass candidates: {o.gate_pass_count})",
        f"- distinct windows (dedup potential): **{o.distinct_windows}** / {o.maximal}",
        f"- key features: {json.dumps(o.key_features)}",
        f"- verdict: {'GO — composite beats variance ordering' if o.r_composite < o.r_var else 'NO-GO — composite does not beat variance ordering'}",
        "", "## A2 — floor selection", "",
        f"- σ_k²̂ (P90 interior) = **{f.sigma_k2_hat:.1f}** (ceiling {SIGMA_K2:.1f})",
        f"- φ_knee (descending Kneedle) = **{f.phi_knee:.1f}**",
        f"- φ_theory = {json.dumps({k: round(v,1) for k,v in f.phi_theory.items()})}",
        f"- key window-variance = **{f.key_wvar:.1f}**  trimmed-mean = {f.key_trimmed_mean:.1f}",
        f"- key retained at knee: **{f.key_retained_at_knee}**  "
        f"at φ_theory: {json.dumps(f.key_retained_at_theory)}",
        f"- φ_knee vs φ_theory(0.35) agree (within 2×): **{f.agree}**",
        "", "## C(φ) ladder", "",
        "| φ | candidates | key retained |", "|---|---|---|",
    ]
    for row in f.ladder:
        lines.append(f"| {row['phi']:.0f} | {row['candidates']} | "
                     f"{row.get('key_retained')} |")
    s = result.subsample
    if s is not None:
        lines += [
            "", "## A3 — subsample stability (EXPERIMENTAL)", "",
            f"- complementary halves: N_a={s.num_dumps_a}, N_b={s.num_dumps_b}  "
            f"(expected σ² rel-err ≈ {s.expected_rel_err:.2f})",
            f"- key stability = **{s.key_stability:.3f}**  "
            f"(rel-err {s.key_rel_err:.3f}); median stability {s.median_stability:.3f}",
            f"- baseline **R_var = {s.r_var}**  vs  stability-aware "
            f"**R_stable = {s.r_stable}**",
            f"- verdict: {'GO — stability beats variance ordering' if s.beats_variance else 'NO-GO — stability does not beat variance ordering'}",
            "", f"> {s.detail}",
        ]
    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────
# auto_floor — verdict report
# ─────────────────────────────────────────────────────────────────────
def auto_floor_report_lines(result: "AutoFloorResult") -> List[str]:
    """Assemble the ``# auto-floor verdict`` markdown lines for a result.

    Returns the list of lines; the engine keeps the ``write_text`` IO
    (joining with ``"\\n"`` and a trailing newline) so behavior is unchanged.
    """
    from memdiver.engine.auto_floor import (
        DEFAULT_FLOOR,
        VERDICT_ABSENT,
        VERDICT_FLOOR_TOO_HIGH,
        VERDICT_INCONCLUSIVE,
        VERDICT_RECOVERED,
    )

    lines = [
        "# auto-floor verdict", "",
        f"**Verdict:** `{result.verdict}`"
        + (f"  (reason: {result.inconclusive_reason})" if result.inconclusive_reason else ""),
        "",
    ]
    if result.verdict in (VERDICT_RECOVERED, VERDICT_FLOOR_TOO_HIGH):
        lines += [
            f"- recovered key: `{result.key_hex}`",
            f"- offset: `0x{result.offset:x}`",
            f"- phi* (hit variance): **{result.phi_star:.1f}**  "
            f"(default floor {DEFAULT_FLOOR:.0f})",
            f"- data-driven phi0: **{result.phi0:.1f}**",
            f"- oracle calls to hit: {result.tried} / {result.maximal_candidates} maximal",
        ]
        if result.verdict == VERDICT_FLOOR_TOO_HIGH:
            lines.append(f"- NOTE: default floor {DEFAULT_FLOOR:.0f} would have MISSED "
                         f"this key (phi*={result.phi_star:.1f} < default) — "
                         f"footnote-2 case, now automated.")
    elif result.verdict == VERDICT_ABSENT:
        conf = "n/a (coverage unverified)" if result.confidence is None else f"{result.confidence:.3f}"
        lines += [
            f"- oracle rejected all {result.maximal_candidates} maximal candidates",
            f"- absence confidence (coverage x recall): {conf}",
            f"- envelope: {json.dumps(result.envelope)}",
            f"- coverage: {result.coverage}  correspondence: {result.correspondence}",
        ]
    elif result.verdict == VERDICT_INCONCLUSIVE and result.maximal_candidates:
        lines += [
            f"- no hit, and a precondition failed (reason: {result.inconclusive_reason}) "
            f"→ NOT reported as ABSENT",
            f"- oracle calls before stopping: {result.tried} / "
            f"{result.maximal_candidates} maximal",
        ]
    # A negative verdict is only meaningful under its reachability assumptions.
    if result.verdict in (VERDICT_ABSENT, VERDICT_INCONCLUSIVE) and result.assumptions:
        lines += ["", "Negative-verdict assumptions (a key violating any of these "
                  "would be missed):"]
        lines += [f"  - {a}" for a in result.assumptions]
    if result.oracle_health:
        lines += ["", f"Oracle health: {json.dumps(result.oracle_health.to_dict())}"]
    if result.phi0_detail:
        lines += [f"phi0 derivation: {result.phi0_detail.detail}"]
    return lines
