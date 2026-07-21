"""Golden tests for memdiver.presentation.reports.

Asserts the relocated presentation builders reproduce the exact strings the
engine delegators emit, and that the engine methods now delegate to them
byte-for-byte (behavior preserved across the presentation-separation refactor).
Mirrors the existing assertions in tests/test_nsweep.py and
tests/test_candidate_stats.py.
"""
from __future__ import annotations

import numpy as np

from memdiver.engine.candidate_stats import render_report, run_phase_a
from memdiver.engine.nsweep import NSweepResult, run_nsweep
from memdiver.presentation.reports import (
    candidate_report_md,
    nsweep_headline,
    nsweep_markdown,
    nsweep_plotly_html,
)

# Reuse the synthetic fixtures the engine tests exercise.
from tests.test_candidate_stats import KEY_OFF, KEY_SIZE, _build_synthetic
from tests.test_nsweep import _synth_dumps, _target_from


_REDUCE_KWARGS = dict(
    alignment=8, density_threshold=0.5,
    entropy_window=32, entropy_threshold=4.0,
    min_variance=500.0, min_region=16,
)


# ─────────────────────────────────────────────────────────────────────
# n-sweep headline
# ─────────────────────────────────────────────────────────────────────
def test_nsweep_headline_zero_dumps():
    assert nsweep_headline(NSweepResult()) == "n-sweep ran on zero dumps."


def test_nsweep_headline_keyed_hit_says_decrypted():
    sources = _synth_dumps(num=20)
    target = _target_from(sources)
    result = run_nsweep(
        sources, n_values=[1, 5, 10, 20], reduce_kwargs=_REDUCE_KWARGS,
        oracle=lambda c: c == target, key_sizes=(32,), stride=8,
    )
    assert result.first_hit_n is not None
    assert "decrypted" in nsweep_headline(result)
    # the engine method now delegates → identical string
    assert result.headline() == nsweep_headline(result)


def test_nsweep_headline_no_hit_says_without_a_hit():
    sources = _synth_dumps(num=10)
    result = run_nsweep(
        sources, n_values=[3, 5, 10], reduce_kwargs=_REDUCE_KWARGS,
        oracle=lambda _: False, key_sizes=(32,), stride=8,
    )
    assert result.first_hit_n is None
    assert "without a hit" in nsweep_headline(result)
    assert result.headline() == nsweep_headline(result)


# ─────────────────────────────────────────────────────────────────────
# n-sweep markdown + plotly
# ─────────────────────────────────────────────────────────────────────
def test_nsweep_markdown_matches_delegator_and_structure():
    sources = _synth_dumps(num=10)
    target = _target_from(sources)
    result = run_nsweep(
        sources, n_values=[1, 5, 10], reduce_kwargs=_REDUCE_KWARGS,
        oracle=lambda c: c == target,
    )
    md = nsweep_markdown(result, plot_href="report.html")
    assert "# N-sweep report" in md
    assert "| N |" in md
    assert "![reduction curve](report.html)" in md
    # delegator (engine private fn) reproduces it byte-for-byte
    from memdiver.engine.nsweep import _nsweep_markdown
    assert _nsweep_markdown(result, plot_href="report.html") == md


def test_nsweep_plotly_html_has_titles():
    sources = _synth_dumps(num=10)
    target = _target_from(sources)
    result = run_nsweep(
        sources, n_values=[1, 5, 10], reduce_kwargs=_REDUCE_KWARGS,
        oracle=lambda c: c == target,
    )
    html = nsweep_plotly_html(result)
    assert "plotly" in html.lower()
    assert "Survivors vs N" in html


# ─────────────────────────────────────────────────────────────────────
# candidate_stats (Phase A) report
# ─────────────────────────────────────────────────────────────────────
def test_candidate_report_md_matches_delegator():
    var, ref, n, key_off = _build_synthetic()
    res = run_phase_a(var, ref, n, key_off, key_size=KEY_SIZE, stride=8)
    report = candidate_report_md(res)
    assert "Phase A" in report and "R_composite" in report
    # engine render_report now delegates → identical string
    assert render_report(res) == report
