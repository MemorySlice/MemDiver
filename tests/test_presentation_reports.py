"""Golden tests for memdiver.presentation.reports and the app-layer writers.

Asserts the presentation builders produce the expected report strings, and that
the app-layer writers (``memdiver.app.reports``) that render them to files
reproduce those builder strings byte-for-byte — behavior preserved across the
P1.2 engine→presentation decoupling. The writers moved UP from engine into app
so the engine no longer imports presentation; these tests pin that the relocated
writers still emit identical artifacts (including ``report.json`` keeping
``headline`` in its original key position).
"""
from __future__ import annotations

import json

import numpy as np

from memdiver.app.reports import render_candidate_report, write_nsweep_artifacts
from memdiver.engine.candidate_stats import run_phase_a
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


def test_nsweep_headline_no_hit_says_without_a_hit():
    sources = _synth_dumps(num=10)
    result = run_nsweep(
        sources, n_values=[3, 5, 10], reduce_kwargs=_REDUCE_KWARGS,
        oracle=lambda _: False, key_sizes=(32,), stride=8,
    )
    assert result.first_hit_n is None
    assert "without a hit" in nsweep_headline(result)


# ─────────────────────────────────────────────────────────────────────
# n-sweep markdown + plotly  (via the relocated app-layer writer)
# ─────────────────────────────────────────────────────────────────────
def test_nsweep_markdown_matches_writer_and_structure(tmp_path):
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

    # The app-layer writer renders report.md via the same builder byte-for-byte,
    # and injects the headline into report.json at its original key position.
    paths = write_nsweep_artifacts(result, tmp_path)
    assert paths["md"].read_text() == md
    rep = json.loads(paths["json"].read_text())
    assert rep["headline"] == nsweep_headline(result)
    # report.json byte-parity: headline sits between first_hit_offset and points.
    assert list(rep.keys())[:5] == [
        "total_dumps", "first_hit_n", "first_hit_offset", "headline", "points",
    ]


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
# candidate_stats (Phase A) report  (via the relocated app-layer wrapper)
# ─────────────────────────────────────────────────────────────────────
def test_candidate_report_md_matches_writer():
    var, ref, n, key_off = _build_synthetic()
    res = run_phase_a(var, ref, n, key_off, key_size=KEY_SIZE, stride=8)
    report = candidate_report_md(res)
    assert "Phase A" in report and "R_composite" in report
    # The app-layer render wrapper delegates → identical string.
    assert render_candidate_report(res) == report
