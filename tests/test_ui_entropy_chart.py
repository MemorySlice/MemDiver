"""Marimo entropy chart: window-aware default threshold line + y range."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("plotly")

from memdiver.ui.views.entropy_chart import render_entropy_chart  # noqa: E402

MO = SimpleNamespace(md=lambda text: text, ui=SimpleNamespace(plotly=lambda fig: fig))


def _threshold_line(fig):
    return [s for s in fig.layout.shapes if s.y0 == s.y1][0].y0


def test_default_threshold_is_reachable_at_window_32():
    fig = render_entropy_chart(MO, [(0, 4.9), (16, 2.0)])
    assert _threshold_line(fig) == 4.5
    assert fig.layout.yaxis.range[1] == 5.5


def test_window_and_explicit_threshold():
    assert _threshold_line(render_entropy_chart(MO, [(0, 1.0)], window=64)) == pytest.approx(5.315, abs=1e-3)
    fig = render_entropy_chart(MO, [(0, 1.0)], threshold=7.5)
    assert _threshold_line(fig) == 7.5 and fig.layout.yaxis.range[1] == 8.0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
