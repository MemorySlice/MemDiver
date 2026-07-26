"""Tests for the framework-agnostic UI rendering adapters.

``ui/adapters.py`` was reduced to marimo + raw after nicegui was retired; these
tests pin the resolution + passthrough behaviour so the raw path (the only one
guaranteed available in CI, where neither UI framework is installed) stays
byte-identical and no removed-framework branch resurfaces.
"""

from memdiver.ui import adapters


def test_resolve_passthrough_for_explicit_framework():
    # A non-"auto" framework is returned verbatim, without detection.
    assert adapters._resolve("raw") == "raw"
    assert adapters._resolve("marimo") == "marimo"
    assert adapters._resolve("anything") == "anything"


def test_resolve_auto_is_marimo_or_raw():
    # "auto" resolves only to an available framework; nicegui is gone, so the
    # only possible outcomes are marimo (if installed) or raw.
    assert adapters._resolve("auto") in {"marimo", "raw"}


def test_render_html_raw_is_identity():
    html = "<b>hello</b>"
    assert adapters.render_html(html, framework="raw") == html


def test_render_plotly_raw_is_identity():
    sentinel = object()
    assert adapters.render_plotly(sentinel, framework="raw") is sentinel
