"""Tests for scripts/build_logo.py.

These mock the rendering layer (cairosvg / Pillow) so they run without the
optional ``memdiver[docs]`` dependencies installed.
"""
import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
MODULE_PATH = REPO_ROOT / "scripts" / "build_logo.py"


def _load_build_logo(monkeypatch):
    """Import scripts/build_logo.py with cairosvg/PIL stubbed out."""
    # Stub the optional render dependencies before importing the module.
    fake_cairosvg = types.ModuleType("cairosvg")
    fake_cairosvg.svg2png = lambda **kwargs: None
    fake_pil = types.ModuleType("PIL")
    fake_pil_image = types.ModuleType("PIL.Image")
    fake_pil.Image = fake_pil_image
    monkeypatch.setitem(sys.modules, "cairosvg", fake_cairosvg)
    monkeypatch.setitem(sys.modules, "PIL", fake_pil)
    monkeypatch.setitem(sys.modules, "PIL.Image", fake_pil_image)

    spec = importlib.util.spec_from_file_location("build_logo", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_check_does_not_mutate_committed_favicon_png(monkeypatch):
    """`--check` is read-only: it must never write the tracked FAVICON_PNG.

    Regression for the bug where check() rendered straight into the committed
    favicon.png and only the temp .ico was cleaned up.
    """
    bl = _load_build_logo(monkeypatch)

    # Capture which paths the renderer is asked to write.
    written_pngs: list[Path] = []

    def fake_svg_to_png(src, dst, width):
        written_pngs.append(Path(dst))
        Path(dst).write_bytes(b"rendered-" + str(width).encode())

    class FakeImg:
        def convert(self, _mode):
            return self

        def save(self, dst, format, sizes):  # noqa: A002 - mirror Pillow API
            Path(dst).write_bytes(b"rendered-ico")

    monkeypatch.setattr(bl, "_svg_to_png", fake_svg_to_png)
    monkeypatch.setattr(bl.Image, "open", lambda _p: FakeImg(), raising=False)

    committed_favicon = bl.FAVICON_PNG
    before = committed_favicon.read_bytes() if committed_favicon.exists() else None

    bl.check()

    # The committed favicon.png must not have been a render target...
    assert committed_favicon not in written_pngs
    # ...and its on-disk bytes must be unchanged.
    after = committed_favicon.read_bytes() if committed_favicon.exists() else None
    assert after == before

    # No temp artifacts left behind in STATIC.
    leftovers = list(bl.STATIC.glob(".check_*"))
    assert leftovers == [], f"check() left temp files: {leftovers}"
