#!/usr/bin/env python3
"""Regenerate raster logo assets from the canonical SVGs in docs/_static/.

Run manually after editing logo.svg / logo_simple.svg.  Outputs are
committed to docs/_static/ so that the Sphinx build and GitHub Pages
deploy do not need cairosvg at build time.

Usage:
    python scripts/build_logo.py          # rebuild everything
    python scripts/build_logo.py --check  # exit non-zero if outputs stale

Dependencies (install via `pip install memdiver[docs]`):
    cairosvg>=2.7
    pillow>=10.4
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import cairosvg
from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC = REPO_ROOT / "docs" / "_static"
SOURCE_SIMPLE = STATIC / "logo_simple.svg"
SOURCE_FULL = STATIC / "logo.svg"

README_PNG = STATIC / "logo_readme.png"
FAVICON_ICO = STATIC / "favicon.ico"
FAVICON_PNG = STATIC / "favicon.png"

README_WIDTH = 512
FAVICON_SIZES = (16, 32, 48)


def _svg_to_png(src: Path, dst: Path, width: int) -> None:
    cairosvg.svg2png(
        url=str(src),
        write_to=str(dst),
        output_width=width,
        output_height=width,
    )


def _build_favicon() -> None:
    # Render a clean 48px PNG then downscale to a multi-res ICO.
    _svg_to_png(SOURCE_SIMPLE, FAVICON_PNG, width=max(FAVICON_SIZES))
    img = Image.open(FAVICON_PNG).convert("RGBA")
    img.save(FAVICON_ICO, format="ICO", sizes=[(s, s) for s in FAVICON_SIZES])


def build() -> None:
    _svg_to_png(SOURCE_SIMPLE, README_PNG, width=README_WIDTH)
    _build_favicon()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check() -> int:
    tmp_png = STATIC / ".check_logo_readme.png"
    tmp_fav = STATIC / ".check_favicon.ico"
    try:
        _svg_to_png(SOURCE_SIMPLE, tmp_png, width=README_WIDTH)
        _svg_to_png(SOURCE_SIMPLE, FAVICON_PNG, width=max(FAVICON_SIZES))
        img = Image.open(FAVICON_PNG).convert("RGBA")
        img.save(tmp_fav, format="ICO", sizes=[(s, s) for s in FAVICON_SIZES])

        ok = _digest(tmp_png) == _digest(README_PNG) and _digest(tmp_fav) == _digest(FAVICON_ICO)
        return 0 if ok else 1
    finally:
        for p in (tmp_png, tmp_fav):
            if p.exists():
                p.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="Verify committed rasters match current SVG.")
    args = parser.parse_args(argv)

    if args.check:
        return check()

    build()
    print(f"Wrote {README_PNG.relative_to(REPO_ROOT)}")
    print(f"Wrote {FAVICON_ICO.relative_to(REPO_ROOT)}")
    print(f"Wrote {FAVICON_PNG.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
