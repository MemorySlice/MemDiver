#!/usr/bin/env python3
"""Composite the three triptych intermediates into 11_theme_triptych.png.

Run after readme-screenshots.spec.ts has produced
``docs/_static/screenshots/.triptych_parts/part_{light,dark,dark_hc}.png``.

Each part is captured at viewport_hero (1920x1080). The final is three
scaled-down panels side by side at the same total width as hero so the
PNG drops cleanly into the README thumbnail slot (220px constrained).
"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent
PARTS_DIR = REPO_ROOT / "docs" / "_static" / "screenshots" / ".triptych_parts"
OUT = REPO_ROOT / "docs" / "_static" / "screenshots" / "11_theme_triptych.png"

PARTS = ("part_light.png", "part_dark.png", "part_dark_hc.png")


def main() -> int:
    missing = [p for p in PARTS if not (PARTS_DIR / p).exists()]
    if missing:
        print(
            f"Missing triptych parts: {missing}. "
            f"Run readme-screenshots.spec.ts first.",
            file=sys.stderr,
        )
        return 1

    images = [Image.open(PARTS_DIR / p).convert("RGB") for p in PARTS]
    # Normalize to the smallest common size so uneven captures don't skew.
    h = min(img.height for img in images)
    panel_w = min(img.width for img in images)
    resized = [
        img if img.size == (panel_w, h) else img.resize((panel_w, h))
        for img in images
    ]

    total_w = panel_w * 3
    canvas = Image.new("RGB", (total_w, h), color=(0, 0, 0))
    for i, img in enumerate(resized):
        canvas.paste(img, (i * panel_w, 0))

    canvas.save(OUT, format="PNG", optimize=True)
    print(f"Wrote {OUT.relative_to(REPO_ROOT)} ({total_w}x{h})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
