#!/usr/bin/env python3
"""Generate placeholder PNGs for docs/_static/screenshots/ until Phase 5 lands.

Run once locally:
    python docs/screenshots/generate_placeholders.py

Outputs are checked in so the Sphinx build succeeds on a fresh clone with
no running MemDiver stack.  Phase 5 (``docs/screenshots/capture.py``)
replaces these with real Playwright captures.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

SLUGS = [
    ("01_landing", "Session landing"),
    ("02_wizard_select_data", "Wizard — select data"),
    ("03_wizard_analysis", "Wizard — analysis algorithms"),
    ("04_workspace_default", "Workspace — default layout"),
    ("05_hex_with_overlay", "Hex viewer with structure overlay"),
    ("06_entropy_tab", "Entropy profile"),
    ("07_consensus_tab", "Consensus view"),
    ("08_pipeline_oracle", "Pipeline — oracle stage"),
    ("09_pipeline_run", "Pipeline — run dashboard"),
    ("10_pipeline_results", "Pipeline — results"),
    ("11_theme_triptych", "Theme triptych"),
]

OUT_DIR = Path(__file__).resolve().parent.parent / "_static" / "screenshots"
SIZE = (1440, 900)
BG = (11, 13, 16)          # matches brand dark #0b0d10
ACCENT = (0, 212, 170)     # teal
MUTED = (150, 160, 170)


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for candidate in (
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/Library/Fonts/Arial.ttf",
    ):
        p = Path(candidate)
        if p.exists():
            try:
                return ImageFont.truetype(str(p), size)
            except OSError:
                continue
    return ImageFont.load_default()


def build_placeholder(slug: str, title: str) -> Path:
    img = Image.new("RGB", SIZE, BG)
    draw = ImageDraw.Draw(img)

    # Border.
    draw.rectangle([(8, 8), (SIZE[0] - 8, SIZE[1] - 8)], outline=ACCENT, width=3)

    # Brand mark + slug banner.
    draw.text((48, 40), "MemDiver", fill=ACCENT, font=_font(48))
    draw.text((48, 110), slug, fill=MUTED, font=_font(28))

    # Centered title + pending note.
    f_title = _font(64)
    f_note = _font(24)
    # Pillow 10+: use textbbox.
    bbox = draw.textbbox((0, 0), title, font=f_title)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    draw.text(((SIZE[0] - tw) / 2, (SIZE[1] - th) / 2 - 30), title, fill=(240, 240, 240), font=f_title)
    note = "Screenshot pending — regenerate with docs/screenshots/capture.py"
    nb = draw.textbbox((0, 0), note, font=f_note)
    nw = nb[2] - nb[0]
    draw.text(((SIZE[0] - nw) / 2, (SIZE[1] + th) / 2 + 10), note, fill=MUTED, font=f_note)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{slug}.png"
    img.save(path, "PNG", optimize=True)
    return path


def main() -> int:
    for slug, title in SLUGS:
        path = build_placeholder(slug, title)
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
