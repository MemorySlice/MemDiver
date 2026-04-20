#!/usr/bin/env python3
"""Regression test for the hex viewer chunk-rerender bug.

Before the chunkVersion fix, HexViewer's Zustand selectors only
subscribed to `cursorOffset`, `selection`, `scrollTarget`, etc., never
to `chunks`. When `ensureChunksLoaded` mutated the chunk map in the
background, no visible selector fired, HexViewer never re-rendered,
and HexRow's React.memo kept showing "--" for freshly loaded offsets.
Real users never saw it because any mouse/keyboard interaction
triggered an unrelated subscriber and cascaded a re-render. A
headless Playwright sitting still did.

This test proves the fix works by loading an MSL session with NO
user interaction and asserting the row at offset 0 renders the
`MEMSLICE` magic bytes (not the `hex-loading` placeholder).

Prerequisites
-------------
- `memdiver web --port 8088` running in another terminal.
- The boringssl MSL capture at the path in `MSL_PATH` below (the
  repo's canonical test dump for MSL workflows).

Run with
--------
    python scripts/test_hex_chunk_rerender.py
"""
from __future__ import annotations

import gzip
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("playwright not installed; install with: pip install playwright && playwright install chromium")
    sys.exit(0)

from tests._paths import dataset_root

BASE = "http://127.0.0.1:8088"
SESSION_NAME = "hex_chunk_rerender_regression"

_DS = dataset_root()
MSL_PATH = str(
    _DS
    / "experiment2_tls_local" / "data" / "TLS13" / "boringssl"
    / "boringssl_run_13_1" / "dumps" / "msl"
    / "20260412_160502_189178_post_handshake.msl"
) if _DS is not None else ""

# MEMSLICE magic in hex — the first 8 bytes of every .msl container.
MSL_MAGIC_HEX = "4d454d534c494345"


def ensure_server_running() -> bool:
    try:
        with urllib.request.urlopen(BASE + "/api/dataset/protocols", timeout=2) as res:
            return res.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False


def save_session() -> None:
    """Save a session that matches what the wizard would create so
    the session-load path lands the MSL file in useActiveDump."""
    payload = {
        "session_name": SESSION_NAME,
        "input_mode": "single_file",
        "input_path": MSL_PATH,
        "single_file_format": "msl",
        "template_name": "Auto-detect",
        "protocol_name": "TLS",
        "protocol_version": "13",
        "mode": "verification",
        "ground_truth_mode": "skip",
        "selected_algorithms": [
            "entropy_scan",
            "pattern_match",
            "change_point",
            "structure_scan",
            "user_regex",
            "exact_match",
        ],
    }
    req = urllib.request.Request(
        BASE + "/api/sessions/",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as res:
        assert res.status == 200, f"session save failed: HTTP {res.status}"


def delete_session() -> None:
    req = urllib.request.Request(
        BASE + f"/api/sessions/{SESSION_NAME}",
        method="DELETE",
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except urllib.error.URLError:
        pass


def test_row_zero_renders_msl_magic() -> int:
    if not MSL_PATH or not Path(MSL_PATH).is_file():
        print(f"SKIP: MSL fixture missing (set MEMDIVER_DATASET_ROOT)")
        return 0
    if not ensure_server_running():
        print(f"SKIP: no memdiver server at {BASE}; run `memdiver web --port 8088`")
        return 0

    delete_session()
    save_session()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport={"width": 1800, "height": 1100})
            page = ctx.new_page()

            runtime_errors: list[str] = []
            page.on("pageerror", lambda e: runtime_errors.append(f"pageerror: {e}"))
            page.on(
                "console",
                lambda m: runtime_errors.append(f"console[{m.type}]: {m.text}")
                if m.type == "error"
                else None,
            )

            page.goto(BASE + "/", wait_until="networkidle")
            page.evaluate("localStorage.clear()")
            page.reload(wait_until="networkidle")
            page.wait_for_timeout(400)

            # Find the saved session row and click Load. Use the card's
            # own Load button to avoid clicking a sibling row.
            row = page.locator(f"text={SESSION_NAME}").first
            row.wait_for(timeout=5000)
            card = row.locator(
                "xpath=ancestor::*[contains(@class, 'md-panel') or contains(@class, 'rounded')][1]"
            )
            load_btn = card.get_by_role("button", name="Load", exact=True)
            if load_btn.count() == 0:
                load_btn = page.get_by_role("button", name="Load", exact=True).first
            load_btn.first.click(force=True)

            # Wait up to 30s for chunks to land AND for the DOM to reflect
            # them. Before the fix this polling would time out because
            # no re-render happens without user interaction.
            page.wait_for_selector('[data-index="0"]', timeout=10000)

            deadline_ms = 30000
            elapsed = 0
            step = 250
            last_html = ""
            while elapsed < deadline_ms:
                row0 = page.locator('[data-index="0"]').first
                html = row0.inner_html()
                last_html = html
                # Accept as soon as offset 0 renders a non-placeholder
                # byte. The placeholder is span[class="hex-byte hex-loading"]
                # showing "--"; a loaded byte has the hex-loading class
                # absent. Check by looking for the specific bytes of
                # MEMSLICE at data-offset="0".
                if 'data-offset="0"' in html and "hex-loading" not in html.split('data-offset="1"')[0]:
                    # Also verify the actual byte values match MSL magic.
                    # Scrape the visible hex digits for offsets 0..7.
                    hex_cells: list[str] = []
                    for i in range(8):
                        cell = row0.locator(f'[data-offset="{i}"][data-col="hex"]').first
                        if cell.count() > 0:
                            text = (cell.inner_text() or "").strip().lower()
                            if text and text != "--":
                                hex_cells.append(text)
                    joined = "".join(hex_cells)
                    if joined == MSL_MAGIC_HEX:
                        print(
                            f"✅ row[0] rendered MSL magic after {elapsed}ms "
                            f"of passive waiting (no interaction)"
                        )
                        print(f"   bytes: {' '.join(hex_cells)}")
                        break
                page.wait_for_timeout(step)
                elapsed += step
            else:
                print("❌ row[0] never rendered the MSL magic bytes.")
                print(f"   last row HTML (first 600 chars): {last_html[:600]}")
                if runtime_errors:
                    print("   runtime errors:")
                    for e in runtime_errors[:5]:
                        print(f"     {e}")
                browser.close()
                return 1

            browser.close()

            if runtime_errors:
                print("⚠ runtime errors (non-blocking):")
                for e in runtime_errors[:10]:
                    print(f"   {e}")
        return 0
    finally:
        delete_session()


if __name__ == "__main__":
    sys.exit(test_row_zero_renders_msl_magic())
