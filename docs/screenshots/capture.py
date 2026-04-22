#!/usr/bin/env python3
"""Regenerate documentation screenshots via Playwright against a running MemDiver stack.

Run locally:
    pip install "memdiver[docs]" playwright
    python -m playwright install --with-deps chromium
    python docs/screenshots/capture.py --update              # refresh all 11 baselines
    python docs/screenshots/capture.py --one 04_workspace_default

The driver seeds a deterministic dataset via ``seed_data.py``, launches the
FastAPI+React stack with ``memdiver web`` in the background, then navigates
the SPA headlessly and writes PNGs to ``docs/_static/screenshots/``.
Finally it tears down the backend.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator
from urllib.error import URLError
from urllib.request import urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
STATIC_SHOTS = REPO_ROOT / "docs" / "_static" / "screenshots"
CAPTIONS = REPO_ROOT / "docs" / "screenshots" / "captions.json"
SEED_DATA = REPO_ROOT / "docs" / "screenshots" / "seed_data.py"
BACKEND_PORT = 8088
BACKEND_URL = f"http://127.0.0.1:{BACKEND_PORT}"
READY_PATH = "/docs"        # FastAPI Swagger UI — cheap readiness probe
READY_TIMEOUT_S = 45.0

# Set in capture_all() so loaded-MSL captures can locate the seeded fixture.
_DATASET_ROOT: Path | None = None
_LOAD_SESSION_NAME = "msl_loaded_screenshot"


@dataclass(frozen=True)
class ShotSpec:
    slug: str
    title: str
    alt: str
    viewport: dict
    theme: str
    mode: str
    capture: Callable


def _viewports_from_captions() -> tuple[dict, dict]:
    data = json.loads(CAPTIONS.read_text())
    return data["viewport_default"], data["viewport_hero"]


def _shots_from_captions(registry: dict[str, Callable]) -> list[ShotSpec]:
    data = json.loads(CAPTIONS.read_text())
    vp_default = data["viewport_default"]
    vp_hero = data["viewport_hero"]
    specs: list[ShotSpec] = []
    for entry in data["shots"]:
        slug = entry["slug"]
        fn = registry.get(slug)
        if fn is None:
            raise KeyError(f"No capture function registered for slug {slug!r}")
        viewport = vp_hero if entry.get("viewport") == "hero" else vp_default
        specs.append(
            ShotSpec(
                slug=slug,
                title=entry["title"],
                alt=entry["alt"],
                viewport=viewport,
                theme=entry.get("theme", "dark"),
                mode=entry.get("mode", "exploration"),
                capture=fn,
            )
        )
    return specs


# --- Backend lifecycle ------------------------------------------------


def _wait_ready(url: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except URLError as exc:
            last_err = exc
        time.sleep(0.5)
    raise RuntimeError(f"Backend at {url} not ready after {timeout_s}s: {last_err}")


@contextmanager
def running_backend(dataset_root: Path) -> Iterator[subprocess.Popen]:
    env = os.environ.copy()
    env["MEMDIVER_DATASET_ROOT"] = str(dataset_root)
    proc = subprocess.Popen(
        [sys.executable, "-m", "memdiver.cli", "web", "--port", str(BACKEND_PORT)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_ready(BACKEND_URL + READY_PATH, READY_TIMEOUT_S)
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# --- Deterministic-render primitives ----------------------------------

FREEZE_JS = r"""
() => {
  const fixed = new Date('2026-04-21T12:00:00Z').getTime();
  Date.now = () => fixed;
  // mulberry32 seeded RNG
  let s = 0x12345678 | 0;
  Math.random = () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
"""

DISABLE_ANIMATIONS_CSS = """
*, *::before, *::after {
  animation: none !important;
  transition: none !important;
  caret-color: transparent !important;
}
::-webkit-scrollbar { display: none; }
* { scrollbar-width: none; }
"""


def prime_page(page, *, theme: str, mode: str) -> None:
    """Seed localStorage values the app reads on init.

    Registered as a context init script so it runs after navigation lands
    on a real origin (the page is at about:blank when contexts are created
    and localStorage is denied for opaque origins).

    The FTUE payload shape must match frontend/src/ftue/store.ts: an array
    of ``{id, version, seenAt, completed}`` entries. Any other shape is
    discarded by ``loadSeen``, which re-triggers the welcome tour.
    """
    ftue_seen = [
        {"id": "workspace-layout-101", "version": 1, "seenAt": 0, "completed": True},
        {"id": "structure-overlay-101", "version": 1, "seenAt": 0, "completed": True},
        {"id": "pipeline-101", "version": 1, "seenAt": 0, "completed": True},
    ]
    page.context.add_init_script(
        f"""
        try {{
          localStorage.setItem('memdiver-theme', {json.dumps(theme)});
          localStorage.setItem('memdiver-mode', {json.dumps(mode)});
          localStorage.setItem('memdiver:ftue:seen', {json.dumps(json.dumps(ftue_seen))});
        }} catch (e) {{ /* opaque-origin pre-navigation; safe to ignore */ }}
        """
    )


# --- Capture functions (one per slug) ---------------------------------


def _goto_and_wait(page) -> None:
    page.goto(BACKEND_URL + "/", wait_until="domcontentloaded")
    page.wait_for_load_state("networkidle")


def shot_landing(page): _goto_and_wait(page)
def shot_wizard_select_data(page): _goto_and_wait(page)
def shot_wizard_analysis(page): _goto_and_wait(page)
def shot_workspace_default(page): _goto_and_wait(page)
def shot_hex_with_overlay(page): _goto_and_wait(page)
def shot_entropy_tab(page): _goto_and_wait(page)
def shot_consensus_tab(page): _goto_and_wait(page)
def shot_pipeline_oracle(page): _goto_and_wait(page)
def shot_pipeline_run(page): _goto_and_wait(page)
def shot_pipeline_results(page): _goto_and_wait(page)
def shot_theme_triptych(page): _goto_and_wait(page)


def _msl_fixture_path() -> Path | None:
    if _DATASET_ROOT is None:
        return None
    return _DATASET_ROOT / "msl" / "test_capture.msl"


def _api(method: str, path: str, body: dict | None = None) -> dict | None:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BACKEND_URL + path,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def _create_msl_session() -> None:
    """Idempotently register a session that points at the seeded MSL fixture."""
    msl_path = _msl_fixture_path()
    if msl_path is None or not msl_path.is_file():
        raise RuntimeError(
            f"Seeded MSL fixture missing at {msl_path}; cannot create loaded-workspace shot."
        )
    try:
        _api("DELETE", f"/api/sessions/{_LOAD_SESSION_NAME}")
    except urllib.error.URLError:
        pass
    _api("POST", "/api/sessions/", {
        "session_name": _LOAD_SESSION_NAME,
        "input_mode": "single_file",
        "input_path": str(msl_path),
        "single_file_format": "msl",
        "template_name": "Auto-detect",
        "protocol_name": "TLS",
        "protocol_version": "13",
        "mode": "verification",
        "ground_truth_mode": "skip",
        "selected_algorithms": [
            "entropy_scan", "pattern_match", "change_point",
            "structure_scan", "user_regex", "exact_match",
        ],
    })


def shot_msl_loaded(page) -> None:
    """Land on the workspace with the canonical MSL fixture loaded.

    Strategy mirrors scripts/test_hex_chunk_rerender.py: register a session
    via the REST API, then click its Load button on the landing page so the
    SPA hydrates the workspace exactly as a returning user would see it.
    """
    _create_msl_session()
    page.goto(BACKEND_URL + "/", wait_until="domcontentloaded")
    page.wait_for_load_state("networkidle")

    row = page.locator(f"text={_LOAD_SESSION_NAME}").first
    row.wait_for(timeout=10_000)
    card = row.locator(
        "xpath=ancestor::*[contains(@class, 'md-panel') or contains(@class, 'rounded')][1]"
    )
    load_btn = card.get_by_role("button", name="Load", exact=True)
    if load_btn.count() == 0:
        load_btn = page.get_by_role("button", name="Load", exact=True).first
    load_btn.first.click(force=True)

    # Wait for the hex viewer to mount and at least row 0 to populate.
    page.wait_for_selector('[data-index="0"]', timeout=15_000)
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)


CAPTURE_REGISTRY: dict[str, Callable] = {
    "01_landing": shot_landing,
    "02_wizard_select_data": shot_wizard_select_data,
    "03_wizard_analysis": shot_wizard_analysis,
    "04_workspace_default": shot_workspace_default,
    "05_hex_with_overlay": shot_hex_with_overlay,
    "06_entropy_tab": shot_entropy_tab,
    "07_consensus_tab": shot_consensus_tab,
    "08_pipeline_oracle": shot_pipeline_oracle,
    "09_pipeline_run": shot_pipeline_run,
    "10_pipeline_results": shot_pipeline_results,
    "11_theme_triptych": shot_theme_triptych,
    "12_workspace_loaded_dark": shot_msl_loaded,
    "13_workspace_loaded_light": shot_msl_loaded,
}


# --- Main --------------------------------------------------------------


def capture_all(targets: list[ShotSpec], *, headed: bool) -> None:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import]
    except ModuleNotFoundError:
        sys.stderr.write(
            "Playwright is not installed.  Install with:\n"
            "    pip install playwright\n"
            "    python -m playwright install --with-deps chromium\n"
        )
        raise SystemExit(2)

    STATIC_SHOTS.mkdir(parents=True, exist_ok=True)

    global _DATASET_ROOT
    dataset_root = Path(tempfile.mkdtemp(prefix="memdiver_docs_seed_"))
    _DATASET_ROOT = dataset_root
    subprocess.check_call([sys.executable, str(SEED_DATA), "--root", str(dataset_root)])

    with running_backend(dataset_root), sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=not headed,
            args=[
                "--force-color-profile=srgb",
                "--font-render-hinting=none",
                "--disable-lcd-text",
                "--hide-scrollbars",
            ],
        )
        try:
            for spec in targets:
                context = browser.new_context(
                    viewport=spec.viewport,
                    device_scale_factor=2,
                    reduced_motion="reduce",
                    color_scheme="dark" if spec.theme == "dark" else "light",
                )
                context.add_init_script(FREEZE_JS)
                try:
                    page = context.new_page()
                    page.add_style_tag(content=DISABLE_ANIMATIONS_CSS)
                    prime_page(page, theme=spec.theme, mode=spec.mode)
                    spec.capture(page)
                    path = STATIC_SHOTS / f"{spec.slug}.png"
                    page.screenshot(path=str(path), full_page=False, animations="disabled", caret="hide")
                    print(f"Wrote {path.relative_to(REPO_ROOT)}")
                finally:
                    context.close()
        finally:
            browser.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--update", action="store_true", help="Regenerate all 11 baselines.")
    parser.add_argument("--one", metavar="SLUG", help="Refresh only the given slug.")
    parser.add_argument("--headed", action="store_true", help="Show the Chromium window (debug).")
    parser.add_argument("--verify-seed", action="store_true", help="Run seed_data.py --verify-seed and exit.")
    args = parser.parse_args()

    if args.verify_seed:
        tmp = Path(tempfile.mkdtemp(prefix="memdiver_docs_verify_"))
        subprocess.check_call([sys.executable, str(SEED_DATA), "--root", str(tmp)])
        return subprocess.call([sys.executable, str(SEED_DATA), "--root", str(tmp), "--verify-seed"])

    specs = _shots_from_captions(CAPTURE_REGISTRY)
    if args.one:
        specs = [s for s in specs if s.slug == args.one]
        if not specs:
            sys.stderr.write(f"Unknown slug: {args.one}\n")
            return 2
    elif not args.update:
        parser.print_help()
        return 0

    capture_all(specs, headed=args.headed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
