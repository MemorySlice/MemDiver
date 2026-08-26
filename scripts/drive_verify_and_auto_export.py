#!/usr/bin/env python3
"""End-to-end Playwright smoke test for verify-key tab + auto-export mode."""
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

SCREENSHOTS = Path("/tmp/verify_auto_screenshots")
SCREENSHOTS.mkdir(exist_ok=True)
URL = "http://localhost:5173"


def goto_fresh(page):
    page.goto(URL)
    page.wait_for_load_state("networkidle")
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload()
    page.wait_for_load_state("networkidle")


def force_workspace(page):
    page.evaluate(
        """async () => {
          const m = await import('/src/stores/app-store.ts');
          m.useAppStore.setState({
            appView: 'workspace',
            inputPath: '/tmp/dummy.dump',
            inputMode: 'file',
            mode: 'exploration'
          });
        }"""
    )


def mark_tours_seen(page):
    page.evaluate(
        """() => {
          const fake = [
            { id: 'workspace-layout-101', version: 1, completed: true, ts: Date.now() },
            { id: 'structure-overlay-101', version: 1, completed: true, ts: Date.now() }
          ];
          try { localStorage.setItem('memdiver:ftue:seen', JSON.stringify(fake)); } catch(e){}
        }"""
    )


def dismiss_any_popover(page):
    for _ in range(5):
        popover = page.query_selector(".driver-popover")
        if not popover or not popover.is_visible():
            return
        close = page.query_selector(".driver-popover-close-btn")
        if close:
            try:
                close.click(force=True)
            except Exception:
                break
        time.sleep(0.25)


def click_bottom_tab(page, tab_label):
    # Tab buttons live under data-tour-id="workspace-bottom"
    page.locator('[data-tour-id="workspace-bottom"] button', has_text=tab_label).first.click()
    time.sleep(0.2)


def assert_text_visible(page, text, label):
    locator = page.get_by_text(text, exact=False).first
    try:
        locator.wait_for(state="visible", timeout=3000)
    except PWTimeout:
        html = page.content()
        raise AssertionError(f"{label}: expected text {text!r} to be visible")


def t1_verify_key_tab(page):
    goto_fresh(page)
    mark_tours_seen(page)
    force_workspace(page)
    dismiss_any_popover(page)
    time.sleep(0.4)

    click_bottom_tab(page, "verify-key")
    page.screenshot(path=str(SCREENSHOTS / "01_verify_key_tab.png"), full_page=True)

    # Panel shows the empty-state text because inputPath is a fake path / no active dump.
    # Either way, the panel should mount without throwing. Try both real-panel + empty-state.
    body = page.content()
    assert (
        "Key Verification" in body or "verify candidate key bytes" in body
    ), "KeyVerificationPanel did not render any of its strings"
    print("PASS: verify-key tab renders")


def t2_auto_export_mode(page):
    goto_fresh(page)
    mark_tours_seen(page)
    force_workspace(page)
    dismiss_any_popover(page)
    time.sleep(0.4)

    click_bottom_tab(page, "architect")
    page.screenshot(path=str(SCREENSHOTS / "02_architect_manual.png"), full_page=True)

    # Click the Auto-Detect mode toggle
    auto_btn = page.locator(
        '[data-tour-id="workspace-bottom"] button', has_text="Auto-Detect"
    ).first
    auto_btn.click()
    time.sleep(0.3)
    page.screenshot(path=str(SCREENSHOTS / "03_architect_auto.png"), full_page=True)

    body = page.content()
    # JSX escapes '&' to '&amp;' in HTML output
    assert (
        "Auto-Detect &amp; Export" in body or "Auto-Detect & Export" in body
    ), "Auto-Detect submit button did not render"
    assert "Context padding" in body, "Auto-Detect context slider missing"
    assert "Align candidates" in body, "Auto-Detect align toggle missing"
    print("PASS: architect auto-detect mode renders")


def main():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1400, "height": 900})
        page = ctx.new_page()
        page.on("pageerror", lambda e: print(f"PAGEERROR: {e}", file=sys.stderr))
        page.on(
            "console",
            lambda msg: print(f"CONSOLE {msg.type}: {msg.text}", file=sys.stderr)
            if msg.type in ("error", "warning")
            else None,
        )

        failures = []
        for fn in (t1_verify_key_tab, t2_auto_export_mode):
            try:
                fn(page)
            except Exception as e:
                failures.append((fn.__name__, e))
                print(f"FAIL: {fn.__name__}: {e}", file=sys.stderr)

        browser.close()

    if failures:
        for name, e in failures:
            print(f"  - {name}: {e}")
        sys.exit(1)
    print(f"\nScreenshots saved to {SCREENSHOTS}/")


if __name__ == "__main__":
    main()
