#!/usr/bin/env python3
"""End-to-end Playwright test for MemDiver FTUE tours."""
import time
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

SCREENSHOTS = Path("/tmp/tour_screenshots")
SCREENSHOTS.mkdir(exist_ok=True)

URL = "http://localhost:5173"
POPOVER = ".driver-popover"


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
            inputPath: '/tmp/dummy',
            inputMode: 'file'
          });
        }"""
    )


def wait_popover(page, timeout=5000):
    page.wait_for_selector(POPOVER, state="visible", timeout=timeout)


def popover_visible(page):
    el = page.query_selector(POPOVER)
    if not el:
        return False
    try:
        return el.is_visible()
    except Exception:
        return False


def popover_text(page):
    el = page.query_selector(POPOVER)
    if not el:
        return ""
    return (el.inner_text() or "").strip()


def get_seen_tours(page):
    return page.evaluate(
        "() => { try { return JSON.parse(localStorage.getItem('memdiver:ftue:seen') || '[]'); } catch(e){ return []; } }"
    )


def click_next(page):
    page.click(".driver-popover-next-btn")


def t1_workspace_tour_auto_starts(page):
    goto_fresh(page)
    force_workspace(page)
    wait_popover(page, timeout=6000)
    text = popover_text(page)
    assert ("Welcome to MemDiver" in text) or ("Quick 30-second tour" in text), \
        f"Expected workspace welcome step, got: {text!r}"
    # Distinguish from structure-overlay welcome
    assert "apply your first structure" not in text, \
        "Structure-overlay tour fired instead of workspace-layout"
    page.screenshot(path=str(SCREENSHOTS / "01_workspace_tour_started.png"))


def t2_advance_through_workspace_tour(page):
    goto_fresh(page)
    force_workspace(page)
    wait_popover(page)
    # 7 steps -> 7 "next" clicks (last click labeled "Done" closes the tour)
    for i in range(7):
        click_next(page)
        time.sleep(0.35)
    time.sleep(0.6)
    # Verify workspace tour is marked completed via localStorage.
    # A new popover may appear immediately (structure-overlay-101), which is fine.
    seen = get_seen_tours(page)
    entry = next((s for s in seen if s.get("id") == "workspace-layout-101"), None)
    assert entry is not None, f"workspace-layout-101 not in seenTours: {seen}"
    assert entry.get("completed") is True, f"tour not marked completed: {entry}"
    assert entry.get("version") == 1, f"unexpected version: {entry}"
    # If a popover is still visible, confirm it's NOT the workspace tour anymore.
    if popover_visible(page):
        text = popover_text(page)
        assert "Quick 30-second tour" not in text, \
            f"workspace tour popover still showing: {text!r}"
    page.screenshot(path=str(SCREENSHOTS / "02_workspace_tour_completed.png"))


def t3_no_repeat_after_reload(page):
    goto_fresh(page)
    force_workspace(page)
    wait_popover(page)
    for _ in range(7):
        click_next(page)
        time.sleep(0.3)
    time.sleep(0.5)
    # After completing, structure-overlay tour may auto-start. Close anything open.
    while popover_visible(page):
        close = page.query_selector(".driver-popover-close-btn")
        if not close:
            break
        try:
            close.click(force=True)
        except Exception:
            break
        time.sleep(0.3)
    # Reload
    page.reload()
    page.wait_for_load_state("networkidle")
    force_workspace(page)
    time.sleep(2.0)
    # workspace-layout should NOT be visible (structure-overlay may trigger — allow it)
    text = popover_text(page)
    if popover_visible(page):
        # If something is visible, it must NOT be the workspace tour
        assert "Quick 30-second tour" not in text, \
            f"workspace tour re-shown after reload: {text!r}"
    seen = get_seen_tours(page)
    assert any(s.get("id") == "workspace-layout-101" for s in seen), \
        "seenTours lost workspace-layout-101 after reload"
    page.screenshot(path=str(SCREENSHOTS / "03_no_repeat_after_reload.png"))


def t4_structure_tour_auto_starts_after_workspace(page):
    goto_fresh(page)
    force_workspace(page)
    wait_popover(page)
    # Complete workspace-layout-101
    for _ in range(7):
        click_next(page)
        time.sleep(0.3)
    time.sleep(0.8)
    # Now structure-overlay-101 should fire (predicate sees seenTours has entry)
    try:
        page.wait_for_selector(POPOVER, state="visible", timeout=6000)
    except PWTimeout:
        page.screenshot(path=str(SCREENSHOTS / "04_structure_tour_triggered_FAIL.png"))
        raise AssertionError("structure-overlay-101 did not auto-start")
    text = popover_text(page)
    assert "Welcome" in text and "apply your first structure" in text, \
        f"Expected structure-overlay welcome, got: {text!r}"
    page.screenshot(path=str(SCREENSHOTS / "04_structure_tour_triggered.png"))


def t5_version_bump_replay(page):
    page.goto(URL)
    page.wait_for_load_state("networkidle")
    page.evaluate(
        """() => {
          try { localStorage.clear(); } catch(e){}
          localStorage.setItem('memdiver:ftue:seen', JSON.stringify([{
            id: 'workspace-layout-101', version: 0, seenAt: Date.now(), completed: true
          }]));
        }"""
    )
    page.reload()
    page.wait_for_load_state("networkidle")
    force_workspace(page)
    wait_popover(page, timeout=6000)
    text = popover_text(page)
    assert ("Quick 30-second tour" in text) or ("Welcome to MemDiver" in text and "apply your first structure" not in text), \
        f"Expected workspace tour to replay, got: {text!r}"
    page.screenshot(path=str(SCREENSHOTS / "05_version_bump_replay.png"))


def t6_settings_entry_replay(page):
    goto_fresh(page)
    force_workspace(page)
    wait_popover(page)
    # Complete the workspace tour first to get out of tour mode
    for _ in range(7):
        click_next(page)
        time.sleep(0.3)
    time.sleep(0.5)
    # Close the structure-overlay tour if it auto-started
    while popover_visible(page):
        close = page.query_selector(".driver-popover-close-btn")
        if not close:
            break
        try:
            close.click(force=True)
        except Exception:
            break
        time.sleep(0.3)
    time.sleep(0.3)
    # Click Settings button (aria-label="Settings")
    settings_btn = page.query_selector('button[aria-label="Settings"]')
    assert settings_btn is not None, "Settings button not found"
    settings_btn.click(force=True)
    time.sleep(0.4)
    # Find "Run onboarding tour" button
    run_tour_btn = page.query_selector('button:has-text("Run onboarding tour")')
    assert run_tour_btn is not None, "Run onboarding tour button not found"
    run_tour_btn.click(force=True)
    wait_popover(page, timeout=5000)
    page.screenshot(path=str(SCREENSHOTS / "06_settings_replay.png"))


def t7_theme_toggle_mid_tour(page):
    """Verify the FTUE framework survives a theme change while a tour is active.

    Uses page.evaluate to flip the document root's .dark class directly rather
    than clicking the ThemeToggle button: Driver.js's overlay intercepts real
    clicks on non-anchored (centered) steps, which is a separate UX concern
    from the framework's resilience to re-renders. The direct DOM mutation
    faithfully simulates a theme change (e.g. system-preference auto-switch)
    without confounding the test with overlay-click semantics.
    """
    goto_fresh(page)
    force_workspace(page)
    wait_popover(page)
    bg_before = page.evaluate(
        "() => { const el = document.querySelector('.driver-popover');"
        " return el ? getComputedStyle(el).backgroundColor : null; }"
    )
    page.screenshot(path=str(SCREENSHOTS / "07a_before_theme.png"))

    # Flip theme by directly toggling the .dark class + updating localStorage
    # (same operations ThemeProvider performs).
    page.evaluate(
        """() => {
          const html = document.documentElement;
          const wasDark = html.classList.contains('dark');
          html.classList.toggle('dark', !wasDark);
          localStorage.setItem('memdiver-theme', wasDark ? 'light' : 'dark');
        }"""
    )
    time.sleep(0.5)

    store_state = page.evaluate(
        """async () => {
          const m = await import('/src/ftue/store.ts');
          const s = m.useFtueStore.getState();
          return { activeTourId: s.activeTourId, activeStepIndex: s.activeStepIndex };
        }"""
    )
    visible = popover_visible(page)
    page.screenshot(path=str(SCREENSHOTS / "07b_after_theme.png"))

    assert visible, (
        "Popover vanished after theme change while store still reports an "
        f"active tour (store={store_state}). FTUE framework is not resilient "
        "to re-renders during an active tour."
    )
    assert store_state["activeTourId"] == "workspace-layout-101", \
        f"Store lost active tour id: {store_state}"

    bg_after = page.evaluate(
        "() => { const el = document.querySelector('.driver-popover');"
        " return el ? getComputedStyle(el).backgroundColor : null; }"
    )
    assert bg_before != bg_after, \
        f"Popover bg did not update with theme variables: {bg_before} == {bg_after}"


TESTS = [
    ("T1_workspace_auto_starts", t1_workspace_tour_auto_starts),
    ("T2_advance_workspace_tour", t2_advance_through_workspace_tour),
    ("T3_no_repeat_after_reload", t3_no_repeat_after_reload),
    ("T4_structure_auto_after_workspace", t4_structure_tour_auto_starts_after_workspace),
    ("T5_version_bump_replay", t5_version_bump_replay),
    ("T6_settings_entry_replay", t6_settings_entry_replay),
    ("T7_theme_toggle_mid_tour", t7_theme_toggle_mid_tour),
]


def main():
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            for name, fn in TESTS:
                ctx = browser.new_context(viewport={"width": 1600, "height": 1000})
                page = ctx.new_page()
                try:
                    fn(page)
                    results.append((name, "PASS", ""))
                    print(f"PASS  {name}")
                except Exception as e:
                    try:
                        page.screenshot(path=str(SCREENSHOTS / f"{name}_FAIL.png"), full_page=True)
                    except Exception:
                        pass
                    results.append((name, "FAIL", f"{type(e).__name__}: {e}"))
                    print(f"FAIL  {name}  {type(e).__name__}: {e}")
                finally:
                    ctx.close()
        finally:
            browser.close()
    print("\n=== Summary ===")
    for name, status, msg in results:
        print(f"{status}  {name}  {msg}")
    failed = [r for r in results if r[1] == "FAIL"]
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
