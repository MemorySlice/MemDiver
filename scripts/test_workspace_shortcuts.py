#!/usr/bin/env python3
"""End-to-end Playwright regression test for MemDiver workspace shortcuts.

Locks Ctrl+B (toggle sidebar), Ctrl+G (focus offset input), Ctrl+N (new
session) and Ctrl+S (autosave) into place so future refactors cannot
silently reopen Gap G in current_gabs.md.

Modeled after scripts/test_tours.py. Run via the webapp-testing skill's
with_server.py helper while the FastAPI backend + Vite dev server are up.
"""
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

SCREENSHOTS = Path("/tmp/workspace_shortcut_screenshots")
SCREENSHOTS.mkdir(exist_ok=True)

URL = "http://localhost:5173"


def _force_workspace_no_tours(page):
    """Land on the workspace with FTUE tours pre-marked seen so they
    don't intercept keystrokes. Mirrors test_tours.force_workspace but
    suppresses popovers."""
    page.goto(URL)
    page.wait_for_load_state("networkidle")
    page.evaluate(
        """() => {
          try { localStorage.clear(); } catch(e){}
          // Pre-mark every known tour as seen so TourProvider doesn't open
          // a popover that would swallow our key events.
          localStorage.setItem(
            'memdiver:ftue:seen',
            JSON.stringify([
              { id: 'workspace-layout-101', version: 99, seenAt: Date.now(), completed: true },
              { id: 'structure-overlay-101', version: 99, seenAt: Date.now(), completed: true },
            ])
          );
        }"""
    )
    page.reload()
    page.wait_for_load_state("networkidle")
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
    time.sleep(0.5)


def _press_ctrl(page, key):
    """Press Ctrl+<key>. On macOS the keyboard hook also accepts Meta,
    but Playwright on headless Chromium uses Control reliably."""
    page.keyboard.press(f"Control+{key}")
    time.sleep(0.2)


def _sidebar_collapsed(page) -> bool:
    """Return True when the workspace sidebar panel has zero size."""
    return page.evaluate(
        """() => {
          const el = document.querySelector('[data-tour-id="workspace-sidebar"]');
          if (!el) return false;
          // react-resizable-panels sets the parent flex-basis to 0 when collapsed.
          const parent = el.parentElement;
          if (!parent) return false;
          const r = parent.getBoundingClientRect();
          return r.width < 4;
        }"""
    )


def t1_ctrl_b_toggles_sidebar(page):
    _force_workspace_no_tours(page)
    assert not _sidebar_collapsed(page), "sidebar should start expanded"
    _press_ctrl(page, "b")
    time.sleep(0.4)
    assert _sidebar_collapsed(page), "Ctrl+B should collapse the sidebar"
    page.screenshot(path=str(SCREENSHOTS / "01a_collapsed.png"))
    _press_ctrl(page, "b")
    time.sleep(0.4)
    assert not _sidebar_collapsed(page), "Ctrl+B should re-expand the sidebar"
    page.screenshot(path=str(SCREENSHOTS / "01b_expanded.png"))


def t2_ctrl_g_focuses_offset_input(page):
    _force_workspace_no_tours(page)
    # Move focus somewhere benign first so we can detect the move.
    page.evaluate("() => document.body.focus()")
    _press_ctrl(page, "g")
    time.sleep(0.2)
    placeholder = page.evaluate(
        "() => document.activeElement && document.activeElement.getAttribute('placeholder')"
    )
    assert placeholder == "0x offset", (
        f"Ctrl+G should focus an input with placeholder '0x offset', "
        f"got placeholder={placeholder!r}"
    )
    page.screenshot(path=str(SCREENSHOTS / "02_ctrl_g_focused.png"))


def t3_ctrl_n_resets_to_wizard(page):
    _force_workspace_no_tours(page)
    _press_ctrl(page, "n")
    time.sleep(0.4)
    app_view = page.evaluate(
        """async () => {
          const m = await import('/src/stores/app-store.ts');
          return m.useAppStore.getState().appView;
        }"""
    )
    # resetWizard() routes back to the landing page (app-store.ts:229-231);
    # the old assertion predated the landing view being split out of wizard.
    # What Gap G locks in is "Ctrl+N leaves the workspace", so any non-workspace
    # view satisfies the shortcut contract.
    assert app_view in ("wizard", "landing"), (
        f"Ctrl+N should leave the workspace (wizard/landing), got: {app_view!r}"
    )
    page.screenshot(path=str(SCREENSHOTS / "03_ctrl_n_wizard.png"))


def t4_ctrl_s_posts_session(page):
    _force_workspace_no_tours(page)

    captured = {"hits": 0, "method": None, "had_body": False}

    def handler(route, request):
        if request.method == "POST" and "/api/sessions" in request.url:
            captured["hits"] += 1
            captured["method"] = request.method
            try:
                body = request.post_data or ""
                captured["had_body"] = len(body) > 2  # not just '{}'
            except Exception:
                pass
            # Respond OK so the frontend's .catch() doesn't swallow a real failure.
            route.fulfill(
                status=200,
                content_type="application/json",
                body='{"path": "/tmp/x.memdiver", "name": "x", "status": "ok"}',
            )
        else:
            route.continue_()

    page.route("**/api/sessions/**", handler)
    _press_ctrl(page, "s")
    # saveSession is async fire-and-forget; give the network task a tick.
    page.wait_for_timeout(600)
    assert captured["hits"] >= 1, "Ctrl+S did not fire a POST /api/sessions/ request"
    assert captured["method"] == "POST"
    assert captured["had_body"], "Ctrl+S session payload was empty"
    page.screenshot(path=str(SCREENSHOTS / "04_ctrl_s_posted.png"))


TESTS = [
    ("T1_ctrl_b_toggle_sidebar", t1_ctrl_b_toggles_sidebar),
    ("T2_ctrl_g_focus_offset",   t2_ctrl_g_focuses_offset_input),
    ("T3_ctrl_n_reset_wizard",   t3_ctrl_n_resets_to_wizard),
    ("T4_ctrl_s_save_session",   t4_ctrl_s_posts_session),
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
                        page.screenshot(
                            path=str(SCREENSHOTS / f"{name}_FAIL.png"),
                            full_page=True,
                        )
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
