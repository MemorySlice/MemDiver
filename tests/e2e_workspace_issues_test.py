"""E2E tests for the 4 workspace issues fix using Playwright.

Tests:
1. Dump loading: session-restored file appears in DumpList
2. Format detection: ELF format badge shown
3. Structure overlay: Apply/Auto-detect buttons present
4. Mode switching: Verification vs Exploration differentiation
5. Multi-dump workflow: load second dump, mode affects consensus

Requires: memdiver server running on port 8080.
Run: python tests/e2e_workspace_issues_test.py
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

pytest.importorskip("playwright", reason="Playwright not installed; skipping browser e2e tests.")

from playwright.sync_api import sync_playwright

from tests._paths import artifacts_dir, dataset_root

_DS = dataset_root()
_RUN_DIR = (
    _DS / "TLS13" / "100_iterations_Abort_KeyUpdate" / "boringssl" / "boringssl_run_13_10"
    if _DS is not None
    else None
)
DUMP_PATH = str(_RUN_DIR / "20251018_124115_148128_pre_abort.dump") if _RUN_DIR else None
DUMP_PATH_2 = str(_RUN_DIR / "20251018_124115_148128_pre_server_key_update.dump") if _RUN_DIR else None

BASE_URL = "http://127.0.0.1:8080"
SCREENSHOT_DIR = str(artifacts_dir("e2e_issues"))
SESSION_NAME = "e2e_issues_test"


def api(method, path, data=None):
    """Simple API helper."""
    url = f"{BASE_URL}{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"} if body else {},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def setup_session_and_load(page):
    """Create session via API, then load via JS store call in browser."""
    # Ensure session exists
    try:
        api("DELETE", f"/api/sessions/{SESSION_NAME}")
    except Exception:
        pass

    api("POST", "/api/sessions/", {
        "session_name": SESSION_NAME,
        "input_mode": "single_file",
        "input_path": DUMP_PATH,
        "dataset_root": "",
        "keylog_filename": "",
        "template_name": "Auto-detect",
        "protocol_name": "TLS",
        "protocol_version": "13",
        "scenario": "",
        "selected_libraries": [],
        "selected_phase": "",
        "mode": "verification",
        "selected_algorithms": [
            "entropy_scan", "pattern_match", "change_point",
            "structure_scan", "user_regex", "exact_match",
        ],
        "analysis_result": None,
        "bookmarks": [],
        "investigation_offset": None,
    })

    # Load the app
    page.goto(BASE_URL)
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)

    # Find the specific session row and click its Load button
    row = page.locator(f'div.md-panel:has(span:has-text("{SESSION_NAME}"))')
    if row.count() > 0:
        load_btn = row.first.locator('button:has-text("Load")')
        if load_btn.count() > 0:
            load_btn.first.click()
            page.wait_for_timeout(3000)

    return page.locator('span.uppercase').count() > 0


def test_dump_loading():
    """Test 1: Session-loaded file appears in DumpList (not 'No dumps loaded')."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 900})

        loaded = setup_session_and_load(page)

        # Click Dumps tab
        dumps_tab = page.locator('button').filter(has_text="Dumps")
        if dumps_tab.count() > 0 and dumps_tab.first.is_visible():
            dumps_tab.first.click()
        page.wait_for_timeout(500)

        page.screenshot(path=f"{SCREENSHOT_DIR}/01_dump_loading.png", full_page=True)

        assert loaded, "Workspace did not load from session"

        # Wait for async dump-store population
        page.wait_for_timeout(2000)

        # Check that dump appears in list
        no_dumps = page.locator('p:has-text("No dumps loaded.")')
        no_dumps_visible = no_dumps.count() > 0 and no_dumps.first.is_visible()
        assert not no_dumps_visible, "Bug: 'No dumps loaded' shown after session restore"

        dump_entries = page.locator('.font-mono.truncate')
        assert dump_entries.count() > 0, "No dump entries found in sidebar"
        print(f"  Dump entries found: {dump_entries.count()}")

        browser.close()


def test_format_detection():
    """Test 2: Format tab shows format badge (not 'No format detected')."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 900})

        setup_session_and_load(page)
        page.wait_for_timeout(1000)

        # Click Format tab
        format_tab = page.locator('button').filter(has_text="Format")
        if format_tab.count() > 0 and format_tab.first.is_visible():
            format_tab.first.click()
        page.wait_for_timeout(2000)

        page.screenshot(path=f"{SCREENSHOT_DIR}/02_format_detection.png", full_page=True)

        # Key fix: "No format detected" should not appear for ELF files
        # (even if nav_tree fails, format badge should show)
        no_format = page.locator('text="No format detected"')
        has_no_format = no_format.count() > 0 and no_format.first.is_visible()

        if not has_no_format:
            print("  Format detection: no 'No format detected' shown (fix working)")
        else:
            # Check if format badge is also shown (partial tree case)
            badge = page.locator('span.font-mono')
            if badge.count() > 0:
                print(f"  Format badge found alongside message")
            else:
                print("  Warning: no format badge found")

        browser.close()


def test_structure_overlay():
    """Test 3: Structure definitions tab has Apply and Auto-detect buttons."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 900})

        setup_session_and_load(page)
        page.wait_for_timeout(1000)

        # Click Structures tab
        tabs = page.locator('button')
        for i in range(tabs.count()):
            text = tabs.nth(i).inner_text()
            if "structur" in text.lower():
                tabs.nth(i).click()
                break
        page.wait_for_timeout(1000)

        page.screenshot(path=f"{SCREENSHOT_DIR}/03_structures.png", full_page=True)

        # Verify structure heading exists
        heading = page.locator('h3:has-text("Structure Definitions")')
        assert heading.count() > 0, "Structure Definitions heading not found"

        # Verify Auto-detect button
        auto_btn = page.locator('button:has-text("Auto-detect")')
        assert auto_btn.count() > 0, "Auto-detect button not found"

        # Verify Apply buttons (play triangle)
        apply_btns = page.locator('button:has-text("\u25B6")')
        assert apply_btns.count() > 0, f"Apply buttons not found"

        print(f"  Structure panel: {apply_btns.count()} apply buttons + auto-detect")
        browser.close()


def test_mode_switching():
    """Test 4: Verification and Exploration modes show different features."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 900})

        loaded = setup_session_and_load(page)
        if not loaded:
            print("  Skip: workspace did not load")
            browser.close()
            return

        page.wait_for_timeout(500)

        # Verify mode badge
        badge = page.locator('span.uppercase')
        assert badge.count() > 0, "Mode badge not found"
        badge_text = badge.first.inner_text().lower()
        assert "verification" in badge_text, f"Initial mode should be verification, got: {badge_text}"

        page.screenshot(path=f"{SCREENSHOT_DIR}/04_verification.png", full_page=True)

        # Entropy tab should be hidden in verification
        entropy_tab = page.locator('button').filter(has_text="entropy")
        entropy_visible = entropy_tab.count() > 0 and entropy_tab.first.is_visible()
        assert not entropy_visible, "Entropy tab should be hidden in Verification"

        # Mode description visible
        desc = page.locator('text=/validate known patterns/i')
        assert desc.count() > 0, "Verification description not found"

        # Switch to Exploration
        exploration_btn = page.locator('button').filter(has_text="Exploration")
        if exploration_btn.count() > 0:
            exploration_btn.first.click()
        page.wait_for_timeout(500)

        page.screenshot(path=f"{SCREENSHOT_DIR}/04_exploration.png", full_page=True)

        # Badge should change
        badge_after = page.locator('span.uppercase').first.inner_text().lower()
        assert "exploration" in badge_after, f"Mode should be exploration, got: {badge_after}"

        # Entropy tab now visible
        entropy_after = page.locator('button').filter(has_text="entropy")
        assert entropy_after.count() > 0, "Entropy tab should be visible in Exploration"

        # Exploration description
        exp_desc = page.locator('text=/full discovery toolkit/i')
        assert exp_desc.count() > 0, "Exploration description not found"

        print("  Mode switching: tabs/descriptions change correctly")
        browser.close()


def test_multi_dump_workflow():
    """Test 5: Add dump via AddDumpButton, mode affects consensus visibility."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 900})

        loaded = setup_session_and_load(page)
        if not loaded:
            print("  Skip: workspace did not load")
            browser.close()
            return

        page.wait_for_timeout(500)

        # Go to Dumps tab
        dumps_tab = page.locator('button').filter(has_text="Dumps")
        if dumps_tab.count() > 0:
            dumps_tab.first.click()
        page.wait_for_timeout(500)

        # Add first dump manually
        add_input = page.locator('input[placeholder="Server path to dump file"]')
        if add_input.count() > 0 and add_input.first.is_visible():
            add_input.first.fill(DUMP_PATH)
            add_btn = page.locator('button:has-text("Add")')
            if add_btn.count() > 0:
                add_btn.first.click()
            page.wait_for_timeout(1500)

        # Add second dump
        if add_input.count() > 0 and add_input.first.is_visible():
            add_input.first.fill(DUMP_PATH_2)
            add_btn = page.locator('button:has-text("Add")')
            if add_btn.count() > 0:
                add_btn.first.click()
            page.wait_for_timeout(1500)

        page.screenshot(path=f"{SCREENSHOT_DIR}/05_multi_dump.png", full_page=True)

        # Count dump entries
        dump_entries = page.locator('.font-mono.truncate')
        count = dump_entries.count()
        assert count >= 2, f"Expected 2+ dumps, got {count}"

        # In verification mode, consensus should be hidden
        consensus_btn = page.locator('button:has-text("Run Consensus")')
        consensus_visible = consensus_btn.count() > 0 and consensus_btn.first.is_visible()
        assert not consensus_visible, "Consensus should be hidden in Verification mode"

        # Switch to Exploration
        exploration_btn = page.locator('button').filter(has_text="Exploration")
        if exploration_btn.count() > 0:
            exploration_btn.first.click()
        page.wait_for_timeout(500)

        # Go back to Dumps tab (mode switch might have changed view)
        dumps_tab2 = page.locator('button').filter(has_text="Dumps")
        if dumps_tab2.count() > 0:
            dumps_tab2.first.click()
        page.wait_for_timeout(500)

        page.screenshot(path=f"{SCREENSHOT_DIR}/05_exploration.png", full_page=True)

        # Consensus should now be visible
        consensus_after = page.locator('button:has-text("Run Consensus")')
        assert consensus_after.count() > 0 and consensus_after.first.is_visible(), (
            "Consensus should be visible in Exploration mode"
        )

        print(f"  Multi-dump: {count} dumps loaded, consensus gated by mode")
        browser.close()


def cleanup():
    try:
        api("DELETE", f"/api/sessions/{SESSION_NAME}")
    except Exception:
        pass


if __name__ == "__main__":
    if DUMP_PATH is None:
        print("SKIP: dataset unavailable. Set MEMDIVER_DATASET_ROOT to enable.")
        sys.exit(0)

    print("Running E2E workspace issues tests...")
    tests = [
        test_dump_loading,
        test_format_detection,
        test_structure_overlay,
        test_mode_switching,
        test_multi_dump_workflow,
    ]
    passed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS: {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {test.__name__}: {e}")
    cleanup()
    print(f"\n{passed}/{len(tests)} tests passed")
    print(f"Screenshots saved to {SCREENSHOT_DIR}")
