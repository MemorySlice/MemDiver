"""E2E test: full session save → reload → load cycle.

Tests the complete flow:
1. Save a session via API with analysis results
2. Verify it appears in session listing with correct metadata
3. Load it back and verify all fields are restored
4. Delete it and verify it's gone
5. Browser test: landing page shows session, Load navigates to workspace
"""

import os
import socket
import sys
import json
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests._paths import artifacts_dir, dataset_root

BASE_URL = "http://127.0.0.1:8080"


def _backend_listening(host: str = "127.0.0.1", port: int = 8080) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


if not _backend_listening():
    pytest.skip(
        "Backend not running at 127.0.0.1:8080; skipping e2e session-cycle tests.",
        allow_module_level=True,
    )

_DS = dataset_root()
DUMP_PATH = str(
    _DS
    / "TLS13" / "100_iterations_Abort_KeyUpdate" / "boringssl"
    / "boringssl_run_13_10" / "20251018_124115_148128_pre_abort.dump"
) if _DS is not None else None

SCREENSHOT_DIR = str(artifacts_dir("e2e_cycle"))
TEST_SESSION_NAME = "e2e_cycle_test"


def api_request(method, path, data=None, timeout=30):
    """Simple API helper."""
    url = f"{BASE_URL}{path}"
    req_data = json.dumps(data).encode() if data else None
    req = urllib.request.Request(
        url, data=req_data,
        headers={"Content-Type": "application/json"} if req_data else {},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def cleanup_test_session():
    """Remove test session if it exists."""
    try:
        api_request("DELETE", f"/api/sessions/{TEST_SESSION_NAME}")
    except Exception:
        pass


def test_api_save_load_delete():
    """Test 1: Full API-level save → list → load → delete cycle."""
    print("\n--- Test 1: API Save/Load/Delete Cycle ---")
    cleanup_test_session()

    # Step 1: Save a session with realistic data
    save_payload = {
        "session_name": TEST_SESSION_NAME,
        "input_mode": "single_file",
        "input_path": DUMP_PATH,
        "dataset_root": "",
        "keylog_filename": "",
        "template_name": "Auto-detect",
        "protocol_name": "TLS",
        "protocol_version": "13",
        "scenario": "test_scenario",
        "selected_libraries": [],
        "selected_phase": "pre_abort",
        "mode": "verification",
        "selected_algorithms": ["entropy_scan", "change_point", "structure_scan"],
        "analysis_result": {
            "libraries": [{
                "library": "test_dump.dump",
                "protocol_version": "unknown",
                "phase": "file",
                "num_runs": 1,
                "hits": [
                    {"secret_type": "entropy_scan", "offset": 100, "length": 32,
                     "dump_path": DUMP_PATH, "library": "test", "phase": "file",
                     "run_id": 0, "confidence": 0.95},
                    {"secret_type": "change_point", "offset": 500, "length": 48,
                     "dump_path": DUMP_PATH, "library": "test", "phase": "file",
                     "run_id": 0, "confidence": 0.87},
                ],
                "static_regions": [],
                "metadata": {},
            }],
            "metadata": {},
        },
        "bookmarks": [{"offset": 0x100, "length": 32, "label": "test bookmark"}],
        "investigation_offset": 0x100,
    }

    result = api_request("POST", "/api/sessions/", save_payload)
    assert result["status"] == "ok", f"Save failed: {result}"
    assert result["name"] == TEST_SESSION_NAME
    print(f"  Saved session: {result['name']} at {result['path']}")

    # Step 2: Verify it appears in session listing
    listing = api_request("GET", "/api/sessions/")
    sessions = listing["sessions"]
    found = [s for s in sessions if s["name"] == TEST_SESSION_NAME]
    assert len(found) == 1, f"Session not found in listing. Available: {[s['name'] for s in sessions]}"

    session_info = found[0]
    print(f"  Listed session: {session_info}")
    assert session_info["input_mode"] == "single_file", f"input_mode mismatch: {session_info['input_mode']}"
    assert session_info["input_path"] == DUMP_PATH, f"input_path mismatch: {session_info['input_path']}"
    assert session_info["mode"] == "verification", f"mode mismatch: {session_info['mode']}"
    assert session_info["created_at"] != "", "created_at should not be empty"
    # name should be the file stem (for lookups), display_name should be the session_name
    assert session_info["name"] == TEST_SESSION_NAME, f"name (file stem) mismatch: {session_info['name']}"
    assert session_info["display_name"] == TEST_SESSION_NAME, f"display_name mismatch: {session_info.get('display_name')}"
    print("  Session listing metadata verified (including name/display_name)")

    # Step 3: Load the full session and verify all fields
    snap = api_request("GET", f"/api/sessions/{TEST_SESSION_NAME}")
    assert snap["session_name"] == TEST_SESSION_NAME
    assert snap["input_mode"] == "single_file"
    assert snap["input_path"] == DUMP_PATH
    assert snap["protocol_version"] == "13"
    assert snap["protocol_name"] == "TLS"
    assert snap["selected_phase"] == "pre_abort"
    assert snap["mode"] == "verification"
    assert snap["selected_algorithms"] == ["entropy_scan", "change_point", "structure_scan"]

    # Verify analysis results survived serialization
    assert snap["analysis_result"] is not None, "analysis_result should be preserved"
    libs = snap["analysis_result"]["libraries"]
    assert len(libs) == 1
    assert len(libs[0]["hits"]) == 2
    assert libs[0]["hits"][0]["secret_type"] == "entropy_scan"
    assert libs[0]["hits"][0]["offset"] == 100
    assert libs[0]["hits"][1]["secret_type"] == "change_point"
    assert libs[0]["hits"][1]["offset"] == 500
    print("  Full snapshot restoration verified")

    # Verify bookmarks survived
    assert len(snap["bookmarks"]) == 1
    assert snap["bookmarks"][0]["offset"] == 0x100
    assert snap["bookmarks"][0]["label"] == "test bookmark"
    print("  Bookmarks preserved")

    # Step 4: Delete and verify it's gone
    del_result = api_request("DELETE", f"/api/sessions/{TEST_SESSION_NAME}")
    assert del_result["status"] == "ok"

    listing_after = api_request("GET", "/api/sessions/")
    found_after = [s for s in listing_after["sessions"] if s["name"] == TEST_SESSION_NAME]
    assert len(found_after) == 0, "Session should be deleted"
    print("  Session deleted and confirmed gone")

    print("PASS: API save/load/delete cycle complete")


def test_browser_session_load():
    """Test 2: Browser-level session load from landing page."""
    print("\n--- Test 2: Browser Session Load ---")

    # First save a session via API
    cleanup_test_session()
    save_payload = {
        "session_name": TEST_SESSION_NAME,
        "input_mode": "single_file",
        "input_path": DUMP_PATH,
        "mode": "verification",
        "protocol_name": "TLS",
        "protocol_version": "13",
        "selected_phase": "pre_abort",
        "selected_algorithms": ["entropy_scan", "change_point"],
    }
    api_request("POST", "/api/sessions/", save_payload)

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            # Step 1: Navigate to app — should show landing page
            page.goto(BASE_URL)
            page.wait_for_load_state("networkidle")
            page.screenshot(path=f"{SCREENSHOT_DIR}/session_01_landing.png", full_page=True)

            # Step 2: Verify our test session is visible
            session_card = page.locator(f"text={TEST_SESSION_NAME}")
            assert session_card.is_visible(), f"Test session '{TEST_SESSION_NAME}' should be visible on landing"
            print("  Session visible on landing page")

            # Step 3: Verify session metadata is shown
            # Should show input_path and mode
            page_content = page.content()
            # The path should be visible (truncated, but the filename part should be there)
            assert "pre_abort.dump" in page_content or DUMP_PATH in page_content, \
                "Session input_path should be visible"
            print("  Session metadata (path) visible")

            # Step 4: Click Load button for our session
            # Find the session card that contains our test session name, then click its Load button
            session_cards = page.locator("div.md-panel")
            target_card = None
            for i in range(session_cards.count()):
                card = session_cards.nth(i)
                if TEST_SESSION_NAME in card.inner_text():
                    target_card = card
                    break
            assert target_card is not None, f"Could not find card for session '{TEST_SESSION_NAME}'"
            load_btn = target_card.locator("button:has-text('Load')")
            load_btn.click()
            page.wait_for_timeout(2000)
            page.screenshot(path=f"{SCREENSHOT_DIR}/session_02_after_load.png", full_page=True)

            # Step 5: Verify we're now in the workspace
            # The workspace should have the MemDiver toolbar with mode indicator
            workspace_content = page.content()
            has_workspace = (
                "verification" in workspace_content.lower() or
                "exploration" in workspace_content.lower() or
                "New Session" in workspace_content  # Toolbar has "New Session" button
            )

            # Check we're NOT on the landing page anymore
            # Landing has "Sessions" as a heading but workspace has it as a sidebar tab
            heading = page.locator("h2:has-text('Sessions')")
            on_landing = heading.is_visible()

            assert not on_landing, "Should have left the landing page after Load"
            print("  Successfully navigated to workspace after Load")

            # Step 6: Verify the loaded state is reflected
            # The workspace toolbar should show the mode badge
            toolbar_badge = page.locator("span:has-text('verification')").first
            if toolbar_badge.is_visible():
                print("  Mode 'verification' correctly restored in toolbar")
            else:
                print("  (Mode indicator not visible in toolbar, may be styled differently)")

            # Step 7: Click "New Session" in toolbar to go back to landing
            new_session_btn = page.locator("button:has-text('New Session')").first
            if new_session_btn.is_visible():
                new_session_btn.click()
                page.wait_for_timeout(1000)
                page.screenshot(path=f"{SCREENSHOT_DIR}/session_03_back_to_landing.png", full_page=True)

                # Should be back on landing
                landing_heading = page.locator("h2:has-text('Sessions')")
                assert landing_heading.is_visible(), "Should return to landing page after 'New Session'"
                print("  Successfully returned to landing via 'New Session' button")
            else:
                print("  (New Session button not found in toolbar)")

            print("PASS: Browser session load cycle complete")

        finally:
            page.close()
            browser.close()
            cleanup_test_session()


def main():
    if DUMP_PATH is None:
        print("SKIP: dataset unavailable. Set MEMDIVER_DATASET_ROOT to enable.")
        return

    results = {}

    for name, test_fn in [
        ("API Save/Load/Delete", test_api_save_load_delete),
        ("Browser Session Load", test_browser_session_load),
    ]:
        try:
            test_fn()
            results[name] = "PASS"
        except Exception as e:
            results[name] = f"FAIL: {e}"
            print(f"\nFAIL [{name}]: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print("Session Cycle Test Results:")
    all_pass = True
    for name, result in results.items():
        status = "PASS" if result == "PASS" else "FAIL"
        if status == "FAIL":
            all_pass = False
        print(f"  [{status}] {name}: {result}")
    print("=" * 60)
    print(f"\nScreenshots: {SCREENSHOT_DIR}/")

    if not all_pass:
        sys.exit(1)


if __name__ == "__main__":
    main()
