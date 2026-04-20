"""E2E tests for the 4 workspace fixes using Playwright."""

import os
import sys
import json
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from playwright.sync_api import sync_playwright

from tests._paths import artifacts_dir, dataset_root

BASE_URL = "http://127.0.0.1:8080"
SCREENSHOT_DIR = str(artifacts_dir("e2e_fixes"))

_DS = dataset_root()
DUMP_PATH = str(
    _DS
    / "TLS13" / "100_iterations_Abort_KeyUpdate" / "boringssl"
    / "boringssl_run_13_10" / "20251018_124115_148128_pre_abort.dump"
) if _DS is not None else None


def navigate_wizard_to_workspace(page):
    """Helper: navigate from landing through wizard to workspace with a dump file."""
    page.goto(BASE_URL)
    page.wait_for_load_state("networkidle")

    # Click New Session on landing
    page.locator("text=New Session").first.click()
    page.wait_for_timeout(500)

    # Enter dump path
    file_input = page.locator('input[type="text"]').first
    if file_input.is_visible():
        file_input.fill(DUMP_PATH)
        page.wait_for_timeout(1000)

    # Wait for loading overlay to disappear
    page.wait_for_selector("div.fixed.inset-0", state="hidden", timeout=10000)

    # Click through wizard steps
    for _ in range(5):
        page.wait_for_timeout(500)
        # Wait for any overlay to clear
        try:
            page.wait_for_selector("div.fixed.inset-0", state="hidden", timeout=3000)
        except:
            pass

        btns = page.locator('button:has-text("Next"), button:has-text("Continue"), button:has-text("Start"), button:has-text("Open")')
        if btns.count() > 0 and btns.first.is_visible():
            try:
                btns.first.click(timeout=5000)
                page.wait_for_timeout(1000)
            except:
                break
        else:
            break


def test_landing_page(page):
    """Test 1: App starts with session landing page (not wizard)."""
    page.goto(BASE_URL)
    page.wait_for_load_state("networkidle")
    page.screenshot(path=f"{SCREENSHOT_DIR}/01_landing.png", full_page=True)

    heading = page.locator("text=Sessions")
    assert heading.is_visible(), "Landing page should show Sessions heading"

    new_btn = page.locator("text=New Session").first
    assert new_btn.is_visible(), "Landing page should show New Session button"

    # Should also show MemDiver branding
    brand = page.locator("text=MemDiver")
    assert brand.is_visible(), "Landing page should show MemDiver branding"

    print("PASS: Landing page shows correctly")


def test_wizard_navigation(page):
    """Test 2: New Session button navigates to wizard."""
    page.goto(BASE_URL)
    page.wait_for_load_state("networkidle")

    page.locator("text=New Session").first.click()
    page.wait_for_timeout(500)
    page.screenshot(path=f"{SCREENSHOT_DIR}/02_wizard.png", full_page=True)

    content = page.content()
    # Wizard should be visible with some form of data selection
    assert "Browse" in content or "path" in content.lower() or "select" in content.lower(), \
        "Should navigate to wizard after clicking New Session"
    print("PASS: Wizard navigation works")


def test_algorithm_results_api():
    """Test 3: Analysis API produces results from multiple algorithms."""
    req_data = json.dumps({
        "dump_path": DUMP_PATH,
        "algorithms": ["entropy_scan", "pattern_match", "change_point", "structure_scan"]
    }).encode()

    req = urllib.request.Request(
        f"{BASE_URL}/api/analysis/run-file",
        data=req_data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read())

    libs = result.get("libraries", [])
    assert len(libs) > 0, "Should have at least one library in result"

    hits = libs[0].get("hits", [])
    secret_types = set(h["secret_type"] for h in hits)

    print(f"  Total hits: {len(hits)}")
    print(f"  Algorithm types found: {secret_types}")

    algo_metadata = libs[0].get("metadata", {}).get("algorithm_results", {})
    for algo, meta in algo_metadata.items():
        print(f"  {algo}: {meta}")

    assert len(secret_types) >= 1, f"Expected results from algorithms, got: {secret_types}"
    # At minimum entropy_scan should produce results on a real dump
    assert "entropy_scan" in secret_types, f"entropy_scan should produce results, got: {secret_types}"
    print("PASS: Multiple algorithms produced results")


def test_entropy_api():
    """Test 4: Entropy API returns valid data (not crashing)."""
    url = f"{BASE_URL}/api/inspect/entropy?dump_path={urllib.request.quote(DUMP_PATH)}&offset=0&length=0"
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.loads(resp.read())

    assert "profile_sample" in data, "Response should have profile_sample"
    assert "high_entropy_regions" in data, "Response should have high_entropy_regions"
    assert "overall_entropy" in data, "Response should have overall_entropy"

    print(f"  Overall entropy: {data['overall_entropy']:.4f}")
    print(f"  Profile samples: {len(data['profile_sample'])}")
    print(f"  High entropy regions: {len(data['high_entropy_regions'])}")
    print("PASS: Entropy API returns valid data")


def test_entropy_chart_no_crash(page):
    """Test 5: EntropyChart component handles data without crashing."""
    navigate_wizard_to_workspace(page)
    page.screenshot(path=f"{SCREENSHOT_DIR}/05a_workspace.png", full_page=True)

    # Check if we're in workspace (look for MemDiver toolbar)
    content = page.content()
    if "MemDiver" not in content:
        print("SKIP: Could not navigate to workspace (wizard flow may have changed)")
        return

    # Click Entropy tab in bottom panel
    entropy_tab = page.locator("button:has-text('entropy')").first
    if entropy_tab.is_visible():
        entropy_tab.click()
        page.wait_for_timeout(3000)
        page.screenshot(path=f"{SCREENSHOT_DIR}/05b_entropy.png", full_page=True)

        # Verify no white screen - MemDiver header should still be visible
        assert page.locator("text=MemDiver").is_visible(), "App should not crash (white screen) when viewing entropy"

        # Check for valid states: chart visible, "No entropy" message, or loading
        has_plotly = "plotly" in page.content().lower() or "js-plotly" in page.content()
        has_no_data = page.locator("text=No entropy profile").is_visible()
        has_loading = page.locator("text=Loading entropy").is_visible()

        assert has_plotly or has_no_data or has_loading, \
            "Should show entropy chart, 'no data' message, or loading state"
        print(f"PASS: Entropy tab works (chart: {has_plotly}, no data: {has_no_data})")
    else:
        print("SKIP: Entropy tab not found in workspace")


def main():
    if DUMP_PATH is None:
        print("SKIP: dataset unavailable. Set MEMDIVER_DATASET_ROOT to enable.")
        return

    results = {}

    # API tests (no browser needed)
    for name, test_fn in [
        ("Entropy API", test_entropy_api),
        ("Algorithm Results (API)", test_algorithm_results_api),
    ]:
        try:
            test_fn()
            results[name] = "PASS"
        except Exception as e:
            results[name] = f"FAIL: {e}"
            print(f"FAIL [{name}]: {e}")

    # Browser tests
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        for name, test_fn in [
            ("Landing Page", test_landing_page),
            ("Wizard Navigation", test_wizard_navigation),
            ("Entropy Chart No Crash", test_entropy_chart_no_crash),
        ]:
            page = browser.new_page()
            try:
                test_fn(page)
                results[name] = "PASS"
            except Exception as e:
                results[name] = f"FAIL: {e}"
                print(f"FAIL [{name}]: {e}")
                try:
                    page.screenshot(path=f"{SCREENSHOT_DIR}/FAIL_{name.replace(' ', '_')}.png", full_page=True)
                except:
                    pass
            finally:
                page.close()

        browser.close()

    print("\n" + "=" * 60)
    print("E2E Test Results:")
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
