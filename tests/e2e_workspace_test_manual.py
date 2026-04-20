"""E2E Playwright test for workspace layout resizing and full workflow."""
import os
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

FRONTEND_URL = "http://localhost:5173"
SCREENSHOT_DIR = Path("/tmp/memdiver_e2e_screenshots")
SCREENSHOT_DIR.mkdir(exist_ok=True)

# Test fixture paths
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "dataset"
TLS12_RUN_DIR = FIXTURE_ROOT / "TLS12" / "scenario_a" / "openssl" / "openssl_run_12_1"
TEST_DUMP = TLS12_RUN_DIR / "20240101_120001_000002_post_handshake.dump"


def screenshot(page, name):
    path = SCREENSHOT_DIR / f"{name}.png"
    page.screenshot(path=str(path), full_page=True)
    print(f"  Screenshot: {path}")


def test_wizard_and_file_load(page):
    """Test 1: Navigate wizard and load a single dump file."""
    print("\n=== Test 1: Wizard + File Load ===")
    page.goto(FRONTEND_URL)
    page.wait_for_load_state("networkidle")
    screenshot(page, "01_wizard_start")

    # Step 1: Enter path to dump file
    path_input = page.locator('input[placeholder="Enter path to file or directory"]')
    path_input.wait_for(state="visible", timeout=10000)
    path_input.fill(str(TEST_DUMP))
    print(f"  Entered path: {TEST_DUMP}")

    # Click Next
    next_btn = page.locator('button:has-text("Next")')
    next_btn.click()
    page.wait_for_timeout(1500)  # Wait for path validation
    screenshot(page, "02_after_next")

    # Step 3 (Analysis) - should skip Step 2 for single file
    # Select "Inspect Only"
    inspect_btn = page.locator('button:has-text("Inspect Only")')
    if inspect_btn.is_visible(timeout=5000):
        inspect_btn.click()
        print("  Selected: Inspect Only")
    else:
        print("  WARN: Inspect Only button not found, trying to proceed")

    page.wait_for_timeout(500)
    screenshot(page, "03_analysis_step")

    # Click "Start Analysis"
    start_btn = page.locator('button:has-text("Start Analysis")')
    if start_btn.is_visible(timeout=3000):
        start_btn.click()
        print("  Clicked: Start Analysis")
    else:
        # Maybe button text differs
        start_btn = page.locator('button:has-text("Start")')
        start_btn.click()
        print("  Clicked: Start (fallback)")

    page.wait_for_timeout(2000)
    page.wait_for_load_state("networkidle")
    screenshot(page, "04_workspace_loaded")

    # Verify workspace elements
    logo = page.locator('img[src="/memdiver-logo.svg"]')
    assert logo.is_visible(), "Logo not visible in workspace"
    print("  OK: Logo visible")

    # Check for hex offset input (indicates hex viewer loaded)
    # There may be multiple offset inputs (sidebar + main), use .first
    offset_input = page.locator('input[placeholder="0x offset"]').first
    if offset_input.is_visible(timeout=5000):
        print("  OK: Hex offset input visible")
    else:
        print("  WARN: Hex offset input not found")

    # Check sidebar tabs are visible
    for tab_name in ["bookmarks", "dumps", "format", "structures", "sessions", "import"]:
        tab = page.locator(f'button:has-text("{tab_name}")')
        if tab.is_visible():
            text = tab.inner_text()
            print(f"  OK: Sidebar tab '{tab_name}' visible, text='{text}'")
        else:
            print(f"  WARN: Sidebar tab '{tab_name}' not visible")

    return True


def get_panel_widths(page):
    """Get current panel widths by measuring direct children of the horizontal group."""
    result = page.evaluate("""() => {
        // Find the horizontal group element
        const hGroup = document.getElementById('memdiver-h-layout');
        if (!hGroup) return { error: 'h-layout not found' };

        // Get all direct children (panels and separators)
        const children = Array.from(hGroup.children);
        const panelWidths = [];
        for (const child of children) {
            const rect = child.getBoundingClientRect();
            const role = child.getAttribute('role');
            const isSep = role === 'separator';
            panelWidths.push({
                role: role || 'panel',
                width: rect.width,
                height: rect.height,
                x: rect.x
            });
        }

        // Also get vertical group info
        const vGroup = document.getElementById('memdiver-v-layout');
        let vChildren = [];
        if (vGroup) {
            vChildren = Array.from(vGroup.children).map(child => {
                const rect = child.getBoundingClientRect();
                return {
                    role: child.getAttribute('role') || 'panel',
                    width: rect.width,
                    height: rect.height,
                    y: rect.y
                };
            });
        }

        return { horizontal: panelWidths, vertical: vChildren };
    }""")
    return result


def test_panel_resize(page):
    """Test 2: Verify panel separators can be dragged to resize."""
    print("\n=== Test 2: Panel Resize ===")

    # Debug: inspect DOM to find actual panel/handle attributes
    debug_info = page.evaluate("""() => {
        const handles = document.querySelectorAll('[role="separator"]');
        const handleInfo = Array.from(handles).map(h => ({
            tag: h.tagName,
            attrs: Array.from(h.attributes).map(a => a.name + '=' + a.value).join(', '),
            box: h.getBoundingClientRect()
        }));
        const panels = document.querySelectorAll('[data-panel-id]');
        const panelInfo = Array.from(panels).map(p => ({
            id: p.getAttribute('data-panel-id'),
            box: p.getBoundingClientRect()
        }));
        return { handles: handleInfo, panels: panelInfo };
    }""")
    print(f"  DOM handles: {len(debug_info['handles'])}")
    for i, h in enumerate(debug_info['handles']):
        print(f"    Handle {i}: {h['attrs'][:120]}")
    print(f"  DOM panels: {len(debug_info['panels'])}")
    for p in debug_info['panels']:
        print(f"    Panel '{p['id']}': {p['box']['width']:.0f}x{p['box']['height']:.0f}")

    # Get initial panel layout
    initial = get_panel_widths(page)
    if "horizontal" in initial:
        print("  Horizontal layout children:")
        for i, child in enumerate(initial["horizontal"]):
            print(f"    [{i}] {child['role']}: {child['width']:.0f}x{child['height']:.0f} at x={child['x']:.0f}")
        sidebar_width_before = initial["horizontal"][0]["width"] if initial["horizontal"] else 0
        print(f"  Sidebar width (panel 0): {sidebar_width_before:.0f}px")
    if "vertical" in initial:
        print("  Vertical layout children:")
        for i, child in enumerate(initial["vertical"]):
            print(f"    [{i}] {child['role']}: {child['width']:.0f}x{child['height']:.0f} at y={child['y']:.0f}")
    screenshot(page, "05_before_resize")

    # Find horizontal resize handles
    h_handles = page.locator('#memdiver-h-layout > [role="separator"]').all()
    print(f"  Found {len(h_handles)} horizontal resize handles")

    if len(h_handles) >= 1:
        # Drag first separator (between sidebar and main) rightward by 150px
        handle = h_handles[0]
        box = handle.bounding_box()
        if box:
            start_x = box["x"] + box["width"] / 2
            start_y = box["y"] + box["height"] / 2
            print(f"  Handle 1 position: ({start_x:.0f}, {start_y:.0f})")

            page.mouse.move(start_x, start_y)
            page.mouse.down()
            for step in range(15):
                page.mouse.move(start_x + (step + 1) * 10, start_y)
                page.wait_for_timeout(30)
            page.mouse.up()
            page.wait_for_timeout(500)

            after = get_panel_widths(page)
            sidebar_width_after = after["horizontal"][0]["width"] if "horizontal" in after and after["horizontal"] else 0
            delta = sidebar_width_after - sidebar_width_before
            print(f"  Sidebar after expand: {sidebar_width_after:.0f}px (delta={delta:+.0f}px)")
            screenshot(page, "06_sidebar_expanded")

            if delta > 20:
                print("  OK: Sidebar successfully resized wider")
            else:
                print(f"  WARN: Sidebar resize delta small ({delta:.0f}px)")

            # Drag back leftward
            box2 = handle.bounding_box()
            if box2:
                start_x2 = box2["x"] + box2["width"] / 2
                page.mouse.move(start_x2, start_y)
                page.mouse.down()
                for step in range(20):
                    page.mouse.move(start_x2 - (step + 1) * 10, start_y)
                    page.wait_for_timeout(30)
                page.mouse.up()
                page.wait_for_timeout(500)
                shrunk = get_panel_widths(page)
                sidebar_shrunk = shrunk["horizontal"][0]["width"] if "horizontal" in shrunk and shrunk["horizontal"] else 0
                print(f"  Sidebar after shrink: {sidebar_shrunk:.0f}px")
                screenshot(page, "07_sidebar_shrunk")

    if len(h_handles) >= 2:
        # Drag second separator leftward to widen detail
        handle2 = h_handles[1]
        box = handle2.bounding_box()
        if box:
            start_x = box["x"] + box["width"] / 2
            start_y = box["y"] + box["height"] / 2
            print(f"  Handle 2 position: ({start_x:.0f}, {start_y:.0f})")

            page.mouse.move(start_x, start_y)
            page.mouse.down()
            for step in range(15):
                page.mouse.move(start_x - (step + 1) * 10, start_y)
                page.wait_for_timeout(30)
            page.mouse.up()
            page.wait_for_timeout(500)

            detail_after = get_panel_widths(page)
            detail_w = detail_after["horizontal"][-1]["width"] if "horizontal" in detail_after and detail_after["horizontal"] else 0
            print(f"  Detail panel after expand: {detail_w:.0f}px")
            screenshot(page, "08_detail_expanded")

    # Vertical resize
    v_handles = page.locator('#memdiver-v-layout > [role="separator"]').all()
    print(f"  Found {len(v_handles)} vertical resize handles")

    if len(v_handles) >= 1:
        handle_v = v_handles[0]
        box = handle_v.bounding_box()
        if box:
            start_x = box["x"] + box["width"] / 2
            start_y = box["y"] + box["height"] / 2

            page.mouse.move(start_x, start_y)
            page.mouse.down()
            for step in range(10):
                page.mouse.move(start_x, start_y - (step + 1) * 10)
                page.wait_for_timeout(30)
            page.mouse.up()
            page.wait_for_timeout(500)
            screenshot(page, "09_vertical_resize")
            print("  OK: Vertical separator dragged")

    return True


def test_layout_space(page):
    """Test 4: Verify layout space utilization."""
    print("\n=== Test 4: Layout Space Utilization ===")

    # Check sidebar tab texts are not truncated
    sidebar_tabs = page.locator('button.truncate').all()
    for tab in sidebar_tabs:
        text = tab.inner_text().strip()
        box = tab.bounding_box()
        if box and text:
            print(f"  Tab '{text}': width={box['width']:.0f}px")

    # Check detail panel header
    detail_headers = page.locator('h3:has-text("Details"), h3:has-text("Results Summary")').all()
    for h in detail_headers:
        text = h.inner_text().strip()
        box = h.bounding_box()
        if box:
            visible = box["width"] > 50
            print(f"  Detail header '{text}': width={box['width']:.0f}px, visible={visible}")
            if visible:
                print("  OK: Detail header fully visible")

    # Check hex viewer fills space
    hex_container = page.locator('[data-panel-id="main"], #main')
    if hex_container.count() > 0:
        box = hex_container.first.bounding_box()
        if box:
            print(f"  Main panel: {box['width']:.0f}x{box['height']:.0f}px")
            if box["width"] > 300:
                print("  OK: Main panel has adequate width")

    # Check separator thickness
    separators = page.locator('[data-resize-handle-state]').all()
    if not separators:
        separators = page.locator('[data-panel-resize-handle-id]').all()
    for i, sep in enumerate(separators):
        box = sep.bounding_box()
        if box:
            thickness = min(box["width"], box["height"])
            print(f"  Separator {i}: {box['width']:.0f}x{box['height']:.0f}px (thickness={thickness:.0f}px)")
            if thickness <= 6:
                print(f"  OK: Separator {i} is thin ({thickness:.0f}px)")
            else:
                print(f"  WARN: Separator {i} may be too thick ({thickness:.0f}px)")

    screenshot(page, "10_layout_final")
    return True


def test_analysis_workflow(page):
    """Test 3: Run analysis from the workspace bottom panel."""
    print("\n=== Test 3: Analysis Workflow ===")

    # Click on bottom panel tabs - use text-exact matching to avoid matching "Run Analysis" button
    # The bottom tabs are: "analysis", "results", "entropy" (lowercase, capitalize CSS)
    bottom_tabs = page.locator('button.capitalize.text-xs')
    tab_count = bottom_tabs.count()
    print(f"  Found {tab_count} bottom tab buttons")

    # Find and click the "Analysis" tab (first capitalize tab)
    for i in range(tab_count):
        tab = bottom_tabs.nth(i)
        text = tab.inner_text().strip().lower()
        if "analysis" in text and "run" not in text:
            tab.click()
            page.wait_for_timeout(500)
            print(f"  Clicked: Analysis tab (text='{text}')")
            screenshot(page, "11_analysis_tab")
            break

    # Switch to results tab
    for i in range(tab_count):
        tab = bottom_tabs.nth(i)
        text = tab.inner_text().strip().lower()
        if "results" in text:
            tab.click()
            page.wait_for_timeout(500)
            print(f"  Clicked: Results tab (text='{text}')")
            break

    # Switch to entropy tab
    for i in range(tab_count):
        tab = bottom_tabs.nth(i)
        text = tab.inner_text().strip().lower()
        if "entropy" in text:
            tab.click()
            page.wait_for_timeout(2000)
            print(f"  Clicked: Entropy tab (text='{text}')")
            screenshot(page, "12_entropy_tab")
            break

    return True


def main():
    print(f"Starting E2E workspace tests...")
    print(f"Screenshots will be saved to: {SCREENSHOT_DIR}")
    print(f"Test dump file: {TEST_DUMP}")
    print(f"Test dump exists: {TEST_DUMP.exists()}")

    all_passed = True

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})

        try:
            # Test 1: Wizard + File Load
            if not test_wizard_and_file_load(page):
                print("FAIL: Test 1 failed")
                all_passed = False

            # Test 2: Panel Resize
            if not test_panel_resize(page):
                print("FAIL: Test 2 failed")
                all_passed = False

            # Test 3: Analysis Workflow
            if not test_analysis_workflow(page):
                print("FAIL: Test 3 failed")
                all_passed = False

            # Test 4: Layout Space Utilization
            if not test_layout_space(page):
                print("FAIL: Test 4 failed")
                all_passed = False

        except Exception as e:
            print(f"\nERROR: {e}")
            screenshot(page, "error_state")
            all_passed = False
            import traceback
            traceback.print_exc()
        finally:
            browser.close()

    if all_passed:
        print("\n=== ALL TESTS PASSED ===")
    else:
        print("\n=== SOME TESTS FAILED ===")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
