"""E2E tests for MemDiver session features using Playwright.

Tests landing page rendering and core API endpoints via browser fetch.
Run with: python tests/e2e_session_features_test.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from playwright.sync_api import sync_playwright

from tests._paths import REPO_ROOT, artifacts_dir, dataset_root

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL = "http://127.0.0.1:8080"
# Server cwd: repo root (where api.main lives). The uvicorn factory import
# is resolved from here.
MEMDIVER_ROOT = str(REPO_ROOT)

_DS = dataset_root()
DUMP_PATH = str(
    _DS
    / "TLS13" / "20_iterations_Abort_KeyUpdate" / "boringssl"
    / "boringssl_run_13_10" / "20251013_131451_383028_pre_server_key_update.dump"
) if _DS is not None else None

SCREENSHOT_PATH = str(artifacts_dir() / "memdiver_e2e_result.png")
TIMEOUT_MS = 10_000

# ---------------------------------------------------------------------------
# Server lifecycle helpers
# ---------------------------------------------------------------------------


def start_server() -> subprocess.Popen:
    """Launch the FastAPI server and wait until it responds."""
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "api.main:create_app", "--factory",
            "--host", "127.0.0.1", "--port", "8080",
        ],
        cwd=MEMDIVER_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Poll until healthy (max 15 seconds)
    for _ in range(30):
        try:
            req = urllib.request.Request(f"{BASE_URL}/api/notebook/status")
            with urllib.request.urlopen(req, timeout=2):
                return proc
        except (urllib.error.URLError, ConnectionRefusedError, OSError):
            time.sleep(0.5)
    proc.kill()
    raise RuntimeError("Server failed to start within 15 seconds")


def stop_server(proc: subprocess.Popen) -> None:
    """Terminate the server process."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


# ---------------------------------------------------------------------------
# Test results tracker
# ---------------------------------------------------------------------------

results: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str = "") -> None:
    status = "PASS" if passed else "FAIL"
    results.append((name, passed, detail))
    msg = f"  [{status}] {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_landing_page(page) -> None:
    """Navigate to / and verify 'MemDiver' appears in the page."""
    try:
        page.goto(BASE_URL, timeout=TIMEOUT_MS)
        page.wait_for_load_state("networkidle", timeout=TIMEOUT_MS)
        content = page.content()
        found = "MemDiver" in content or "memdiver" in content.lower()
        record("test_landing_page", found, "Header text found" if found else "No MemDiver text")
    except Exception as exc:
        record("test_landing_page", False, str(exc))


def test_format_detection_api(page) -> None:
    """Call /api/inspect/format and verify a response is returned."""
    try:
        page.goto(BASE_URL, timeout=TIMEOUT_MS)
        escaped_path = DUMP_PATH.replace("'", "\\'")
        result = page.evaluate(f'''async () => {{
            const url = "/api/inspect/format?dump_path=" + encodeURIComponent('{escaped_path}');
            const r = await fetch(url);
            return await r.json();
        }}''')
        # Raw .dump files may or may not have a recognized format
        has_format_key = "format" in result
        fmt_value = result.get("format")
        detail = f"format={fmt_value}"
        record("test_format_detection_api", has_format_key, detail)
    except Exception as exc:
        record("test_format_detection_api", False, str(exc))


def test_notebook_status_api(page) -> None:
    """Fetch /api/notebook/status and verify it has 'available' field."""
    try:
        page.goto(BASE_URL, timeout=TIMEOUT_MS)
        result = page.evaluate('''async () => {
            const r = await fetch("/api/notebook/status");
            return await r.json();
        }''')
        has_available = "available" in result
        detail = f"available={result.get('available')}"
        record("test_notebook_status_api", has_available, detail)
    except Exception as exc:
        record("test_notebook_status_api", False, str(exc))


def test_patterns_api(page) -> None:
    """Fetch /api/analysis/patterns and verify >= 3 patterns."""
    try:
        page.goto(BASE_URL, timeout=TIMEOUT_MS)
        result = page.evaluate('''async () => {
            const r = await fetch("/api/analysis/patterns");
            return await r.json();
        }''')
        patterns = result.get("patterns", [])
        passed = len(patterns) >= 3
        detail = f"{len(patterns)} patterns returned"
        record("test_patterns_api", passed, detail)
    except Exception as exc:
        record("test_patterns_api", False, str(exc))


def test_architect_export_api(page) -> None:
    """POST to /api/architect/export with a test pattern and verify YARA output."""
    try:
        page.goto(BASE_URL, timeout=TIMEOUT_MS)
        payload = json.dumps({
            "pattern": {
                "name": "test_pattern",
                "wildcard_hex": "48 8B ?? ?? 00 00",
                "static_mask": [True, True, False, False, True, True],
                "reference_hex": "488b0a0a0000",
            },
            "format": "yara",
            "rule_name": "test_memdiver_rule",
            "description": "E2E test pattern",
        })
        result = page.evaluate(f'''async () => {{
            const r = await fetch("/api/architect/export", {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify({payload}),
            }});
            return await r.json();
        }}''')
        fmt = result.get("format")
        content = result.get("content", "")
        passed = fmt == "yara" and "rule" in content.lower()
        detail = f"format={fmt}, has_rule={'rule' in content.lower()}"
        record("test_architect_export_api", passed, detail)
    except Exception as exc:
        record("test_architect_export_api", False, str(exc))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    if DUMP_PATH is None:
        print("SKIP: dataset unavailable. Set MEMDIVER_DATASET_ROOT to enable.")
        return 0

    print("Starting MemDiver server...")
    server = start_server()
    print(f"Server running (PID {server.pid})")

    exit_code = 0
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1920, "height": 1080})
            page = context.new_page()
            page.set_default_timeout(TIMEOUT_MS)

            print("\nRunning tests:\n")

            test_landing_page(page)
            test_format_detection_api(page)
            test_notebook_status_api(page)
            test_patterns_api(page)
            test_architect_export_api(page)

            # Take final screenshot
            page.goto(BASE_URL, timeout=TIMEOUT_MS)
            page.wait_for_load_state("networkidle", timeout=TIMEOUT_MS)
            page.screenshot(path=SCREENSHOT_PATH, full_page=True)
            print(f"\nScreenshot saved to {SCREENSHOT_PATH}")

            browser.close()

        # Summary
        total = len(results)
        passed = sum(1 for _, ok, _ in results if ok)
        failed = total - passed
        print(f"\n{'='*50}")
        print(f"Results: {passed}/{total} passed, {failed} failed")
        print(f"{'='*50}")

        if failed > 0:
            exit_code = 1

    finally:
        print("\nStopping server...")
        stop_server(server)
        print("Server stopped.")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
