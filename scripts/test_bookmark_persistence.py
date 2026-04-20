#!/usr/bin/env python3
"""End-to-end Playwright regression test for bookmark autosave persistence.

Locks the Gap D fix from current_gabs.md into place: bookmarks added to
the hex store must persist in localStorage keyed by dump path and survive
a full page reload without any explicit session save.

Drives the hex store directly via its public actions — we do not need a
real dump file on disk because the persistence contract lives entirely
in the Zustand store + localStorage.

Modeled after scripts/test_workspace_shortcuts.py. Run via the
webapp-testing skill's with_server.py helper while the FastAPI backend +
Vite dev server are up.
"""
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

SCREENSHOTS = Path("/tmp/bookmark_persistence_screenshots")
SCREENSHOTS.mkdir(exist_ok=True)

URL = "http://localhost:5173"
DUMP_PATH = "/tmp/gap-d-fixture.dump"


def _force_workspace_no_tours(page):
    """Land on the workspace with FTUE tours pre-marked seen so they
    don't intercept keystrokes or overlay the UI. Mirrors
    scripts/test_workspace_shortcuts._force_workspace_no_tours."""
    page.goto(URL)
    page.wait_for_load_state("networkidle")
    page.evaluate(
        """() => {
          try { localStorage.clear(); } catch(e){}
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
    time.sleep(0.3)


def _set_dump_path(page, path: str):
    page.evaluate(
        """async (path) => {
          const m = await import('/src/stores/hex-store.ts');
          m.useHexStore.getState().setDumpPath(path, 4096, 'raw');
        }""",
        path,
    )
    time.sleep(0.1)


def _add_bookmark(page, offset: int, label: str):
    page.evaluate(
        """async ({ offset, label }) => {
          const m = await import('/src/stores/hex-store.ts');
          m.useHexStore.getState().addBookmark({ offset, length: 1, label });
        }""",
        {"offset": offset, "label": label},
    )
    time.sleep(0.05)


def _remove_bookmark(page, offset: int):
    page.evaluate(
        """async (offset) => {
          const m = await import('/src/stores/hex-store.ts');
          m.useHexStore.getState().removeBookmark(offset);
        }""",
        offset,
    )
    time.sleep(0.05)


def _read_bookmarks(page):
    return page.evaluate(
        """async () => {
          const m = await import('/src/stores/hex-store.ts');
          return m.useHexStore.getState().bookmarks;
        }"""
    )


def _read_ls_key(page, key: str):
    return page.evaluate(
        "(k) => localStorage.getItem(k)",
        key,
    )


def t1_add_bookmark_writes_localstorage(page):
    _force_workspace_no_tours(page)
    _set_dump_path(page, DUMP_PATH)
    _add_bookmark(page, 0x100, "alpha")
    _add_bookmark(page, 0x200, "beta")
    ls = _read_ls_key(page, f"memdiver:hex:bookmarks:{DUMP_PATH}")
    assert ls is not None, "addBookmark should write a localStorage entry"
    import json
    parsed = json.loads(ls)
    assert len(parsed) == 2, f"expected 2 persisted bookmarks, got {len(parsed)}"
    offsets = {b["offset"] for b in parsed}
    assert offsets == {0x100, 0x200}, f"persisted offsets mismatch: {offsets}"
    labels = {b["label"] for b in parsed}
    assert labels == {"alpha", "beta"}, f"persisted labels mismatch: {labels}"
    page.screenshot(path=str(SCREENSHOTS / "01_persisted.png"))


def t2_reload_restores_bookmarks(page):
    _force_workspace_no_tours(page)
    _set_dump_path(page, DUMP_PATH)
    _add_bookmark(page, 0x300, "gamma")
    _add_bookmark(page, 0x400, "delta")

    # Reload — fully drops the in-memory Zustand state.
    page.reload()
    page.wait_for_load_state("networkidle")

    # Confirm in-memory bookmarks are empty before re-opening the dump.
    pre = page.evaluate(
        """async () => {
          const m = await import('/src/stores/hex-store.ts');
          return m.useHexStore.getState().bookmarks;
        }"""
    )
    assert pre == [], f"fresh reload should start with empty bookmarks, got {pre}"

    # Re-open the same dump — setDumpPath should hydrate from localStorage.
    _set_dump_path(page, DUMP_PATH)
    bookmarks = _read_bookmarks(page)
    assert len(bookmarks) == 2, (
        f"expected 2 bookmarks restored after reload, got {len(bookmarks)}: {bookmarks}"
    )
    offsets = {b["offset"] for b in bookmarks}
    assert offsets == {0x300, 0x400}, f"restored offsets mismatch: {offsets}"
    labels = {b["label"] for b in bookmarks}
    assert labels == {"gamma", "delta"}, f"restored labels mismatch: {labels}"
    page.screenshot(path=str(SCREENSHOTS / "02_restored.png"))


def t3_remove_bookmark_updates_localstorage(page):
    _force_workspace_no_tours(page)
    _set_dump_path(page, DUMP_PATH)
    _add_bookmark(page, 0x500, "epsilon")
    _add_bookmark(page, 0x600, "zeta")
    _remove_bookmark(page, 0x500)

    ls = _read_ls_key(page, f"memdiver:hex:bookmarks:{DUMP_PATH}")
    assert ls is not None, "removeBookmark must not wipe the localStorage entry"
    import json
    parsed = json.loads(ls)
    assert len(parsed) == 1, f"expected 1 persisted bookmark after remove, got {len(parsed)}"
    assert parsed[0]["offset"] == 0x600
    assert parsed[0]["label"] == "zeta"
    page.screenshot(path=str(SCREENSHOTS / "03_removed.png"))


def t4_distinct_dump_paths_isolated(page):
    _force_workspace_no_tours(page)
    path_a = "/tmp/gap-d-a.dump"
    path_b = "/tmp/gap-d-b.dump"
    _set_dump_path(page, path_a)
    _add_bookmark(page, 0x10, "a-only")
    _set_dump_path(page, path_b)
    bookmarks_b = _read_bookmarks(page)
    assert bookmarks_b == [], f"loading path_b should NOT carry path_a bookmarks, got {bookmarks_b}"
    _add_bookmark(page, 0x20, "b-only")

    # Flip back to path_a — should see alpha only.
    _set_dump_path(page, path_a)
    bookmarks_a = _read_bookmarks(page)
    assert len(bookmarks_a) == 1 and bookmarks_a[0]["label"] == "a-only", (
        f"path_a should have only its own bookmark, got {bookmarks_a}"
    )
    page.screenshot(path=str(SCREENSHOTS / "04_isolated.png"))


TESTS = [
    ("T1_add_writes_localstorage",  t1_add_bookmark_writes_localstorage),
    ("T2_reload_restores",          t2_reload_restores_bookmarks),
    ("T3_remove_updates",           t3_remove_bookmark_updates_localstorage),
    ("T4_paths_isolated",           t4_distinct_dump_paths_isolated),
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
