import os from "node:os";
import path from "node:path";
import { test, expect, type APIRequestContext, type Page } from "@playwright/test";
import { disableFtueViaStorage, dismissFtueIfPresent } from "../fixtures/workspace";

/**
 * Favourite directories in the wizard's file browser.
 *
 * The browse dialog opens on ``$HOME`` every time, so a user working out of one
 * directory walked the tree back to it on every visit. Favourites existed
 * before this spec did — as ``localStorage`` behind an unlabelled ``☆``, in a
 * list that stayed hidden until you had already used it, which is why a user
 * reported the feature as missing. Two things are proved here:
 *
 *   1. The section is on screen BEFORE anything is saved. That is the whole
 *      discoverability fix; a green tick on "clicking ☆ works" would have been
 *      just as green while nobody could find the ☆.
 *   2. The list is SERVER state. Proved by wiping the browser's own storage
 *      and reloading — a ``localStorage`` implementation passes every other
 *      assertion in this file and fails that one.
 *
 * Housekeeping: the e2e backend has its own ``XDG_DATA_HOME``
 * (``tests/e2e/.memdiver-home``, see playwright.config.ts), so this writes
 * nowhere near the developer's real ``~/.memdiver``. It is still shared with
 * every later run, so the hooks below leave the prefs file as they found it.
 */

const BACKEND_PORT = process.env.BACKEND_PORT ?? "8091";
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;

/**
 * The directory this spec saves.
 *
 * The e2e fixtures tree: it is committed, it always exists, and it is not
 * somewhere any other spec cares about the browser landing in.
 */
const TARGET_DIR = path.resolve(__dirname, "..", "fixtures");
const TARGET_NAME = path.basename(TARGET_DIR);

interface Favourite {
  path: string;
  label: string;
  added_at: number;
}

async function favourites(request: APIRequestContext): Promise<Favourite[]> {
  const res = await request.get(`${BACKEND_URL}/api/settings/favourites`);
  expect(res.status(), "GET /api/settings/favourites").toBe(200);
  return ((await res.json()) as { favourites: Favourite[] }).favourites;
}

/** Landing -> wizard -> the Browse dialog, from a cold page load. */
async function openFileBrowser(page: Page): Promise<void> {
  await disableFtueViaStorage(page);
  await page.goto("/");
  await dismissFtueIfPresent(page);
  await page.getByRole("button", { name: /New Session/i }).first().click();
  await expect(page.getByPlaceholder("Enter path to file or directory")).toBeVisible({
    timeout: 15_000,
  });
  await page.getByRole("button", { name: /^Open$/ }).click();
  await expect(page.getByTestId("file-browser")).toBeVisible({ timeout: 10_000 });
}

/**
 * Browse to `dir` and wait for the SERVER to confirm it landed there.
 *
 * The path bar renders `editPath ?? currentPath`, so while it is being edited
 * its value is the text just typed — identical whether the browse succeeded,
 * failed, or is still in flight. Asserting that value proves nothing; the
 * response for this directory does.
 */
async function browseTo(page: Page, dir: string): Promise<void> {
  const pathBar = page.getByTestId("file-browser-path");
  await pathBar.click();
  await pathBar.fill(dir);
  const browsed = page.waitForResponse(async (resp) => {
    if (!new URL(resp.url()).pathname.endsWith("/api/path/browse")) return false;
    if (!resp.ok()) return false;
    const body = (await resp.json().catch(() => null)) as { current?: string } | null;
    return body?.current === dir;
  });
  await pathBar.press("Enter");
  await browsed;
  await expect(pathBar).toHaveValue(dir);
}

test.describe("file browser favourites", () => {
  /**
   * Every test starts from "not saved".
   *
   * The prefs file is real and shared with every later run of this suite, so
   * without this the second test to run would inherit the first one's
   * favourite — which is exactly how the remove test first failed, clicking a
   * toggle it believed would ADD and watching the row vanish underneath it.
   */
  test.beforeEach(async ({ request }) => {
    await request.delete(`${BACKEND_URL}/api/settings/favourites`, {
      params: { path: TARGET_DIR },
    });
  });

  test.afterAll(async ({ request }) => {
    await request.delete(`${BACKEND_URL}/api/settings/favourites`, {
      params: { path: TARGET_DIR },
    });
    // No DELETE for last-dir by design (it is a single value, never absent
    // once set), so hand it back to $HOME — where the browser opened before
    // this spec ran.
    await request.put(`${BACKEND_URL}/api/settings/last-dir`, {
      data: { path: os.homedir() },
    });
  });

  test("offers favourites before any exist, and survives a wiped browser store", async ({
    page,
    request,
  }) => {
    test.setTimeout(90_000);

    await openFileBrowser(page);

    // (1) Discoverability: the section and its invitation are on screen with
    // nothing saved yet.
    await expect(page.getByTestId("file-browser-favourites")).toBeVisible();
    await expect(page.getByTestId("file-browser-favourites-empty")).toContainText(
      /No favourites yet/i,
    );
    const toggle = page.getByTestId("file-browser-favourite-toggle");
    await expect(toggle).toContainText("Favourite");
    await expect(toggle).toHaveAttribute("aria-pressed", "false");

    // (2) Save the directory the dialog is standing in.
    await browseTo(page, TARGET_DIR);
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("file-browser-favourite")).toContainText(TARGET_NAME);

    // (3) It reached the server, not just the screen.
    expect(
      (await favourites(request)).map((f) => f.path),
      "the favourite is in the server's prefs file",
    ).toContain(TARGET_DIR);

    // (4) THE claim. Wipe everything this browser stores and reload: a
    // localStorage implementation loses the list right here.
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await page.reload();
    await dismissFtueIfPresent(page);

    await openFileBrowser(page);
    await expect(page.getByTestId("file-browser-favourite")).toContainText(TARGET_NAME);
    await expect(page.getByTestId("file-browser-favourites-empty")).toHaveCount(0);

    // (5) And it is usable, not just visible: one click goes there.
    await browseTo(page, os.homedir());
    await page.getByTestId("file-browser-favourite-open").click();
    await expect(page.getByTestId("file-browser-path")).toHaveValue(TARGET_DIR);
  });

  test("reopens on the directory last selected", async ({ page }) => {
    test.setTimeout(90_000);

    await openFileBrowser(page);
    await browseTo(page, TARGET_DIR);

    // Selecting is what "I was working here" means — the dialog does not
    // remember every directory merely glanced at on the way.
    await page.getByRole("button", { name: "Select This Directory" }).click();
    await expect(page.getByTestId("file-browser")).toBeHidden();

    await page.reload();
    await dismissFtueIfPresent(page);
    await openFileBrowser(page);

    await expect(page.getByTestId("file-browser-path")).toHaveValue(TARGET_DIR);
  });

  test("removes a favourite", async ({ page, request }) => {
    test.setTimeout(90_000);

    await openFileBrowser(page);
    await browseTo(page, TARGET_DIR);
    await page.getByTestId("file-browser-favourite-toggle").click();
    await expect(page.getByTestId("file-browser-favourite")).toHaveCount(1);

    await page.getByTestId("file-browser-favourite-remove").click();

    await expect(page.getByTestId("file-browser-favourites-empty")).toBeVisible();
    expect((await favourites(request)).map((f) => f.path)).not.toContain(TARGET_DIR);
  });
});
