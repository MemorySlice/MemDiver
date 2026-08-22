import { test, expect, type Page } from "@playwright/test";
import { datasetAvailable, RUN_0001, DATASET_DIR, MSL } from "../fixtures/dataset";
import {
  enterWorkspaceWithDataset,
  enterWorkspaceWithMsl,
  installErrorGuards,
} from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

// Real committed dataset fact: run_0001/gcore.core is ~2.06 GiB. Windowing math
// keys off it, so pin the size and derive offsets from it. A drift here fails
// loudly (a fixture change), which is the intended signal.
const GCORE_SIZE = 2_155_823_640;
const BYTES_PER_ROW = 16;
const MAX_WINDOW_ROWS = 500_000; // must match window-utils.ts
const WINDOW_BYTES = MAX_WINDOW_ROWS * BYTES_PER_ROW; // 8 MiB per window

/** Enter the dataset overview for run_0001 and open the dump whose filename
 *  contains `kindText`; resolve once byte 0 renders in the hex viewer. */
async function openRunDump(page: Page, kindText: string) {
  await enterWorkspaceWithDataset(page, RUN_0001);
  const dump = page
    .locator('[data-testid="dataset-dump"]')
    .filter({ hasText: kindText })
    .first();
  await expect(dump).toBeVisible({ timeout: 30_000 });
  await dump.click();
  const firstByte = page.locator('.hex-byte[data-offset="0"]').first();
  await expect(firstByte).toBeVisible({ timeout: 20_000 });
  return firstByte;
}

test.describe("huge dumps + large datasets (bounded-window + pagination)", () => {
  // ============================ Hex windowing (P0) ============================

  // Ctrl/Cmd+End must reach the very end of a 2 GB file — which lives ABOVE the
  // 2^31 boundary — by recentering the bounded window, and Ctrl/Cmd+Home back.
  test("keyboard End/Home traverse a 2 GB file end-to-end @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await openRunDump(page, "gcore");

    const viewer = page.locator('[data-tour-id="hex-viewer"]');
    await viewer.focus();

    // Ctrl/Cmd+End → maxOffset (fileSize-1). Its row start is > 2^31.
    const lastRowStart = Math.floor((GCORE_SIZE - 1) / BYTES_PER_ROW) * BYTES_PER_ROW;
    expect(lastRowStart).toBeGreaterThan(2 ** 31); // proves >2^31 coverage
    await page.keyboard.press("ControlOrMeta+End");
    await expect(
      page.locator(`.hex-byte[data-offset="${lastRowStart}"]`).first(),
    ).toBeVisible({ timeout: 20_000 });

    // Ctrl/Cmd+Home → back to offset 0 (window recenters to the start).
    await page.keyboard.press("ControlOrMeta+Home");
    await expect(page.locator('.hex-byte[data-offset="0"]').first()).toBeVisible({
      timeout: 20_000,
    });

    guards.assertClean();
  });

  // The status-bar Prev/Next-window buttons step the window by MAX_WINDOW_ROWS
  // and clamp at the ends.
  test("Prev/Next window controls page a 2 GB file @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await openRunDump(page, "gcore");

    const nextBtn = page.getByRole("button", { name: "Next window" });
    const prevBtn = page.getByRole("button", { name: "Prev window" });
    await expect(nextBtn).toBeVisible();
    await expect(prevBtn).toBeDisabled(); // at start

    // Advance one window: the top row is now at absolute offset WINDOW_BYTES.
    await nextBtn.click();
    await expect(
      page.locator(`.hex-byte[data-offset="${WINDOW_BYTES}"]`).first(),
    ).toBeVisible({ timeout: 20_000 });
    await expect(prevBtn).toBeEnabled();

    // Back to the first window.
    await prevBtn.click();
    await expect(page.locator('.hex-byte[data-offset="0"]').first()).toBeVisible({
      timeout: 20_000,
    });
    await expect(prevBtn).toBeDisabled();

    guards.assertClean();
  });

  // The toolbar "go to offset" box must reach an offset above 2^31 (and near
  // EOF, exercising the last-window clamp) by recentering the window.
  test("go-to offset above 2^31 renders bytes @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await openRunDump(page, "gcore");

    const gotoInput = page.getByTestId("main").getByPlaceholder("0x offset");

    // An offset just past 2^31 (2,147,483,648 < file size, 16-aligned).
    const OVER_2GB = 0x80000000;
    await gotoInput.fill(String(OVER_2GB));
    await gotoInput.press("Enter");
    await expect(
      page.locator(`.hex-byte[data-offset="${OVER_2GB}"]`).first(),
    ).toBeVisible({ timeout: 20_000 });

    // Last full row (last-window clamp).
    const lastRowStart = Math.floor((GCORE_SIZE - 1) / BYTES_PER_ROW) * BYTES_PER_ROW;
    await gotoInput.fill(String(lastRowStart));
    await gotoInput.press("Enter");
    await expect(
      page.locator(`.hex-byte[data-offset="${lastRowStart}"]`).first(),
    ).toBeVisible({ timeout: 20_000 });

    guards.assertClean();
  });

  // Cursor + selection state must stay correct at a high absolute offset.
  test("cursor and selection track high offsets @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await openRunDump(page, "gcore");

    const gotoInput = page.getByTestId("main").getByPlaceholder("0x offset");
    const OFF = 100_000_000; // 0x05F5E100
    await gotoInput.fill(String(OFF));
    await gotoInput.press("Enter");

    const cell = page.locator(`.hex-byte[data-offset="${OFF}"]`).first();
    await expect(cell).toBeVisible({ timeout: 20_000 });
    await cell.click();
    // The hex status bar shows the cursor offset in zero-padded hex.
    await expect(page.getByText("Offset: 0x05f5e100", { exact: true })).toBeVisible({
      timeout: 10_000,
    });

    // Shift-click the next row to extend a selection across a high offset.
    await page.locator(`.hex-byte[data-offset="${OFF + 16}"]`).first().click({
      modifiers: ["Shift"],
    });
    await expect(page.getByText(/Sel:/)).toBeVisible({ timeout: 10_000 });

    guards.assertClean();
  });

  // Switching view mode on a windowed MSL must reset the window to the start
  // (windowStartRow → 0), so Prev-window becomes disabled again.
  test("view-mode switch resets the window @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, MSL); // 210 MB → windowed

    await page.getByRole("tab", { name: "Raw file" }).click();
    await expect(page.locator('.hex-byte[data-offset="0"]').first()).toBeVisible({
      timeout: 20_000,
    });

    const prevBtn = page.getByRole("button", { name: "Prev window" });
    await expect(prevBtn).toBeVisible();
    await expect(prevBtn).toBeDisabled();

    // Scroll deep so the window leaves the start.
    const gotoInput = page.getByTestId("main").getByPlaceholder("0x offset");
    await gotoInput.fill("50000000"); // 50 MB, within raw MSL
    await gotoInput.press("Enter");
    await expect(prevBtn).toBeEnabled({ timeout: 10_000 });

    // Flip view modes; the raw window must be reset to the start.
    await page.getByRole("tab", { name: "Memory (VAS)" }).click();
    await page.getByRole("tab", { name: "Raw file" }).click();
    await expect(page.getByRole("button", { name: "Prev window" })).toBeDisabled({
      timeout: 10_000,
    });

    guards.assertClean();
  });

  // ==================== Parallel virtualizer / other kinds (P0/P1) ===========

  // The Strings panel virtualizes too; a 2 GB dump must not crash it (rows are
  // capped + paged). This is the risk-check for a parallel unbounded-row bug.
  test("Strings panel opens a 2 GB dump without crashing @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await openRunDump(page, "gcore");

    await page.locator(tab("strings")).first().click();
    // The panel mounts and streams its first page of strings (no Target crash).
    await expect(
      page.locator('[data-testid="strings-row"]').first(),
    ).toBeVisible({ timeout: 45_000 });

    guards.assertClean();
  });

  // The other real dump kinds (gdb_raw / lldb_raw, ~207 MB each) must render.
  test("gdb_raw and lldb_raw dumps render in the hex viewer @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    for (const kind of ["gdb_raw", "lldb_raw"]) {
      const guards = installErrorGuards(page);
      const firstByte = await openRunDump(page, kind);
      await expect(firstByte).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 20_000 });
      guards.assertClean();
    }
  });

  // ======================= Dataset pagination (P1) ===========================

  // A dump living on a non-first page must be openable after loading its page.
  test("opening a dump from a far pagination page works @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await enterWorkspaceWithDataset(page, DATASET_DIR); // 100 runs

    await expect(page.locator('[data-testid="dataset-run"]').first()).toBeVisible({
      timeout: 45_000,
    });

    // Pull all pages (button + auto-load sentinel).
    const loadMore = page.getByTestId("dataset-runs-load-more");
    for (let i = 0; i < 5 && (await loadMore.isVisible().catch(() => false)); i++) {
      await loadMore.click().catch(() => {});
      await page.waitForTimeout(400);
    }
    await expect(page.locator('[data-testid="dataset-run"]')).toHaveCount(100, {
      timeout: 45_000,
    });

    // Open the .msl dump of a run from page 2 (run_0060).
    const farRun = page
      .locator('[data-testid="dataset-run"]')
      .filter({ hasText: "run_0060" })
      .first();
    await expect(farRun).toBeVisible();
    await farRun.locator('[data-testid="dataset-dump"]').filter({ hasText: ".msl" }).first().click();
    await expect(page.locator('.hex-byte[data-offset="0"]').first()).toBeVisible({
      timeout: 20_000,
    });

    guards.assertClean();
  });

  // The first page of a 100-run dataset must return quickly (was ~36 s when the
  // endpoint statted + parsed every dump of every run up front).
  test("first dataset page returns well under the old ~36 s @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);

    const firstPage = page.waitForResponse(
      (r) => r.url().includes("/api/dataset/runs") && /[?&]offset=0\b/.test(r.url()),
    );
    await enterWorkspaceWithDataset(page, DATASET_DIR);
    const resp = await firstPage;
    const ms = resp.request().timing().responseEnd;
    // eslint-disable-next-line no-console
    console.log(`[timing] first /api/dataset/runs page (50 of 100): ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(25_000);
  });
});
