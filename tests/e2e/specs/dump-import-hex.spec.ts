import path from "node:path";
import { test, expect } from "@playwright/test";
import {
  datasetAvailable,
  syntheticMslAvailable,
  syntheticMslPath,
  MSL,
  RUN_0001,
} from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  enterWorkspaceWithDataset,
  installErrorGuards,
} from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

// Committed 4 KiB raw dump — small enough to upload in-test; import_dump
// sniffs it as raw and converts to .msl.
const SAMPLE_DUMP_BIN = path.resolve(__dirname, "../../fixtures/sample_dump.bin");

test.describe("dump import + hex viewer", () => {
  // --- Import flow: uploading a dump must make it usable, not a dead end. ---
  test("importing a dump via the Import tab makes it viewable in the hex viewer", async ({ page }) => {
    test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");
    const guards = installErrorGuards(page);

    // Enter the workspace via the tiny committed synthetic MSL (fast). The
    // dump STORE starts empty (the wizard renders from inputPath).
    await enterWorkspaceWithMsl(page, syntheticMslPath);

    // Import a raw dump through the Import sidebar tab (drop zone opens a
    // native file chooser on click).
    await page.locator(tab("import")).first().click();
    const [chooser] = await Promise.all([
      page.waitForEvent("filechooser"),
      page.locator("div.border-dashed").first().click(),
    ]);
    await chooser.setFiles(SAMPLE_DUMP_BIN);

    // Success panel shows the converted .msl output path.
    const outputPath = page.locator(".md-panel span.font-mono").first();
    await expect(outputPath).toBeVisible({ timeout: 30_000 });
    const base = (await outputPath.innerText()).trim().split(/[\\/]/).pop()!;
    expect(base).toMatch(/\.msl$/);

    // The imported dump must now appear in the Dumps list (the fix): before
    // the fix, upload was a dead end and nothing showed here.
    await page.locator(tab("dumps")).first().click();
    await expect(page.getByText(base, { exact: false }).first()).toBeVisible({ timeout: 10_000 });

    // …and it must load in the hex viewer. A raw-imported dump's bytes live in
    // the raw view, so select it, then assert byte 0 resolves to real hex.
    await page.getByRole("tab", { name: "Raw file" }).click();
    const firstByte = page.locator('.hex-byte[data-offset="0"]');
    await expect(firstByte).toBeVisible({ timeout: 15_000 });
    await expect(firstByte).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 15_000 });

    guards.assertClean();
  });

  // --- Hex "syntax highlighting" (search) + MSL view modes on a real MSL. ---
  // Uses the committed synthetic MSL: fast, deterministic, dataset-free.
  test("hex viewer renders bytes, search highlighting, and MSL view modes", async ({ page }) => {
    test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, syntheticMslPath);

    // Ensure the raw view (byte-addressable) and that bytes render.
    await page.getByRole("tab", { name: "Raw file" }).click();
    const firstByte = page.locator('.hex-byte[data-offset="0"]');
    await expect(firstByte).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 20_000 });
    const byteVal = (await firstByte.innerText()).trim();

    // Search for byte 0's own value → guarantees ≥1 hit that is in the initial
    // viewport, so its `highlight-search` class is assertable without scrolling.
    const find = page.getByPlaceholder("hex pattern e.g. deadbeef");
    await find.fill(byteVal);
    await find.press("Enter");
    await expect(page.getByText(/\d+\+? hits/)).toBeVisible({ timeout: 15_000 });
    await expect(firstByte).toHaveClass(/highlight-search/, { timeout: 10_000 });
    // The legend surfaces once regions are highlighted.
    await expect(page.locator(".highlight-search").first()).toBeVisible();

    // MSL view-mode tabs switch cleanly.
    await page.getByRole("tab", { name: "Memory (VAS)" }).click();
    await expect(page.getByRole("tab", { name: "Memory (VAS)" })).toHaveAttribute("aria-selected", "true");
    await page.getByRole("tab", { name: "Raw file" }).click();
    await expect(page.getByRole("tab", { name: "Raw file" })).toHaveAttribute("aria-selected", "true");

    guards.assertClean();
  });

  // --- Real dataset MSL renders in the hex viewer (deep tier). ---
  test("real dataset MSL renders bytes in the hex viewer @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, MSL);
    const firstByte = page.locator('.hex-byte[data-offset="0"]');
    await expect(firstByte).toBeVisible({ timeout: 20_000 });
    await expect(firstByte).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 20_000 });
    guards.assertClean();
  });

  // --- Dataset mode: browse runs and drill into a dump in the hex viewer. ---
  // Uses a single run dir (fast, ~0.6s to enumerate). Pointing at a full
  // 100-run dataset exercises the same code path but enumeration is slow
  // (~35s for 400+ dump stats over the gocryptfs mount).
  test("dataset overview lists runs and opening a dump loads the hex viewer @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    const guards = installErrorGuards(page);
    await enterWorkspaceWithDataset(page, RUN_0001);

    // The overview enumerates runs + their dumps (previously just a count).
    await expect(page.locator('[data-testid="dataset-run"]').first()).toBeVisible({ timeout: 30_000 });
    // Open the .msl dump specifically. (A run also contains a multi-GB gcore
    // core; opening files that large is a separate hex-viewer scaling limit,
    // out of scope for verifying the dataset drill-down itself.)
    const mslDump = page.locator('[data-testid="dataset-dump"]').filter({ hasText: ".msl" }).first();
    await expect(mslDump).toBeVisible();

    // Opening a dump switches to file mode and mounts the hex viewer on it.
    await mslDump.click();
    const firstByte = page.locator('.hex-byte[data-offset="0"]');
    await expect(firstByte).toBeVisible({ timeout: 20_000 });
    await expect(firstByte).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 20_000 });

    guards.assertClean();
  });
});
