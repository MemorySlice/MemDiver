import path from "node:path";
import { test, expect } from "@playwright/test";
import {
  datasetAvailable,
  syntheticMslAvailable,
  syntheticMslPath,
  MSL,
  RUN_0001,
  DATASET_DIR,
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

    // The output is a long temp path (/var/folders/.../tmpXXXX.msl) — one
    // unbreakable token. It used to overflow the success panel horizontally
    // instead of wrapping, clipping the path mid-string. Assert the panel does
    // not scroll horizontally, and that the full path stays reachable on hover.
    const successPanel = page.locator(".md-panel", { hasText: "Import successful" }).first();
    const overflow = await successPanel.evaluate(
      (el) => el.scrollWidth - el.clientWidth,
    );
    expect(overflow, "import success panel must not overflow horizontally").toBeLessThanOrEqual(1);
    await expect(outputPath).toHaveAttribute("title", /\.msl$/);

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
    // core; the dedicated "multi-GB" test below verifies that huge file opens
    // without crashing via bounded-window virtualization.)
    const mslDump = page.locator('[data-testid="dataset-dump"]').filter({ hasText: ".msl" }).first();
    await expect(mslDump).toBeVisible();

    // Opening a dump switches to file mode and mounts the hex viewer on it.
    await mslDump.click();
    const firstByte = page.locator('.hex-byte[data-offset="0"]');
    await expect(firstByte).toBeVisible({ timeout: 20_000 });
    await expect(firstByte).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 20_000 });

    guards.assertClean();
  });

  // --- Multi-GB dump opens without crashing (bounded-window virtualization). ---
  // The 2 GB gcore.core previously crashed the renderer ("Target crashed")
  // because the virtualizer rendered ~134M rows (~2.68e9 px spacer). The window
  // is now clamped to MAX_WINDOW_ROWS, and any byte stays reachable via the
  // toolbar "go to offset" box, which recenters the window.
  test("opening a multi-GB dump does not crash and stays navigable @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await enterWorkspaceWithDataset(page, RUN_0001);

    // Drill into the multi-GB gcore core specifically.
    const gcoreDump = page
      .locator('[data-testid="dataset-dump"]')
      .filter({ hasText: "gcore" })
      .first();
    await expect(gcoreDump).toBeVisible({ timeout: 30_000 });
    await gcoreDump.click();

    // The tab must survive: byte 0 renders as real hex (a crash would abort the
    // test with "Target crashed" before this resolves).
    const firstByte = page.locator('.hex-byte[data-offset="0"]');
    await expect(firstByte).toBeVisible({ timeout: 20_000 });
    await expect(firstByte).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 20_000 });

    // A file this large is windowed, so the status-bar window controls appear.
    await expect(page.getByRole("button", { name: "Next window" })).toBeVisible();

    // Jump far past the first window (100 MB, 16-aligned). The window recenters
    // and the byte at that absolute offset renders — proving the whole file is
    // reachable, not just the first window.
    const FAR_OFFSET = 100_000_000; // < 2 GB, divisible by 16 → a row start
    // Scope to the main panel: a sidebar control shares the "0x offset" placeholder.
    const gotoInput = page.getByTestId("main").getByPlaceholder("0x offset");
    await gotoInput.fill(String(FAR_OFFSET));
    await gotoInput.press("Enter");
    const farByte = page.locator(`.hex-byte[data-offset="${FAR_OFFSET}"]`);
    await expect(farByte).toBeVisible({ timeout: 20_000 });
    await expect(farByte).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 20_000 });

    guards.assertClean();
  });

  // --- Dataset overview paginates a large (100-run) dataset. ---
  // The full dataset_gocryptfs corpus has 100 runs; the overview must load a
  // page at a time (limit/offset) and accumulate the rest on demand, instead of
  // enumerating all 400+ dump files up front.
  test("dataset overview paginates a large dataset @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);

    // Capture every /runs request so we can prove the fetch is paged.
    const runReqs: string[] = [];
    page.on("request", (req) => {
      if (req.url().includes("/api/dataset/runs")) runReqs.push(req.url());
    });

    await enterWorkspaceWithDataset(page, DATASET_DIR);

    // First page returns quickly (no longer blocked on statting the whole corpus).
    await expect(page.locator('[data-testid="dataset-run"]').first()).toBeVisible({ timeout: 45_000 });

    // Pull remaining pages: the IntersectionObserver auto-loads, but click the
    // fallback button too so the test is deterministic regardless of layout.
    const loadMore = page.getByTestId("dataset-runs-load-more");
    for (let i = 0; i < 5 && (await loadMore.isVisible().catch(() => false)); i++) {
      await loadMore.click().catch(() => {});
      await page.waitForTimeout(400);
    }

    // All 100 runs accumulate, and the fetch was genuinely paged (offset 0 then 50).
    await expect(page.locator('[data-testid="dataset-run"]')).toHaveCount(100, { timeout: 45_000 });
    expect(runReqs.some((u) => /[?&]limit=50\b/.test(u) && /[?&]offset=0\b/.test(u))).toBe(true);
    expect(runReqs.some((u) => /[?&]offset=50\b/.test(u))).toBe(true);

    guards.assertClean();
  });
});
