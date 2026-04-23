/**
 * Regenerates documentation screenshots under docs/_static/screenshots/.
 *
 * Not a conformance test — a capture harness that drives the real UI
 * through each feature's workflow and writes a PNG per slug. Every
 * light-mode shot uses primeAll({theme:"light"}) before navigation so
 * ThemeProvider picks up the preference during initial render.
 *
 * Runs under the existing tests/e2e/playwright.config.ts webServer
 * (backend :8091, Vite :5191).
 */
import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { MSL, datasetAvailable } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
} from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";
import {
  VIEWPORT_DEFAULT,
  VIEWPORT_HERO,
  primeAll,
  injectStableStyles,
  takeShot,
  takeTriptychPart,
  consensusFixtureDumps,
  waitForHexBytes,
} from "./screenshots-helpers";

test.describe("README screenshots", () => {
  test.skip(!datasetAvailable, "Dataset MSL fixture not present.");
  // The default per-test timeout in playwright.config.ts is 60 s. A cold
  // entropy compute on a 215 MB MSL can exceed that by itself, and the
  // pipeline + hex-overlay workflows also include multiple network
  // round-trips. Lift the budget uniformly so repeat-each=10 doesn't
  // become a game of chasing timeouts.
  test.setTimeout(360_000);

  // -------- 01 landing --------
  test("01_landing (light, hero)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_HERO });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "verification" });
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await injectStableStyles(page);
    // Sessions or empty-state must be visible; either way the header renders.
    await expect(page.getByText(/MemDiver/)).toBeVisible();
    await page.waitForTimeout(500);
    await takeShot(page, "01_landing");
    await context.close();
  });

  // -------- 02 wizard — select data (modal open) --------
  test("02_wizard_select_data (light, default)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_DEFAULT });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "verification" });
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: /New Session/i }).first().click();
    // Wizard StepSelectData: click the "Open" button to surface FileBrowser.
    await expect(
      page.getByPlaceholder("Enter path to file or directory"),
    ).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: /^Open$/ }).click();
    // FileBrowser is a modal; wait for its visible markers.
    await expect(
      page.getByRole("button", { name: /Cancel|Select/i }).first(),
    ).toBeVisible({ timeout: 5_000 });
    await injectStableStyles(page);
    await page.waitForTimeout(600);
    await takeShot(page, "02_wizard_select_data");
    await context.close();
  });

  // -------- 03 wizard — analysis step (algo grid) --------
  test("03_wizard_analysis (light, default)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_DEFAULT });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "exploration" });
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: /New Session/i }).first().click();
    const pathInput = page.getByPlaceholder("Enter path to file or directory");
    await expect(pathInput).toBeVisible({ timeout: 15_000 });
    await pathInput.fill(MSL);
    await page.getByRole("button", { name: /^Next$/ }).click();
    // Step shows "Start Analysis" at the end — we want to capture before clicking.
    await expect(
      page.getByRole("button", { name: /Start Analysis/i }),
    ).toBeVisible({ timeout: 25_000 });
    // Ensure algorithm grid rendered (at least "Entropy Scan" label visible).
    await expect(page.getByText(/Entropy Scan/i)).toBeVisible();
    await injectStableStyles(page);
    await page.waitForTimeout(500);
    await takeShot(page, "03_wizard_analysis");
    await context.close();
  });

  // -------- 04 workspace default layout --------
  test("04_workspace_default (light, hero)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_HERO });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "exploration" });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    await page.waitForLoadState("networkidle");
    await injectStableStyles(page);
    await page.waitForTimeout(400);
    await takeShot(page, "04_workspace_default");
    await context.close();
  });

  // -------- 05 hex + structure overlay --------
  test("05_hex_with_overlay (light, default)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_DEFAULT });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "exploration" });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    // Click hex row 0 to set cursorOffset — required for Apply/Auto-detect.
    await page
      .locator('[data-index="0"]')
      .first()
      .click({ timeout: 5_000 })
      .catch(() => undefined);
    await page.waitForTimeout(300);
    // Open Structures sidebar tab.
    await page.locator(tab("structures")).first().click();
    await page.waitForTimeout(500);
    // Auto-detect applies the first matching structure at the cursor
    // offset via POST /api/structures/autodetect, then setOverlay()
    // triggers the colour highlight on the hex grid.
    const autoBtn = page
      .getByRole("button", { name: /Auto.?detect at cursor/i })
      .first();
    if (await autoBtn.isVisible().catch(() => false)) {
      await autoBtn.click({ force: true }).catch(() => undefined);
      await page.waitForTimeout(2_000);
    }
    // Reveal the Analysis bottom tab so the screenshot shows both the
    // structures sidebar AND the algorithm panel that produces overlays.
    await page.locator(tab("analysis")).first().click().catch(() => undefined);
    await page.waitForTimeout(500);
    await injectStableStyles(page);
    await takeShot(page, "05_hex_with_overlay");
    await context.close();
  });

  // -------- 06 entropy tab --------
  test("06_entropy_tab (light, default)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_DEFAULT });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "exploration" });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    await switchToExplorationMode(page);
    await page.locator(tab("entropy")).first().click();
    // Wait for the "Loading entropy data..." paragraph to DISAPPEAR —
    // that's the definitive signal that the 60–120 s cold compute
    // finished. Then one more settle tick for Plotly to paint.
    await page
      .waitForFunction(
        () => !document.body.textContent?.includes("Loading entropy data"),
        undefined,
        { timeout: 240_000 },
      )
      .catch(() => {});
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(2_000);
    await injectStableStyles(page);
    await takeShot(page, "06_entropy_tab");
    await context.close();
  });

  // -------- 07 consensus tab (Live Consensus path) --------
  test("07_consensus_tab (light, default)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_DEFAULT });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "exploration" });
    await enterWorkspaceWithMsl(page);
    await switchToExplorationMode(page);
    await page.locator(tab("live-consensus")).first().click();
    // The default consensus-size input is 1_048_576; the fixture dumps
    // we upload are only 512 bytes, so the backend rejects them with
    // "dump shorter than consensus size". Drop the size to 512 first.
    const sizeInput = page.locator('input[type="number"]').first();
    if (await sizeInput.isVisible().catch(() => false)) {
      await sizeInput.fill("512");
    }
    // EmptyState primary CTA is "Start session"
    await page
      .getByRole("button", { name: /Start session/i })
      .first()
      .click();
    await page.waitForTimeout(500);
    // Set the hidden file input to fixture dumps.
    const dumps = consensusFixtureDumps();
    if (dumps.length >= 2) {
      const fileInput = page.locator('input[type="file"]').first();
      // Upload multiple dumps at once; store.addFile iterates them.
      await fileInput.setInputFiles(dumps);
      // Wait for numDumps >= 2 and sparkline to render.
      await page
        .waitForFunction(
          () => {
            const text = document.body.textContent ?? "";
            return /\b[2-9]\d* dumps\b/.test(text) ||
              /\b[2-9]\d* dump\b/.test(text);
          },
          undefined,
          { timeout: 15_000 },
        )
        .catch(() => {});
    }
    await page.waitForTimeout(1_000);
    await injectStableStyles(page);
    await takeShot(page, "07_consensus_tab");
    await context.close();
  });

  // -------- 08 pipeline oracle stage --------
  test("08_pipeline_oracle (light, default)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_DEFAULT });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "exploration" });
    // Seed zustand-persisted pipeline store to stage="oracle" with a
    // plausible form so the UI renders the oracle wizard. The store is
    // restored during app hydration.
    await seedPipelineStore(page, {
      stage: "oracle",
      form: { oracleSha256: null, oracleId: null },
      taskId: null,
      lastSeq: 0,
    });
    await enterWorkspaceWithMsl(page);
    // Ensure the main-panel hex has rendered real bytes before we push
    // the bottom panel to Pipeline — otherwise the visible hex shows
    // `--` placeholders behind the pipeline wizard.
    await waitForHexBytes(page);
    // Click into the Pipeline bottom tab.
    await page.locator(tab("pipeline")).first().click();
    await page.waitForTimeout(1_500);
    await injectStableStyles(page);
    await takeShot(page, "08_pipeline_oracle");
    await context.close();
  });

  // -------- 09 pipeline run dashboard (seeded state) --------
  test("09_pipeline_run (light, hero)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_HERO });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "exploration" });
    await seedPipelineStore(page, {
      stage: "running",
      form: {},
      taskId: "mock-task-running",
      lastSeq: 42,
    });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    await page.locator(tab("pipeline")).first().click();
    await page.waitForTimeout(1_500);
    await injectStableStyles(page);
    await takeShot(page, "09_pipeline_run");
    await context.close();
  });

  // -------- 10 pipeline results (seeded state) --------
  test("10_pipeline_results (light, default)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_DEFAULT });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "exploration" });
    await seedPipelineStore(page, {
      stage: "results",
      form: {},
      taskId: "mock-task-succeeded",
      lastSeq: 99,
    });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    await page.locator(tab("pipeline")).first().click();
    await page.waitForTimeout(1_500);
    await injectStableStyles(page);
    await takeShot(page, "10_pipeline_results");
    await context.close();
  });

  // -------- 11 theme triptych (three parts captured; stitched in teardown) --------
  test("11_theme_triptych_light_part", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_HERO });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "exploration" });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    await page.waitForTimeout(400);
    await injectStableStyles(page);
    await takeTriptychPart(page, "light");
    await context.close();
  });

  test("11_theme_triptych_dark_part", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_HERO });
    const page = await context.newPage();
    await primeAll(page, { theme: "dark", mode: "exploration" });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    await page.waitForTimeout(400);
    await injectStableStyles(page);
    await takeTriptychPart(page, "dark");
    await context.close();
  });

  test("11_theme_triptych_darkhc_part", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_HERO });
    const page = await context.newPage();
    await primeAll(page, {
      theme: "dark",
      highContrast: true,
      mode: "exploration",
    });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    await page.waitForTimeout(400);
    await injectStableStyles(page);
    await takeTriptychPart(page, "dark_hc");
    await context.close();
  });

  // -------- 12 workspace loaded (dark, by design) --------
  test("12_workspace_loaded_dark (dark, hero)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_HERO });
    const page = await context.newPage();
    await primeAll(page, { theme: "dark", mode: "verification" });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    await page.waitForTimeout(400);
    await injectStableStyles(page);
    await takeShot(page, "12_workspace_loaded_dark");
    await context.close();
  });

  // -------- 13 workspace loaded (light) --------
  test("13_workspace_loaded_light (light, hero)", async ({ browser }) => {
    const context = await browser.newContext({ viewport: VIEWPORT_HERO });
    const page = await context.newPage();
    await primeAll(page, { theme: "light", mode: "verification" });
    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);
    await page.waitForTimeout(400);
    await injectStableStyles(page);
    await takeShot(page, "13_workspace_loaded_light");
    await context.close();
  });
});

/**
 * Seed the zustand-persist key for usePipelineStore so the app
 * hydrates straight into the desired stage.
 * Persist key: "memdiver-pipeline" (see stores/pipeline-store.ts:472)
 * Persisted fields (partialize): stage, form, taskId, lastSeq.
 */
async function seedPipelineStore(
  page: Page,
  state: {
    stage: string;
    form: Record<string, unknown>;
    taskId: string | null;
    lastSeq: number;
  },
): Promise<void> {
  const payload = JSON.stringify({ state, version: 1 });
  await page.addInitScript(
    ({ key, value }) => {
      try {
        localStorage.setItem(key, value);
      } catch {
        /* ignore */
      }
    },
    { key: "memdiver-pipeline", value: payload },
  );
}
