/**
 * Dual-renderer chart backend spec.
 *
 * Proves both the Plotly and SVG backends render correctly for the two
 * charts that have live call sites:
 *   - EntropyChart (Workspace → Exploration mode → Entropy tab)
 *   - SurvivorCurve (Pipeline tab → Results view, fixture-seeded)
 *
 * VarianceMap and VasChart have no UI call sites at the moment — their
 * dispatchers + impls exist and are ready to wire in — so there is no
 * meaningful end-to-end path to screenshot them under either backend.
 * (The chunks are tree-shaken out of the bundle until a caller imports
 * them; that's the expected state per the plan.)
 *
 * The test relies on:
 *   - localStorage seed of the zustand-persist key `memdiver-settings`
 *     to control `display.chartBackend` before the app hydrates.
 *   - The selector `.js-plotly-plot` for the Plotly renderer's root
 *     <div>, and `[data-chart-backend="svg"]` on the SVG chart roots.
 */
import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
} from "../fixtures/workspace";
import {
  primeAll,
  primeChartBackend,
  loadPipelineFixture,
  routePipelineToFixture,
  injectPipelineEvents,
} from "./screenshots-helpers";

test.describe("Chart backend dispatch", () => {
  test.skip(!datasetAvailable, "Dataset MSL fixture not present.");
  // Entropy compute can be 60-120s cold; pipeline fixtures need the
  // backend's hex viewer + workspace mount flow. Budget generously.
  test.setTimeout(360_000);

  test.describe("EntropyChart", () => {
    test("renders via Plotly backend", async ({ browser }) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      await primeChartBackend(page, "plotly");
      await primeAll(page, { theme: "light", mode: "exploration" });
      await enterWorkspaceWithMsl(page);
      await switchToExplorationMode(page);
      await page.locator(tab("entropy")).first().click();
      // Wait for entropy data to settle; then assert Plotly actually rendered.
      await page
        .waitForFunction(
          () => {
            const t = document.body.textContent ?? "";
            if (t.includes("Loading entropy data")) return false;
            return (
              t.includes("Entropy Profile") ||
              t.includes("Entropy chart failed to render.")
            );
          },
          undefined,
          { timeout: 240_000 },
        )
        .catch(() => {});
      await expect(page.locator(".js-plotly-plot").first()).toBeVisible({
        timeout: 15_000,
      });
      // Negative assertion: no SVG-backend marker on any chart.
      expect(
        await page.locator('[data-chart-backend="svg"]').count(),
      ).toBe(0);
      await context.close();
    });

    test("renders via SVG backend", async ({ browser }) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      await primeChartBackend(page, "svg");
      await primeAll(page, { theme: "light", mode: "exploration" });
      await enterWorkspaceWithMsl(page);
      await switchToExplorationMode(page);
      await page.locator(tab("entropy")).first().click();
      await page
        .waitForFunction(
          () =>
            !(document.body.textContent ?? "").includes("Loading entropy data"),
          undefined,
          { timeout: 240_000 },
        )
        .catch(() => {});
      // SVG marker must be present.
      await expect(
        page.locator('[data-chart-backend="svg"]').first(),
      ).toBeVisible({ timeout: 15_000 });
      // And no Plotly root.
      expect(await page.locator(".js-plotly-plot").count()).toBe(0);
      await context.close();
    });
  });

  test.describe("SurvivorCurve", () => {
    test("renders via Plotly backend (fixture-seeded)", async ({ browser }) => {
      const fixture = loadPipelineFixture();
      test.skip(!fixture, "Pipeline fixture not precomputed.");

      const context = await browser.newContext();
      const page = await context.newPage();
      await primeChartBackend(page, "plotly");
      await primeAll(page, { theme: "light", mode: "exploration" });

      const taskId = String(fixture!.record.task_id ?? "fixture-gocryptfs");
      await routePipelineToFixture(page, taskId, fixture!);

      // Seed pipeline store to results stage.
      await page.addInitScript(
        ({ key, state }) => {
          try {
            localStorage.setItem(key, JSON.stringify({ state, version: 1 }));
          } catch {
            /* ignore */
          }
        },
        {
          key: "memdiver-pipeline",
          state: {
            stage: "results",
            form: {},
            taskId,
            lastSeq: 0,
          },
        },
      );

      await enterWorkspaceWithMsl(page);
      await page.locator(tab("pipeline")).first().click();
      await injectPipelineEvents(page, fixture!.events);
      // Plotly chart root must be present.
      await expect(page.locator(".js-plotly-plot").first()).toBeVisible({
        timeout: 15_000,
      });
      expect(
        await page.locator('[data-chart-backend="svg"]').count(),
      ).toBe(0);
      await context.close();
    });

    test("renders via SVG backend (fixture-seeded)", async ({ browser }) => {
      const fixture = loadPipelineFixture();
      test.skip(!fixture, "Pipeline fixture not precomputed.");

      const context = await browser.newContext();
      const page = await context.newPage();
      await primeChartBackend(page, "svg");
      await primeAll(page, { theme: "light", mode: "exploration" });

      const taskId = String(fixture!.record.task_id ?? "fixture-gocryptfs");
      await routePipelineToFixture(page, taskId, fixture!);

      await page.addInitScript(
        ({ key, state }) => {
          try {
            localStorage.setItem(key, JSON.stringify({ state, version: 1 }));
          } catch {
            /* ignore */
          }
        },
        {
          key: "memdiver-pipeline",
          state: {
            stage: "results",
            form: {},
            taskId,
            lastSeq: 0,
          },
        },
      );

      await enterWorkspaceWithMsl(page);
      await page.locator(tab("pipeline")).first().click();
      await injectPipelineEvents(page, fixture!.events);
      // SVG SurvivorCurve root must render.
      await expect(
        page.locator('[data-chart-backend="svg"]').first(),
      ).toBeVisible({ timeout: 15_000 });
      expect(await page.locator(".js-plotly-plot").count()).toBe(0);
      await context.close();
    });
  });
});
