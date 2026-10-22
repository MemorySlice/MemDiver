/**
 * Entropy tab on a dump with KNOWN key material.
 *
 * A 12 MiB heap-like raw dump (fixtures/entropy_planted.ts) holds one 32-byte
 * and one 64-byte random key in otherwise low-entropy filler. For both chart
 * backends the Entropy tab must:
 *   - end at full resolution (the dump is above the 8 MiB auto limit, so the
 *     first response is sampled and the progressive follow-up replaces it),
 *   - peak at or above the window-aware threshold (4.5 at window 32),
 *   - report exactly one region per planted key (no false positive on filler),
 *   - (SVG) draw each region marker where its key lies.
 * The full-resolution API response is checked directly too: every key lies
 * inside one region's [start, byte_end).
 */
import { test, expect, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { tab } from "../fixtures/selectors";
import { enterWorkspaceWithMsl, switchToExplorationMode } from "../fixtures/workspace";
import { generatePlantedHeapDump, type PlantedDump } from "../fixtures/entropy_planted";
import { primeAll, primeChartBackend } from "./screenshots-helpers";

const DEFAULT_THRESHOLD = 4.5;
const SCREENSHOT_DIR =
  process.env.ENTROPY_SCREENSHOT_DIR ?? path.resolve(__dirname, "../test-results/entropy-planted");

interface EntropyRegion {
  start: number;
  end: number;
  byte_end: number;
}

interface FullEntropyResponse {
  resolution: string;
  threshold: number;
  max_entropy: number;
  region_count: number;
  regions_truncated: boolean;
  high_entropy_regions: EntropyRegion[];
}

let dump: PlantedDump;

test.beforeAll(() => {
  dump = generatePlantedHeapDump();
  mkdirSync(SCREENSHOT_DIR, { recursive: true });
});

/** Open the dump, show the Entropy tab and wait for the full-resolution chart. */
async function openEntropyTab(page: Page): Promise<void> {
  await enterWorkspaceWithMsl(page, dump.path);
  await switchToExplorationMode(page);
  const full = page.waitForResponse(
    (res) => res.url().includes("/api/inspect/entropy") && res.url().includes("resolution=full"),
    { timeout: 120_000 },
  );
  await page.locator(tab("entropy")).first().click();
  expect((await full).status(), "GET /api/inspect/entropy?resolution=full").toBe(200);
  await expect(page.getByTestId("entropy-resolution")).toHaveAttribute("data-resolution", "full", {
    timeout: 30_000,
  });
  await expect(page.getByTestId("entropy-refining")).toBeHidden();
  await expect(page.getByTestId("entropy-refine-failed")).toHaveCount(0);
}

async function numericAttr(page: Page, testId: string, name: string): Promise<number> {
  const raw = await page.getByTestId(testId).first().getAttribute(name);
  expect(raw, `${testId}[${name}]`).not.toBeNull();
  return Number(raw);
}

async function assertChartSummary(page: Page): Promise<void> {
  const chart = page.getByTestId("entropy-chart");
  await expect(chart).toBeVisible();
  const threshold = await numericAttr(page, "entropy-chart", "data-threshold");
  expect(threshold).toBeCloseTo(DEFAULT_THRESHOLD, 6);
  expect(await numericAttr(page, "entropy-chart", "data-max-entropy-peak")).toBeGreaterThanOrEqual(threshold);
  expect(await numericAttr(page, "entropy-chart", "data-envelope-buckets")).toBeGreaterThan(0);
  expect(await numericAttr(page, "entropy-chart", "data-region-count")).toBe(dump.keys.length);
  const caption = page.getByTestId("entropy-region-count");
  await expect(caption).toHaveAttribute("data-region-total", String(dump.keys.length));
  await expect(caption).toHaveAttribute("data-regions-truncated", "false");
  await expect(page.getByTestId("entropy-threshold-warning")).toHaveCount(0);
}

/** Every planted key lies in exactly one region of the full-resolution response. */
async function assertApiRegionsCoverKeys(page: Page): Promise<void> {
  const res = await page.request.get(
    `/api/inspect/entropy?dump_path=${encodeURIComponent(dump.path)}&resolution=full&buckets=1500`,
    { timeout: 120_000 },
  );
  expect(res.ok()).toBe(true);
  const body = (await res.json()) as FullEntropyResponse;
  expect(body.resolution).toBe("full");
  expect(body.threshold).toBeCloseTo(DEFAULT_THRESHOLD, 6);
  expect(body.max_entropy).toBeGreaterThanOrEqual(DEFAULT_THRESHOLD);
  expect(body.regions_truncated).toBe(false);
  expect(body.region_count).toBe(dump.keys.length);
  for (const key of dump.keys) {
    const hits = body.high_entropy_regions.filter(
      (r) => r.start <= key.offset && key.offset < r.byte_end,
    );
    expect(hits, `region covering key @${key.offset}`).toHaveLength(1);
  }
}

/** SVG: one marker per key, in order, near the key's fraction of the x axis. */
async function assertSvgMarkersAtKeys(page: Page): Promise<void> {
  const markers = page.getByTestId("entropy-region");
  await expect(markers).toHaveCount(dump.keys.length);
  const svgBox = await page.locator('[data-testid="entropy-chart"] svg').first().boundingBox();
  expect(svgBox).not.toBeNull();
  const centres: number[] = [];
  for (let i = 0; i < dump.keys.length; i++) {
    const box = await markers.nth(i).boundingBox();
    expect(box, `entropy-region #${i} box`).not.toBeNull();
    centres.push((box!.x + box!.width / 2 - svgBox!.x) / svgBox!.width);
  }
  centres.sort((a, b) => a - b);
  dump.keys.forEach((key, i) => {
    // Margins make the plot narrower than the svg, hence the loose tolerance.
    expect(Math.abs(centres[i] - key.offset / dump.size), `marker #${i} position`).toBeLessThan(0.1);
  });
}

async function screenshotEntropy(page: Page, backend: string): Promise<void> {
  await page.screenshot({ path: path.join(SCREENSHOT_DIR, `entropy_${backend}_planted_key_workspace.png`) });
  await page
    .getByTestId("entropy-chart")
    .screenshot({ path: path.join(SCREENSHOT_DIR, `entropy_${backend}_planted_key.png`) });
}

for (const backend of ["svg", "plotly"] as const) {
  test.describe(`Entropy tab finds planted keys (${backend})`, () => {
    test.setTimeout(240_000);

    test("full resolution, one region per key, no filler false positives", async ({ page }) => {
      await primeChartBackend(page, backend);
      await primeAll(page, { theme: "light", mode: "exploration" });
      // Tall enough that the bottom panel shows the whole chart (x axis included)
      // without scrolling, so the screenshots are complete.
      await page.setViewportSize({ width: 1600, height: 1200 });
      await openEntropyTab(page);

      await expect(page.getByTestId("entropy-chart")).toHaveAttribute("data-chart-backend", backend);
      if (backend === "plotly") await expect(page.locator(".js-plotly-plot").first()).toBeVisible();
      await assertChartSummary(page);
      await assertApiRegionsCoverKeys(page);
      if (backend === "svg") {
        await expect(page.getByTestId("entropy-envelope-band")).toBeVisible();
        // A horizontal <line> has a zero-height box, which Playwright calls
        // "hidden"; assert it is drawn at the threshold inside the plot instead.
        const thresholdLine = page.getByTestId("entropy-threshold-line");
        await expect(thresholdLine).toHaveAttribute("data-threshold", String(DEFAULT_THRESHOLD));
        expect(Number(await thresholdLine.getAttribute("y1"))).toBeGreaterThan(0);
        await assertSvgMarkersAtKeys(page);
      }
      await screenshotEntropy(page, backend);
    });
  });
}
