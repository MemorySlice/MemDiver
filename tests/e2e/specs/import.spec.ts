import path from "node:path";
import { existsSync } from "node:fs";
import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import {
  HEAP_STACK_MSL_UUID,
  datasetAvailable,
  heapStackMslAvailable,
  heapStackMslPath,
  syntheticMslAvailable,
  syntheticMslPath,
} from "../fixtures/dataset";
import {
  disableFtueViaStorage,
  dismissFtueIfPresent,
  enterWorkspaceWithMsl,
  switchToExplorationMode,
} from "../fixtures/workspace";
import { primeChartBackend } from "./screenshots-helpers";

test.describe("Import side tab mounts", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset not present.");
  test("mounts without errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));
    page.on("response", (res) => {
      if (res.status() >= 500) errors.push(`${res.status()} ${res.url()}`);
    });
    await enterWorkspaceWithMsl(page);
    await page.locator(tab("import")).first().click();
    await expect(page.locator(tab("import")).first()).toBeVisible();
    await page.waitForTimeout(800);
    expect(errors).toEqual([]);
  });
});

/**
 * The wizard's Regions step, driven against the committed synthetic `.msl`
 * (no private dataset needed). Covers the defaults, a live toggle, and the
 * `.msl`-only materialize opt-in with its trade-off text.
 */
test.describe("Wizard Regions step", () => {
  test.skip(!syntheticMslAvailable, "Synthetic MSL fixture missing.");

  test("shows defaults, toggles stack, offers materialize for .msl", async ({ page }, testInfo) => {
    await disableFtueViaStorage(page);
    await page.goto("/");
    await dismissFtueIfPresent(page);
    await page.getByRole("button", { name: /New Session/i }).first().click();

    const pathInput = page.getByPlaceholder("Enter path to file or directory");
    await expect(pathInput).toBeVisible({ timeout: 15_000 });
    await pathInput.fill(syntheticMslPath);
    await page.getByRole("button", { name: /^Next$/ }).click();

    const step = page.getByTestId("region-select-step");
    await expect(step).toBeVisible({ timeout: 20_000 });
    // The preview landed: the live summary is rendered from its totals.
    await expect(page.getByTestId("region-summary")).toBeVisible({ timeout: 15_000 });

    for (const c of ["heap", "stack", "unclassified"]) {
      await expect(page.getByTestId(`region-category-${c}`)).toBeChecked();
    }
    for (const c of ["image_code", "image_data", "mapped_file", "shared"]) {
      await expect(page.getByTestId(`region-category-${c}`)).not.toBeChecked();
    }

    await page.getByTestId("region-category-stack").uncheck();
    await expect(page.getByTestId("region-category-stack")).not.toBeChecked();
    // Keyboard works too: Space re-ticks the focused checkbox.
    await page.getByTestId("region-category-stack").focus();
    await page.keyboard.press("Space");
    await expect(page.getByTestId("region-category-stack")).toBeChecked();
    await page.getByTestId("region-category-stack").uncheck();
    await expect(page.getByTestId("region-summary")).toBeVisible();

    const materialize = page.getByTestId("region-materialize");
    await expect(materialize).toBeVisible();
    await expect(materialize).not.toBeChecked();
    await expect(page.getByText(/integrity hash or byte identity/)).toBeVisible();
    await expect(page.getByTestId("region-image-data-info")).toBeVisible();

    await page.screenshot({ path: testInfo.outputPath("wizard-regions-step.png"), fullPage: true });

    // Non-destructive default: Next -> Analysis -> workspace, no import.
    await page.getByRole("button", { name: /^Next$/ }).click();
    await page.getByRole("button", { name: /^Inspect Only/i }).first().click();
    await page.getByRole("button", { name: /^Open Workspace$/i }).click();
    await expect(page.locator('[data-testid="tab-bookmarks"]')).toBeVisible({ timeout: 20_000 });
  });
});

// Committed raw dump + a memory map named unlike it (so it is NOT auto-detected
// as a sidecar). Regenerate with: python tests/e2e/fixtures/raw_maps/generate.py
const RAW_MAPS_DIR = path.resolve(__dirname, "../fixtures/raw_maps");
const RAW_DUMP = path.join(RAW_MAPS_DIR, "sample.bin");
const RAW_DUMP_MAPS = path.join(RAW_MAPS_DIR, "process_layout.maps");
const rawMapsAvailable = existsSync(RAW_DUMP) && existsSync(RAW_DUMP_MAPS);

/**
 * A raw dump without an auto-detected sidecar previews as `layout: "none"`
 * (categories disabled). Pointing the Regions step at its memory map re-runs
 * the preview as `layout: "maps"`: real categories, enabled checkboxes, and
 * the chosen map named with a "change" link.
 */
test.describe("Wizard Regions step: memory map for a raw dump", () => {
  test.skip(!rawMapsAvailable, "Raw dump + maps fixture missing.");

  test("applying a .maps file switches the layout from none to maps", async ({ page }) => {
    await disableFtueViaStorage(page);
    await page.goto("/");
    await dismissFtueIfPresent(page);
    await page.getByRole("button", { name: /New Session/i }).first().click();

    const pathInput = page.getByPlaceholder("Enter path to file or directory");
    await expect(pathInput).toBeVisible({ timeout: 15_000 });
    await pathInput.fill(RAW_DUMP);
    await page.getByRole("button", { name: /^Next$/ }).click();

    await expect(page.getByTestId("region-select-step")).toBeVisible({ timeout: 20_000 });
    await expect(page.getByTestId("region-no-layout-info")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("region-category-heap")).toBeDisabled();
    await expect(page.getByTestId("region-maps-apply")).toBeDisabled();

    await page.getByTestId("region-maps-input").fill(RAW_DUMP_MAPS);
    const previewed = page.waitForRequest((req) =>
      req.url().endsWith("/api/dumps/preview") && req.postDataJSON()?.maps_path === RAW_DUMP_MAPS);
    await page.getByTestId("region-maps-apply").click();
    await previewed;

    await expect(page.getByTestId("region-maps-active")).toContainText("process_layout.maps", { timeout: 15_000 });
    await expect(page.getByTestId("region-no-layout-info")).toBeHidden();
    await expect(page.getByTestId("region-category-heap")).toBeEnabled();
    await expect(page.getByTestId("region-category-image_code")).toBeEnabled();
    await expect(page.getByTestId("region-all")).toBeEnabled();
    await expect(page.getByTestId("region-summary")).toContainText(/excluding 1 region/);
    await expect(page.getByTestId("region-maps-change")).toBeVisible();
  });
});

/**
 * Materialize ON for a `.msl` with stack deselected: the wizard writes a
 * filtered copy (stack dropped), the workspace opens on it, and
 *   - the copy keeps the original dump UUID,
 *   - its import provenance (REST + the Format tab section) says
 *     "materialized" with the excluded totals and the original EoC hash,
 *   - the VAS chart greys out the excluded stack range, in both renderers.
 */
const STACK_VA_LABEL = "0x7fff0000";
const HEAP_VA_LABEL = "0x10000000";

interface ProvenanceRecord {
  materialized: boolean;
  selected_categories: string[] | null;
  excluded_regions: number | null;
  excluded_bytes: number | null;
  orig_eoc_hash: string | null;
}

for (const backend of ["svg", "plotly"] as const) {
  test.describe(`Wizard materialize import (${backend} VAS chart)`, () => {
    test.skip(!heapStackMslAvailable, "Heap+stack MSL fixture missing.");

    test("copy keeps dump_uuid, records provenance, greys excluded VAS range", async ({ page }, testInfo) => {
      await primeChartBackend(page, backend);
      await disableFtueViaStorage(page);
      await page.goto("/");
      await dismissFtueIfPresent(page);
      await page.getByRole("button", { name: /New Session/i }).first().click();

      const pathInput = page.getByPlaceholder("Enter path to file or directory");
      await expect(pathInput).toBeVisible({ timeout: 15_000 });
      await pathInput.fill(heapStackMslPath);
      await page.getByRole("button", { name: /^Next$/ }).click();

      await expect(page.getByTestId("region-select-step")).toBeVisible({ timeout: 20_000 });
      await expect(page.getByTestId("region-preview-loading")).toBeHidden({ timeout: 60_000 });
      await page.getByTestId("region-category-stack").uncheck();
      await expect(page.getByTestId("region-summary")).toContainText(/excluding 1 region/);
      await page.getByTestId("region-materialize").check();
      await expect(page.getByTestId("region-materialize")).toBeChecked();
      await page.getByRole("button", { name: /^Next$/ }).click();

      await page.getByRole("button", { name: /^Inspect Only/i }).first().click();
      const imported = page.waitForResponse((r) => r.url().endsWith("/api/dumps/import-path"));
      await page.getByRole("button", { name: /^Open Workspace$/i }).click();
      const importRes = await imported;
      expect(importRes.ok()).toBe(true);
      const importBody = (await importRes.json()) as { output: string; materialized?: boolean };
      expect(importBody.materialized).toBe(true);
      const copyPath = importBody.output;
      expect(copyPath).not.toBe(heapStackMslPath);
      await expect(page.locator(tab("bookmarks"))).toBeVisible({ timeout: 20_000 });
      // The workspace tour can still race the storage seed; sweep it.
      await dismissFtueIfPresent(page);

      // The copy keeps the original identity.
      for (const p of [heapStackMslPath, copyPath]) {
        const info = await page.request.get(`/api/inspect/session-info?msl_path=${encodeURIComponent(p)}`);
        expect(info.ok()).toBe(true);
        expect((await info.json()).dump_uuid).toBe(HEAP_STACK_MSL_UUID);
      }

      // Provenance via REST: materialized, stack excluded (1 region, 4 KiB).
      const provRes = await page.request.get(
        `/api/inspect/import-provenance?msl_path=${encodeURIComponent(copyPath)}`);
      expect(provRes.ok()).toBe(true);
      const { provenance } = (await provRes.json()) as { provenance: ProvenanceRecord[] };
      expect(provenance).toHaveLength(1);
      expect(provenance[0]).toMatchObject({
        materialized: true,
        selected_categories: ["heap", "unclassified"],
        excluded_regions: 1,
        excluded_bytes: 4096,
      });
      expect(provenance[0].orig_eoc_hash).toMatch(/^[0-9a-f]{64}$/);
      // The original is a live capture: no provenance, no error.
      const origProv = await page.request.get(
        `/api/inspect/import-provenance?msl_path=${encodeURIComponent(heapStackMslPath)}`);
      expect((await origProv.json()).provenance).toEqual([]);

      // Provenance in the UI (Format side tab, under Session Info).
      await page.locator(tab("format")).first().click();
      const section = page.getByTestId("import-provenance");
      await expect(section).toBeVisible({ timeout: 15_000 });
      await expect(section.getByTestId("import-provenance-materialized")).toBeVisible();
      await expect(section.getByTestId("import-provenance-kept")).toContainText("Heap, Unclassified");
      await expect(section.getByTestId("import-provenance-excluded")).toContainText("1 region, 4.0 KiB");
      await expect(section.getByTestId("import-provenance-orig-hash"))
        .toContainText(provenance[0].orig_eoc_hash!);

      // VAS chart: the excluded stack range is drawn but marked not captured.
      await switchToExplorationMode(page);
      await page.locator(tab("vas")).first().click();
      if (backend === "svg") {
        const chart = page.locator('[data-chart-backend="svg"]').first();
        await expect(chart).toBeVisible({ timeout: 20_000 });
        await expect(chart).toContainText(STACK_VA_LABEL);
        await expect(chart).toContainText(HEAP_VA_LABEL);
        await expect(chart.locator('rect[data-captured="false"]')).toHaveCount(1);
        await expect(chart.getByTestId("vas-bar-hatch")).toHaveCount(1);
        await expect(chart.getByTestId("vas-legend-not-captured")).toBeVisible();
      } else {
        const chart = page.locator(".js-plotly-plot").first();
        await expect(chart).toBeVisible({ timeout: 20_000 });
        await expect(chart.locator(".ytick text", { hasText: STACK_VA_LABEL })).toHaveCount(1);
        await expect(chart.locator(".legendtext", { hasText: /Not captured/ })).toHaveCount(1);
      }
      await page.screenshot({ path: testInfo.outputPath(`materialize-vas-${backend}.png`), fullPage: true });
    });
  });
}

// Committed Android regioned raw dump (one page per mapping of
// tests/fixtures/android/app_process_arm64.maps, auto-detected sidecar).
// Regenerate with: python tests/e2e/fixtures/android_maps/generate.py
const ANDROID_DIR = path.resolve(__dirname, "../fixtures/android_maps");
const ANDROID_DUMP = path.join(ANDROID_DIR, "app_process.bin");
const androidMapsAvailable = existsSync(ANDROID_DUMP) && existsSync(path.join(ANDROID_DIR, "app_process.maps"));
// memslicer-written Android capture with a VAS_MAP of mapping names.
const MEMSLICER_ANDROID_MSL = path.resolve(__dirname, "../../fixtures/android/memslicer_android.msl");

async function openRegionsStep(page: import("@playwright/test").Page, dumpPath: string) {
  await disableFtueViaStorage(page);
  await page.goto("/");
  await dismissFtueIfPresent(page);
  await page.getByRole("button", { name: /New Session/i }).first().click();
  const pathInput = page.getByPlaceholder("Enter path to file or directory");
  await expect(pathInput).toBeVisible({ timeout: 15_000 });
  await pathInput.fill(dumpPath);
  await page.getByRole("button", { name: /^Next$/ }).click();
  await expect(page.getByTestId("region-select-step")).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("region-summary")).toBeVisible({ timeout: 30_000 });
}

/**
 * Android-aware classification: zygote / boot-image / ART metadata / device
 * mappings are `runtime` and excluded by default, while the real Android
 * heaps (scudo, libc_malloc, dalvik spaces) and thread stacks stay selected.
 */
test.describe("Wizard Regions step: Android regioned raw dump", () => {
  test.skip(!androidMapsAvailable, "Android maps fixture missing.");

  test("runtime excluded by default, names classified, provenance row", async ({ page }, testInfo) => {
    await openRegionsStep(page, ANDROID_DUMP);

    const notice = page.getByTestId("region-runtime-notice");
    await expect(notice).toBeVisible();
    await expect(notice).toContainText("Android process: 23 runtime regions (92.0 KiB)");
    await expect(page.getByTestId("region-category-runtime")).not.toBeChecked();
    for (const c of ["heap", "stack", "unclassified"]) {
      await expect(page.getByTestId(`region-category-${c}`)).toBeChecked();
    }
    await expect(page.getByTestId("region-summary"))
      .toContainText("Keeping 17 regions (68.0 KiB) · excluding 43 regions (172.0 KiB)");
    await page.getByTestId("region-table-toggle").click();
    await expect(page.getByTestId("region-table-name").filter({ hasText: "[anon:scudo:primary]" }).first())
      .toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("wizard-regions-android.png"), fullPage: true });

    // Import with the default selection; the provenance records name-based classification.
    await page.getByRole("button", { name: /^Next$/ }).click();
    await page.getByRole("button", { name: /^Inspect Only/i }).first().click();
    const imported = page.waitForResponse((r) => r.url().endsWith("/api/dumps/import-path"));
    await page.getByRole("button", { name: /^Open Workspace$/i }).click();
    const importRes = await imported;
    expect(importRes.ok()).toBe(true);
    const { output } = (await importRes.json()) as { output: string };
    await expect(page.locator(tab("bookmarks"))).toBeVisible({ timeout: 20_000 });
    await dismissFtueIfPresent(page);

    const provRes = await page.request.get(
      `/api/inspect/import-provenance?msl_path=${encodeURIComponent(output)}`);
    expect(provRes.ok()).toBe(true);
    const { provenance } = (await provRes.json()) as { provenance: { region_names: boolean }[] };
    expect(provenance.some((p) => p.region_names)).toBe(true);

    await page.locator(tab("format")).first().click();
    const section = page.getByTestId("import-provenance");
    await expect(section).toBeVisible({ timeout: 15_000 });
    await expect(section.getByTestId("import-provenance-region-names")).toContainText("Classified by mapping names");
  });

  test("memslicer Android .msl previews with runtime excluded by default", async ({ page }) => {
    test.skip(!existsSync(MEMSLICER_ANDROID_MSL), "memslicer Android .msl fixture missing.");
    await openRegionsStep(page, MEMSLICER_ANDROID_MSL);
    await expect(page.getByTestId("region-runtime-notice"))
      .toContainText("Android process: 3 runtime regions (12.0 KiB)");
    await expect(page.getByTestId("region-category-runtime")).not.toBeChecked();
    await expect(page.getByTestId("region-category-heap")).toBeChecked();
    await expect(page.getByTestId("region-summary")).toContainText("excluding 5 regions");
  });
});
