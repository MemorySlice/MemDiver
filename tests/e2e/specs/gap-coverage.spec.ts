import { test, expect } from "@playwright/test";
import { datasetAvailable } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
  installErrorGuards,
} from "../fixtures/workspace";
import { tab, formatPill } from "../fixtures/selectors";

/**
 * Coverage for user-facing features that the other specs mount but never
 * actually exercise (the "mount-only" gap), plus tabs/panels with no spec
 * at all. Every test installs the shared error guards so a console error or
 * 5xx surfaced while driving the feature fails the run.
 */
test.describe("gap coverage: real interactions on under-covered features", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset not present; cannot mount workspace.");

  // The format sidebar stacks every MSL panel (SessionInfo, BlockNavigator,
  // ModuleList/Index, Process/Connection/Handle lists, all six ReservedBlocks
  // panels) and mounts them together on a .msl dump — each fires its own
  // /api/inspect/* call. Opening the tab against the REAL dataset exercises
  // all of them at once and asserts none error.
  test("format tab mounts every MSL panel against real data without errors", async ({ page }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page);

    await page.locator(tab("format")).first().click();
    // format-pill is the unique format-detection badge; its presence confirms
    // the format tab (and the stacked MSL panels beneath it) mounted.
    await expect(page.locator(formatPill)).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("heading", { name: "MSL Blocks" }).first()).toBeVisible();
    // Let every stacked panel's /api/inspect/* call settle.
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1000);

    guards.assertClean();
  });

  // variance + vas exploration tabs have no spec at all. Verify each renders
  // its chart (or its documented empty-state) without throwing.
  test("variance and vas exploration tabs render without errors", async ({ page }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page);
    await switchToExplorationMode(page);

    // variance shows VarianceMap only when a neighborhood overlay is active;
    // otherwise it renders a documented "select a hit…" message. Either is a
    // valid, non-erroring render.
    await page.locator(tab("variance")).first().click();
    await expect(
      page.getByText(/variance profile/i).or(page.locator('[data-chart-backend]')),
    ).toBeVisible({ timeout: 10_000 });

    // vas fetches regions for the dump and renders VasChart.
    await page.locator(tab("vas")).first().click();
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(800);
    await expect(page.locator(tab("vas"))).toHaveClass(/font-semibold/);

    guards.assertClean();
  });

  // SettingsMenu is never opened by any spec. Open it, exercise a couple of
  // display controls, and confirm no errors.
  test("settings menu opens and display controls toggle without errors", async ({ page }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page);

    await page.getByRole("button", { name: /settings/i }).first().click();
    await expect(page.getByText("Display", { exact: true })).toBeVisible();

    // Toggle the first two checkboxes in the menu (e.g. uppercase hex, ASCII
    // column) — pure client-state changes that must not throw.
    const checkboxes = page.getByRole("checkbox");
    const count = Math.min(await checkboxes.count(), 2);
    for (let i = 0; i < count; i++) {
      await checkboxes.nth(i).click();
    }

    guards.assertClean();
  });

  // No spec presses the app keyboard shortcuts. ctrl+b toggles the sidebar.
  test("ctrl+b keyboard shortcut toggles the sidebar", async ({ page }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page);

    const sidebar = page.locator('[data-tour-id="workspace-sidebar"]');
    await expect(sidebar).toBeVisible();
    const expandedWidth = (await sidebar.boundingBox())?.width ?? 0;
    expect(expandedWidth).toBeGreaterThan(0);

    // ctrl+b collapses the sidebar panel to 0%.
    await page.keyboard.press("Control+b");
    await page.waitForTimeout(700);
    const collapsedWidth = (await sidebar.boundingBox())?.width ?? 0;
    expect(collapsedWidth).toBeLessThan(expandedWidth);

    // ctrl+b again expands it back.
    await page.keyboard.press("Control+b");
    await page.waitForTimeout(700);
    const reexpandedWidth = (await sidebar.boundingBox())?.width ?? 0;
    expect(reexpandedWidth).toBeGreaterThan(collapsedWidth);

    guards.assertClean();
  });
});
