import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
} from "../fixtures/workspace";

test.describe("Convergence bottom tab mounts", () => {
  test.skip(!datasetAvailable, "Dataset not present.");
  test("mounts without errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));
    page.on("response", (res) => {
      if (res.status() >= 500) errors.push(`${res.status()} ${res.url()}`);
    });
    await enterWorkspaceWithMsl(page);
    await switchToExplorationMode(page);
    await page.locator(tab("convergence")).first().click();
    await expect(page.locator(tab("convergence")).first()).toBeVisible();
    await page.waitForTimeout(800);
    expect(errors).toEqual([]);
  });
});
