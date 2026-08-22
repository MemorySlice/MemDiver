import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import { enterWorkspaceWithMsl } from "../fixtures/workspace";

test.describe("Structures side tab mounts", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset not present.");
  test("mounts without errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));
    page.on("response", (res) => {
      if (res.status() >= 500) errors.push(`${res.status()} ${res.url()}`);
    });
    await enterWorkspaceWithMsl(page);
    await page.locator(tab("structures")).first().click();
    await expect(page.locator(tab("structures")).first()).toBeVisible();
    await page.waitForTimeout(800);
    expect(errors).toEqual([]);
  });

  test("applying a structure overlays the hex viewer", async ({ page }) => {
    await enterWorkspaceWithMsl(page);

    // A structure applies at the cursor offset, so set the cursor by clicking
    // a byte in the hex viewer first.
    await page.locator('.hex-byte[data-col="hex"]').first().click();

    await page.locator(tab("structures")).first().click();
    const applyBtn = page.locator('[data-tour-id="structure-apply-button"]').first();
    await expect(applyBtn).toBeVisible({ timeout: 10_000 });
    await applyBtn.click();

    // The applied structure's fields become `type: "structure"` highlight
    // regions, which paint `highlight-structure` onto the covered hex cells.
    await expect(page.locator(".hex-byte.highlight-structure").first()).toBeVisible({
      timeout: 10_000,
    });
  });
});
