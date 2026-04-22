import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import { enterWorkspaceWithMsl } from "../fixtures/workspace";

test.describe("Verify-key tab — basic render stub", () => {
  test.skip(!datasetAvailable, "Dataset not present on this machine.");

  test("verify-key tab mounts without crashing", async ({ page }) => {
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(err.message));

    await enterWorkspaceWithMsl(page);

    await page.locator(tab("verify-key")).first().click();
    await expect(page.locator(tab("verify-key")).first()).toBeVisible();

    // Allow the panel a brief moment to render any network calls.
    await page.waitForTimeout(300);
    expect(pageErrors).toEqual([]);
  });
});
