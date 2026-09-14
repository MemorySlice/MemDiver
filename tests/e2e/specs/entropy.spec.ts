import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
} from "../fixtures/workspace";

test.describe("Entropy bottom tab mounts", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset not present.");
  test("mounts without errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));
    page.on("response", (res) => {
      if (res.status() >= 500) errors.push(`${res.status()} ${res.url()}`);
    });
    await enterWorkspaceWithMsl(page);
    await switchToExplorationMode(page);

    // Wait for the REQUEST, not for 800ms. `GET /api/inspect/entropy` is a sync
    // FastAPI handler, so Starlette cannot cancel it when the context closes at
    // the end of this test -- it runs to completion in the threadpool, holding
    // the GIL, and whatever spec runs next pays for it. A fixed sleep that is
    // shorter than the compute abandons exactly that.
    const entropy = page.waitForResponse(
      (res) => res.url().includes("/api/inspect/entropy"),
      { timeout: 120_000 },
    );
    await page.locator(tab("entropy")).first().click();
    await expect(page.locator(tab("entropy")).first()).toBeVisible();
    const res = await entropy;
    expect(res.status(), "GET /api/inspect/entropy").toBe(200);

    expect(errors).toEqual([]);
  });
});
