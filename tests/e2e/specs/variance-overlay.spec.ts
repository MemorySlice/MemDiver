import path from "node:path";
import { test, expect } from "@playwright/test";
import { datasetAvailable, MSL, DATASET_DIR } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
  installErrorGuards,
} from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

// Second real .msl of the same process (different run) — cross-session pair.
const MSL_2 = path.join(DATASET_DIR, "run_0002", "memslicer.msl");

test.describe("cross-dump variance (4-state consensus) on .msl", () => {
  // Figure 6: import ≥2 .msl dumps → auto module/VA-aligned consensus → the
  // four states (Invariant / Structural / Pointer / Key-candidate) painted on
  // the hex viewer in VA coordinate, plus a whole-dump variance minimap.
  test("run consensus paints the 4-state overlay in VA view + minimap @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(180_000);
    const guards = installErrorGuards(page);

    // Dump 1 via the wizard, dump 2 via the Dumps-tab "Add dump" path input.
    await enterWorkspaceWithMsl(page, MSL);
    await page.locator(tab("dumps")).first().click();
    const addInput = page.getByPlaceholder("Server path to dump file");
    await expect(addInput).toBeVisible({ timeout: 10_000 });
    await addInput.fill(MSL_2);
    await addInput.press("Enter");

    // Consensus controls live in exploration mode; ≥2 dumps enables the button.
    await switchToExplorationMode(page);
    const runBtn = page.getByRole("button", { name: "Run Consensus" });
    await expect(runBtn).toBeEnabled({ timeout: 15_000 });
    await runBtn.click();

    // The build over two ~210 MB dumps takes a while; it completes when the
    // overlay checkbox (gated on consensusAvailable) becomes enabled.
    const overlayToggle = page
      .getByText("Show overlay in hex view")
      .locator("xpath=preceding-sibling::input[@type='checkbox']");
    await expect(overlayToggle).toBeEnabled({ timeout: 120_000 });
    await overlayToggle.check();

    // Enabling the overlay auto-switches the hex viewer to the VA view, where
    // the classifications are coordinate-correct. The dominant class is
    // invariant (bytes identical across both dumps) — assert it paints on real
    // cells, i.e. the colors land on bytes (the fix).
    await expect(page.locator(".hex-byte.consensus-invariant").first()).toBeVisible({
      timeout: 30_000,
    });

    // The whole-dump variance minimap renders and is clickable (jump-to).
    const minimap = page.getByTestId("variance-minimap");
    await expect(minimap).toBeVisible({ timeout: 15_000 });
    // Click a band low in the strip → jump far across the (huge, sparse) VA
    // span. That target may be a gap with no invariant bytes, so just assert
    // the viewer survives the jump and still renders a hex grid.
    await minimap.click({ position: { x: 10, y: 250 } });
    await expect(page.locator(".hex-byte").first()).toBeVisible({ timeout: 20_000 });

    guards.assertClean();
  });
});
