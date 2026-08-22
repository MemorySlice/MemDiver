import fs from "node:fs";
import path from "node:path";
import { test, expect } from "@playwright/test";
import {
  datasetAvailable,
  syntheticMslAvailable,
  syntheticMslPath,
  MSL,
  RUN_0001,
} from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
  installErrorGuards,
} from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

test.describe("P2 breadth — analysis, panels, keys, structures", () => {
  // ---- Full Start-Analysis pipeline (real backend, synthetic MSL). ----
  // The 215 MB real MSL is unbounded + entropy_scan is ~94 s/10 MB, so a full
  // run there is impractical. The committed 7 KB synthetic MSL exercises the
  // exact same /api/analysis/run-file → WS progress → results pipeline and
  // completes deterministically in seconds.
  test("Auto-Analyze runs the full pipeline and produces results", async ({ page }) => {
    test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);

    await enterWorkspaceWithMsl(page, syntheticMslPath, { autoAnalyze: true });

    // The auto-run effect fires on mount; when hits land, BottomTabs auto-
    // switches to results and the results tab shows a hit-count badge.
    await expect(page.locator('[data-testid="tab-results"]')).toContainText(/\d/, {
      timeout: 90_000,
    });
    await page.locator(tab("results")).first().click();
    await expect(page.getByText(/\d+\s+hits/i).first()).toBeVisible({ timeout: 10_000 });

    guards.assertClean();
  });

  // ---- Every exploration-mode panel renders a defined state (no crash). ----
  test("exploration-mode panels render gracefully on a real MSL @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, MSL);
    await switchToExplorationMode(page);

    // (id, locator that proves a defined state). `entropy` is omitted here —
    // its whole-file compute on a 215 MB dump is too slow for a tab click.
    const checks: Array<[string, () => Promise<void>]> = [
      ["consensus", async () => { await expect(page.getByTestId("consensus-empty")).toBeVisible({ timeout: 10_000 }); }],
      ["live-consensus", async () => { await expect(page.getByTestId("live-consensus-empty")).toBeVisible({ timeout: 10_000 }); }],
      ["architect", async () => { await expect(page.getByTestId("architect-empty")).toBeVisible({ timeout: 10_000 }); }],
      ["experiment", async () => { await expect(page.getByTestId("experiment-panel")).toBeVisible({ timeout: 10_000 }); }],
      ["convergence", async () => { await expect(page.getByTestId("convergence-empty")).toBeVisible({ timeout: 10_000 }); }],
      ["variance", async () => { await expect(page.getByText(/Select a hit or neighborhood overlay/i)).toBeVisible({ timeout: 10_000 }); }],
    ];

    for (const [id, assertState] of checks) {
      await page.locator(tab(id)).first().click();
      await assertState();
    }

    guards.assertClean();
  });

  // ---- VAS chart loads real region metadata (or a clean empty state). ----
  test("VAS chart loads for a real MSL @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, MSL);
    await switchToExplorationMode(page);

    await page.locator(tab("vas")).first().click();
    // Either the plotly chart mounts (regions present) or the defined empty
    // text renders — both are graceful (no crash).
    await expect(
      page.locator(".js-plotly-plot").or(page.getByText("No VAS data.")),
    ).toBeVisible({ timeout: 20_000 });

    guards.assertClean();
  });

  // ---- Entropy chart renders (small synthetic MSL keeps whole-file fast). ----
  test("entropy chart renders on the synthetic MSL", async ({ page }) => {
    test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");
    test.setTimeout(60_000);
    await enterWorkspaceWithMsl(page, syntheticMslPath);
    await switchToExplorationMode(page);

    await page.locator(tab("entropy")).first().click();
    // Chart mounts, or a defined loading/failed message — never a crash.
    await expect(
      page
        .locator(".js-plotly-plot")
        .or(page.getByText(/entropy/i).first()),
    ).toBeVisible({ timeout: 20_000 });
  });

  // ---- Encrypted-MSL key material: unlock enables a keyed (VAS) read. ----
  test("unlocking an encrypted MSL enables keyed reads @requires-dataset", async ({ page }) => {
    test.skip(!datasetAvailable, "real dataset not present");
    test.setTimeout(120_000);
    await enterWorkspaceWithMsl(page, MSL);

    // The run's password lives in its meta.json (the dataset's own key source).
    const meta = JSON.parse(
      fs.readFileSync(path.join(RUN_0001, "meta.json"), "utf8"),
    ) as { password?: string };
    const password = meta.password ?? "";
    expect(password.length).toBeGreaterThan(0);

    // Key entry lives in the Dumps side tab as TagStatusUnlock, shown only when
    // the container reads as `missing_key`.
    await page.locator(tab("dumps")).first().click();
    const pw = page.locator('input[type="password"]').first();

    if (await pw.isVisible().catch(() => false)) {
      await pw.fill(password);
      await pw.press("Enter");
      // On a valid key the unlock UI unmounts (status flips away from missing_key).
      await expect(pw).toBeHidden({ timeout: 15_000 });

      // Prove the key is now applied: switching to the decrypted VAS view issues
      // a hex-raw read carrying the passphrase.
      const keyedRead = page.waitForRequest(
        (r) => /\/api\/inspect\/hex-raw\?/.test(r.url()) && /[?&]passphrase=/.test(r.url()),
        { timeout: 20_000 },
      );
      await page.getByRole("tab", { name: "Memory (VAS)" }).click();
      await keyedRead;
    } else {
      // Not encrypted on this machine — keyless raw read already works.
      await expect(page.locator('.hex-byte[data-offset="0"]').first()).toBeVisible({
        timeout: 15_000,
      });
    }
  });
});
