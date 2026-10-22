import fs from "node:fs";
import path from "node:path";
import { test, expect, type Page } from "@playwright/test";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

/**
 * Regression: a file analysis on a gcore core highlighted the WRONG bytes.
 *
 * `run_file` reports a gcore's hits as offsets in its "vas" view (PT_LOADs
 * concatenated), but the hex viewer painted them in whatever view it was in
 * — "raw" by default — and only offered the raw/vas switch for `.msl` files.
 * The fixture stores its PT_LOAD bodies in reverse file order, so the planted
 * `secret=ABCDEF01` sits at vas 0x1100 but raw 0x1b0: painting the vas offset
 * in the raw view marks unrelated bytes.
 *
 * Fixture: tests/e2e/fixtures/gcore_planted (regenerate with its generate.py).
 */

const FIXTURE_DIR = path.resolve(__dirname, "../fixtures/gcore_planted");
const CORE = path.join(FIXTURE_DIR, "planted.core");
const META_PATH = path.join(FIXTURE_DIR, "planted.json");
const fixtureAvailable = fs.existsSync(CORE) && fs.existsSync(META_PATH);

interface PlantedMeta {
  raw_offset: number;
  vas_offset: number;
  secret: string;
  regex: string;
}

function secretHex(secret: string): string[] {
  return [...secret].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"));
}

async function goToOffset(page: Page, offset: number): Promise<void> {
  // The hex toolbar's go-to box: the "0x offset" input right before "Go"
  // (the Bookmarks side tab has another input with the same placeholder).
  const go = page.getByRole("button", { name: /^Go$/ }).first();
  await go.locator("xpath=preceding-sibling::input[1]").fill(`0x${offset.toString(16)}`);
  await go.click();
}

async function onlyUserRegex(page: Page, regex: string): Promise<void> {
  for (const label of ["Entropy Scan", "Pattern Match", "Change Point", "Structure Scan"]) {
    const box = page.getByRole("checkbox", { name: label });
    if (await box.isChecked()) await box.uncheck();
  }
  const regexBox = page.getByRole("checkbox", { name: "User Regex" });
  if (!(await regexBox.isChecked())) await regexBox.check();
  await page.getByPlaceholder(/Regex pattern/).fill(regex);
}

test.describe("hex viewer — gcore analysis hits land on the planted bytes", () => {
  test.skip(!fixtureAvailable, "gcore_planted fixture missing (run its generate.py)");

  test("hits switch the viewer to vas and highlight exactly the secret", async ({ page }) => {
    test.setTimeout(120_000);
    const meta = JSON.parse(fs.readFileSync(META_PATH, "utf8")) as PlantedMeta;
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, CORE);

    // The view switch is offered from the backend-detected format, although
    // a `.core` is "raw" by extension. Start in the raw view on purpose.
    const views = page.getByRole("tablist", { name: "Dump view mode" });
    await expect(views).toBeVisible({ timeout: 15_000 });
    await expect(views.getByRole("tab")).toHaveText(["Raw file", "Memory (VAS)"]);
    await views.getByRole("tab", { name: "Raw file" }).click();
    await expect(views.getByRole("tab", { name: "Raw file" })).toHaveAttribute("aria-selected", "true");

    await page.locator(tab("analysis")).first().click();
    await onlyUserRegex(page, meta.regex);
    await page.getByRole("button", { name: /^Run Analysis$/ }).click();
    await expect(page.locator(tab("results")).first()).toContainText(/\d/, { timeout: 90_000 });

    // The hits' offset_view ("vas") switched the viewer.
    await expect(views.getByRole("tab", { name: "Memory (VAS)" })).toHaveAttribute(
      "aria-selected", "true", { timeout: 10_000 });
    await expect(page.getByText(/GCORE · VAS\b/)).toBeVisible();

    await goToOffset(page, meta.vas_offset);
    const expected = secretHex(meta.secret);
    for (let i = 0; i < expected.length; i++) {
      const cell = page.locator(`.hex-byte[data-offset="${meta.vas_offset + i}"]`);
      await expect(cell).toHaveText(expected[i], { timeout: 15_000 });
      await expect(cell).toHaveClass(/highlight-search/);
    }
    // ...and nothing either side of it.
    for (const off of [meta.vas_offset - 1, meta.vas_offset + expected.length]) {
      await expect(page.locator(`.hex-byte[data-offset="${off}"]`)).not.toHaveClass(/highlight-search/);
    }
    await page.screenshot({ path: test.info().outputPath("gcore-hit-vas.png") });

    // Back in the raw view the vas-offset highlight must not paint unrelated
    // bytes; the secret's raw copy is there, unhighlighted.
    await views.getByRole("tab", { name: "Raw file" }).click();
    await goToOffset(page, meta.raw_offset);
    const rawFirst = page.locator(`.hex-byte[data-offset="${meta.raw_offset}"]`);
    await expect(rawFirst).toHaveText(expected[0], { timeout: 15_000 });
    await expect(page.locator(".hex-byte.highlight-search")).toHaveCount(0);

    guards.assertClean();
  });
});
