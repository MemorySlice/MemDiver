import { test, expect } from "@playwright/test";
import { tab, formatPill } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import { enterWorkspaceWithMsl } from "../fixtures/workspace";

test.describe("Format tab — MSL is recognized, not mislabeled as ELF", () => {
  test.skip(!datasetAvailable, "Dataset not present on this machine.");

  test("MSL dump surfaces msl parser and MSL nav tree", async ({ page }) => {
    await enterWorkspaceWithMsl(page);

    // Switch to the Format side tab.
    await page.locator(tab("format")).first().click();

    // The format pill should read "msl" (case-insensitive), NOT "elf*".
    const pill = page.locator(formatPill);
    await expect(pill).toBeVisible({ timeout: 15_000 });
    const pillText = (await pill.textContent())?.toLowerCase() ?? "";
    expect(pillText).toContain("msl");
    expect(pillText).not.toContain("elf");

    // Nav tree must contain MSL block labels. The root label contains
    // "MSL" and block children start with "Block[".
    const navRoot = page.locator("text=/MSL File Header/i").first();
    await expect(navRoot).toBeVisible({ timeout: 15_000 });
    const hasBlock = await page
      .locator('text=/Block\\[/')
      .first()
      .isVisible()
      .catch(() => false);
    expect(hasBlock).toBeTruthy();

    // No PHDR-style labels from a mis-applied ELF parser.
    const phdrCount = await page.locator("text=/PHDR/").count();
    expect(phdrCount).toBe(0);
  });

  test("user can switch parser to elf64 and reset to auto", async ({ page }) => {
    await enterWorkspaceWithMsl(page);
    await page.locator(tab("format")).first().click();

    const pill = page.locator(formatPill);
    await expect(pill).toBeVisible({ timeout: 15_000 });
    await pill.click();

    // The dropdown shows a "Suggested" section with msl, and an
    // "Other parsers" disclosure that contains elf64.
    await expect(page.locator("text=/Suggested/i")).toBeVisible();
    await page.locator("text=/Other parsers/i").click();

    // The "Other parsers" list renders each option as a menuitem (button
    // with role="menuitem" inside the role="menu" dropdown) whose
    // accessible name starts with the format slug, e.g.
    // "elf64 Warning: magic doesn't match".
    const elf64 = page.getByRole("menuitem", { name: /^elf64\b/ }).first();
    await expect(elf64).toBeVisible();
    await elf64.click();

    // Pill now reads "elf64 (forced)".
    await expect(pill).toContainText(/elf64/i);
    await expect(pill).toContainText(/forced/i);

    // Reset: open pill, click "Reset to auto" (also role="menuitem").
    await pill.click();
    await page.getByRole("menuitem", { name: /Reset to auto/i }).click();

    // Pill returns to msl auto.
    await expect(pill).toContainText(/msl/i);
    await expect(pill).not.toContainText(/forced/i);
  });
});
