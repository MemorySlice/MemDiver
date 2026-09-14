import { test, expect } from "@playwright/test";
import { syntheticMslAvailable, syntheticMslPath } from "../fixtures/dataset";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";

/**
 * The multi-format search needle, in the real browser.
 *
 * The unit tests prove the parser; this proves the thing an analyst actually
 * touches — that the format survives the trip to the server, that the preview
 * shows the bytes that were really searched, and that the ambiguity hint is a
 * working control rather than a label.
 */

const box = "[data-testid='hex-search-box']";
const pattern = "[data-testid='hex-search-pattern']";
const formatSelect = "[data-testid='hex-search-format']";
const preview = "[data-testid='hex-search-preview']";
const find = "[data-testid='hex-search-find']";
const subrow = "[data-testid='hex-search-subrow']";

test.describe("hex search: pattern formats", () => {
  test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");

  test("the preview shows the resolved bytes BEFORE the search runs", async ({ page }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, syntheticMslPath);
    await expect(page.locator(box)).toBeVisible();

    // `dead` is a word AND a byte pair. Auto keeps the historical behaviour
    // (hex) -- and says so, which is the whole point: a guess you can see.
    await page.locator(pattern).fill("dead");
    await expect(page.locator(preview)).toContainText("Hex");
    await expect(page.locator(preview)).toContainText("2 B");
    await expect(page.locator(subrow)).toContainText("de ad");

    // ...and names the other reading, as a control.
    const switchBtn = page.locator("[data-testid='hex-search-switch-format']");
    await expect(switchBtn).toBeVisible();
    await switchBtn.click();
    await expect(page.locator(formatSelect)).toHaveValue("text");
    // Same four characters, different bytes -- the reason the hint exists.
    await expect(page.locator(subrow)).toContainText("64 65 61 64");
    await expect(page.locator(preview)).toContainText("4 B");

    // The sub-row takes a line of its own; it must NEVER widen the toolbar.
    // Wrapping the group in a column div once made the hint text the group's
    // intrinsic width, overflowing the toolbar and pushing the view-mode and
    // go-to groups onto separate lines.
    const overflow = await page.evaluate(() => {
      const el = document.querySelector("[data-testid='hex-search-subrow']")!
        .parentElement!;
      return el.scrollWidth - el.clientWidth;
    });
    expect(overflow, "search sub-row must not widen the toolbar").toBeLessThanOrEqual(1);

    guards.assertClean();
  });

  test("a text needle is sent as text and answered by the server", async ({ page }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, syntheticMslPath);

    const request = page.waitForRequest((r) =>
      r.url().includes("/api/inspect/byte-search") &&
      r.url().includes("pattern_format=text"));

    await page.locator(formatSelect).selectOption("text");
    await page.locator(pattern).fill("MEMSLICE");
    await page.locator(find).click();

    // The format reached the wire -- not merely the preview.
    await request;
    guards.assertClean();
  });

  test("invalid input is explained in place, and Find stays disabled", async ({ page }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, syntheticMslPath);

    await page.locator(formatSelect).selectOption("hex");
    await page.locator(pattern).fill("dea");   // odd -> half a byte
    await expect(page.locator("[data-testid='hex-search-parse-error']"))
      .toContainText("odd number of hex digits");
    // Nothing to search for, so the control that would search says so.
    await expect(page.locator(find)).toBeDisabled();

    guards.assertClean();
  });

  test("a short needle warns before it floods the view", async ({ page }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, syntheticMslPath);

    await page.locator(formatSelect).selectOption("hex");
    await page.locator(pattern).fill("00");
    await expect(page.locator("[data-testid='hex-search-short-warning']")).toBeVisible();

    await page.locator(pattern).fill("0011223344");
    await expect(page.locator("[data-testid='hex-search-short-warning']")).toHaveCount(0);

    guards.assertClean();
  });
});
