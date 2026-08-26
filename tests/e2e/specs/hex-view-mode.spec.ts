import { test, expect, type Page } from "@playwright/test";
import { syntheticMslAvailable, syntheticMslPath } from "../fixtures/dataset";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";

/**
 * Regression: switching an .msl's hex view mode used to blank the viewer.
 *
 * `setViewMode` clears the chunk cache (correct — a byte means something
 * different in each view), but the only thing that refills it is the fetch
 * effect in HexViewer, whose dependency array did not include `viewMode`.
 * With the window at row 0 and no scroll, none of its deps changed, so no
 * re-fetch was ever issued: every cell rendered the `--` placeholder, the
 * status bar kept reporting correct metadata, and toggling back did NOT
 * recover. The failure was permanent.
 *
 * Why the pre-existing import spec never caught it: there, the view toggle
 * follows a dump switch, which changes the visible row range and masks the
 * missing dependency. These tests toggle with nothing else changing.
 */

/** A real byte-chunk request (not one of the 1-byte per-view size probes). */
function isChunkRequest(url: string, view: string): boolean {
  if (!url.includes("/api/inspect/hex-raw")) return false;
  const q = new URL(url).searchParams;
  return q.get("view") === view && Number(q.get("length") ?? "0") > 1;
}

/** Every rendered byte cell showing the placeholder == the bug. */
async function placeholderRatio(page: Page): Promise<number> {
  return page.evaluate(() => {
    const cells = [...document.querySelectorAll(".hex-byte")];
    if (cells.length === 0) return 1;
    const ph = cells.filter((c) => /^-+$/.test((c.textContent ?? "").trim())).length;
    return ph / cells.length;
  });
}

test.describe("hex viewer — .msl view-mode switching", () => {
  test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");

  test("each view switch re-fetches bytes instead of blanking the viewer", async ({ page }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, syntheticMslPath);

    // Baseline: the raw view of an .msl always has content (the MSL header).
    const byte0 = page.locator('.hex-byte[data-offset="0"]');
    await expect(byte0).toBeVisible({ timeout: 15_000 });
    await expect(byte0).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 15_000 });

    // raw -> VAS. The re-fetch firing at all is the regression under test;
    // we assert the request rather than the bytes because a synthetic MSL may
    // legitimately have nothing mapped at VAS offset 0.
    const vasChunk = page.waitForRequest((r) => isChunkRequest(r.url(), "vas"), {
      timeout: 15_000,
    });
    await page.getByRole("tab", { name: "Memory (VAS)" }).click();
    await vasChunk;

    // VAS -> VA, same guarantee.
    const vaChunk = page.waitForRequest((r) => isChunkRequest(r.url(), "va"), {
      timeout: 15_000,
    });
    await page.getByRole("tab", { name: "VA", exact: true }).click();
    await vaChunk;

    // The status bar must name the view it is actually in. It used to label
    // the "va" view as "raw", which actively hid this bug during triage.
    await expect(page.getByText(/MSL · VA\b/)).toBeVisible({ timeout: 10_000 });

    // VA -> raw: bytes must come back. Before the fix the cache stayed empty
    // forever, so returning to raw still showed only placeholders.
    const rawChunk = page.waitForRequest((r) => isChunkRequest(r.url(), "raw"), {
      timeout: 15_000,
    });
    await page.getByRole("tab", { name: "Raw file" }).click();
    await rawChunk;
    await expect(byte0).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 15_000 });
    expect(await placeholderRatio(page)).toBeLessThan(1);

    guards.assertClean();
  });
});
