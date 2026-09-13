/**
 * Getting a real, consensus-backed ALIGNED OVERLAY on screen.
 *
 * Extracted from `specs/multi-dump-overlay.spec.ts`'s own setup so that the
 * overlay's a11y coverage runs against the SAME screen the behavioural spec
 * asserts on. A second, hand-rolled path into the overlay would let the two
 * drift — and an a11y sweep of a slightly different screen is an a11y sweep of
 * a screen no user reaches.
 *
 * Every step here is load-bearing and the reasons are in the spec's header:
 *   - "Memory (VAS)" first, because the aligned-window endpoint refuses
 *     `view="raw"` for an `.msl` anchor;
 *   - exploration mode, because `dump-run-consensus` only exists there;
 *   - the consensus must FINISH before the Overlay tab has anything to paint.
 */
import { expect, type Page } from "@playwright/test";

import { aslrMslRun1Path, aslrMslRun2Path } from "./dataset";
import { tab } from "./selectors";
import { enterWorkspaceWithMsl, switchToExplorationMode } from "./workspace";

export const OVERLAY_RUN_1 = "run_1.msl";
export const OVERLAY_RUN_2 = "run_2.msl";

/** Wall-clock budget for one full "wizard → two dumps → consensus → overlay". */
export const OVERLAY_SETUP_TIMEOUT = 180_000;

export interface AlignedOverlayHandles {
  /** `data-dump-id` of run_1 — the session origin, and therefore the anchor. */
  id1: string;
  /** `data-dump-id` of run_2. */
  id2: string;
}

async function dumpIdByName(page: Page, name: string): Promise<string> {
  const row = page.locator('[data-testid="dump-row"]').filter({ hasText: name }).first();
  await expect(row).toBeVisible({ timeout: 15_000 });
  const id = await row.getAttribute("data-dump-id");
  expect(id, `the ${name} row must carry data-dump-id`).toBeTruthy();
  return id as string;
}

/**
 * Drive the UI from the landing page to a painted, consensus-backed overlay
 * over the committed ASLR `.msl` pair.
 *
 * Returns on the first frame where a real byte cell holds a hex value, so a
 * caller may assert on painted classes immediately.
 */
export async function enterAlignedOverlay(page: Page): Promise<AlignedOverlayHandles> {
  await enterWorkspaceWithMsl(page, aslrMslRun1Path);

  await page.getByRole("tab", { name: "Memory (VAS)" }).click();

  await page.locator(tab("dumps")).first().click();
  const addInput = page.getByPlaceholder("Server path to dump file");
  await expect(addInput).toBeVisible({ timeout: 15_000 });
  await addInput.fill(aslrMslRun2Path);
  await addInput.press("Enter");

  const id1 = await dumpIdByName(page, OVERLAY_RUN_1);
  const id2 = await dumpIdByName(page, OVERLAY_RUN_2);

  await switchToExplorationMode(page);
  await page.locator(tab("dumps")).first().click();
  const runConsensus = page.getByTestId("dump-run-consensus");
  await expect(runConsensus).toHaveText("Run consensus on 2 dumps");
  await expect(runConsensus).toBeEnabled();
  await runConsensus.click();
  await expect(runConsensus).toHaveText("Run consensus on 2 dumps", { timeout: 90_000 });

  const overlayTab = page.getByTestId("main-view-overlay");
  await expect(overlayTab).toBeEnabled();
  await overlayTab.click();
  await expect(page.getByTestId("hex-overlay-pane")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("hex-overlay-no-consensus")).toHaveCount(0);

  // Bytes have to be on screen before anything can be painted on them.
  await expect(
    page.locator('[data-testid="hex-overlay-scroll"] .hex-byte[data-offset="0"]'),
  ).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 30_000 });

  return { id1, id2 };
}

/** The hex store's live cursor, via the DEV-only `window.__useHexStore` hook. */
export async function cursorOffset(page: Page): Promise<number | null> {
  return page.evaluate(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const hook = (window as any).__useHexStore;
    if (typeof hook !== "function") return null;
    return hook.getState().cursorOffset as number | null;
  });
}
