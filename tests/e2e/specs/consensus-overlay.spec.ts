/**
 * E2E coverage for the Phase 1 consensus-overlay wiring.
 *
 * The Phase 1 work (HexViewer + HexRow) maps per-byte classification
 * codes 0–3 to the CSS classes `consensus-invariant`, `consensus-structural`,
 * `consensus-pointer`, `consensus-key-candidate` (defined in hex.css:140).
 * Without a test that actually exercises the toggle → byte-class flow,
 * a future refactor could silently regress the wiring.
 *
 * Rather than running a full live consensus (which takes minutes on a
 * real dataset), we inject a synthetic `pageClassifications` map into
 * the consensus store via the DEV-only `window.__useConsensusStore`
 * hook. This exercises the HexViewer → HexRow → CSS class pipeline
 * end-to-end without needing backend consensus.
 */
import { test, expect } from "@playwright/test";
import { datasetAvailable } from "../fixtures/dataset";
import { enterWorkspaceWithMsl } from "../fixtures/workspace";
import { waitForHexBytes } from "./screenshots-helpers";

test.describe("Consensus overlay wiring", () => {
  test.skip(!datasetAvailable, "Dataset MSL fixture not present.");
  test.setTimeout(180_000);

  test("toggle + synthetic classifications paint bytes with consensus-* classes", async ({
    browser,
  }) => {
    const context = await browser.newContext();
    const page = await context.newPage();

    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);

    // Ensure the DEV hook is available before we try to drive it.
    const hookAvailable = await page.evaluate(() => {
      return typeof (window as unknown as {
        __useConsensusStore?: unknown;
      }).__useConsensusStore === "function";
    });
    expect(
      hookAvailable,
      "window.__useConsensusStore must be exposed in DEV builds",
    ).toBe(true);

    // Inject synthetic per-byte classifications for row 0 (offsets 0–15):
    // byte 0 → invariant (code 0)
    // byte 1 → structural (code 1)
    // byte 2 → pointer (code 2)
    // byte 3 → key-candidate (code 3)
    // bytes 4–15 → all code 0 (invariant) as filler
    await page.evaluate(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const store = (window as any).__useConsensusStore;
      const classifications = [0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      store.setState({
        available: true,
        size: 1024,
        numDumps: 2,
        overlayEnabled: true,
        pageClassifications: new Map([[0, classifications]]),
      });
    });

    // The stable getClassificationAt callback's identity rotates on
    // pageClassifications change, so HexRow's memo invalidates on the
    // next virtualizer flush. Wait a tick.
    await page.waitForTimeout(500);

    // Assert each class lands on the expected byte offset. We target
    // the hex-column span; .hex-char (ASCII column) gets the same class
    // applied at the same time so either column is a valid probe.
    const byte0 = page.locator('[data-offset="0"][data-col="hex"]').first();
    const byte1 = page.locator('[data-offset="1"][data-col="hex"]').first();
    const byte2 = page.locator('[data-offset="2"][data-col="hex"]').first();
    const byte3 = page.locator('[data-offset="3"][data-col="hex"]').first();

    await expect(byte0).toHaveClass(/consensus-invariant/);
    await expect(byte1).toHaveClass(/consensus-structural/);
    await expect(byte2).toHaveClass(/consensus-pointer/);
    await expect(byte3).toHaveClass(/consensus-key-candidate/);

    // Negative: toggling the overlay off should remove the classes on
    // the next render.
    await page.evaluate(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const store = (window as any).__useConsensusStore;
      store.setState({ overlayEnabled: false });
    });
    await page.waitForTimeout(500);

    // Post-toggle: bytes still have the same dom identity but
    // consensus-* classes are gone.
    await expect(byte0).not.toHaveClass(/consensus-invariant/);
    await expect(byte1).not.toHaveClass(/consensus-structural/);
    await expect(byte2).not.toHaveClass(/consensus-pointer/);
    await expect(byte3).not.toHaveClass(/consensus-key-candidate/);

    await context.close();
  });
});
