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
 * real dataset), we inject synthetic classifications into the consensus
 * store via the DEV-only `window.__useConsensusStore` hook. This exercises
 * the HexViewer → HexRow → CSS class pipeline end-to-end without needing
 * backend consensus.
 *
 * There are TWO lookup branches in `getClassificationAtStable`
 * (HexViewer.tsx) and both are covered here:
 *
 *  1. `.msl` dumps in the "va" view read `vaClassifications`, keyed by
 *     row-aligned ABSOLUTE virtual address (`vaSpanStart + row*16`).
 *     Enabling the overlay on an `.msl` dump FORCES the "va" view (see the
 *     `setViewMode("va")` effect) precisely because the slab-coordinate
 *     `pageClassifications` map paints the WRONG BYTES on `.msl`. This is the
 *     load-bearing path.
 *  2. Raw dumps keep the original container-offset `pageClassifications`
 *     lookup.
 *
 * The VA base is read at runtime from the hex store (`vaSpanStart`, resolved
 * by `fetchPageStates`) via the DEV-only `window.__useHexStore` hook — never
 * hardcoded, since it is a property of the dump under test.
 */
import { test, expect } from "@playwright/test";
import { datasetAvailable, GDB_RAW } from "../fixtures/dataset";
import { enterWorkspaceWithMsl } from "../fixtures/workspace";
import { waitForHexBytes } from "./screenshots-helpers";

// Mirrors HexViewer.tsx's module-level `BYTES_PER_ROW`.
const BYTES_PER_ROW = 16;

// byte 0 → invariant (code 0)
// byte 1 → structural (code 1)
// byte 2 → pointer (code 2)
// byte 3 → key-candidate (code 3)
// bytes 4–15 → all code 0 (invariant) as filler
const ROW_CLASSIFICATIONS = [0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

test.describe("Consensus overlay wiring", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset MSL fixture not present.");
  test.setTimeout(180_000);

  test("toggle + synthetic classifications paint bytes with consensus-* classes", async ({
    browser,
  }) => {
    const context = await browser.newContext();
    const page = await context.newPage();

    await enterWorkspaceWithMsl(page);
    await waitForHexBytes(page);

    // Ensure both DEV hooks are available before we try to drive them.
    const hooks = await page.evaluate(() => {
      const w = window as unknown as {
        __useConsensusStore?: unknown;
        __useHexStore?: unknown;
      };
      return {
        consensus: typeof w.__useConsensusStore === "function",
        hex: typeof w.__useHexStore === "function",
      };
    });
    expect(
      hooks.consensus,
      "window.__useConsensusStore must be exposed in DEV builds",
    ).toBe(true);
    expect(
      hooks.hex,
      "window.__useHexStore must be exposed in DEV builds",
    ).toBe(true);

    // Enabling the overlay on an .msl dump makes HexViewer switch to the "va"
    // view, which is the only coordinate-correct view for the overlay.
    // `consensusId` is deliberately left null so HexViewer's fetch effect
    // short-circuits and never overwrites the synthetic map below.
    await page.evaluate(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const store = (window as any).__useConsensusStore;
      store.setState({
        available: true,
        size: 1024,
        numDumps: 2,
        overlayEnabled: true,
      });
    });

    // The forced view switch plus the lazy page-state fetch it triggers are
    // what resolve `vaSpanStart`. Injecting before that would key the map off
    // a placeholder base of 0 and silently miss.
    await page.waitForFunction(
      () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const s = (window as any).__useHexStore.getState();
        return s.viewMode === "va" && s.pageStatesLoaded === true;
      },
      undefined,
      { timeout: 60_000 },
    );

    // Inject synthetic per-byte classifications for row 0, keyed exactly the
    // way getClassificationAtStable looks them up:
    //   va = vaSpanStart + floor(offset / BYTES_PER_ROW) * BYTES_PER_ROW
    // For the offsets the assertions target (0–3) that row-aligns to
    // vaSpanStart itself. The base is READ from the store, never hardcoded.
    const vaBase = await page.evaluate(
      ({ bytesPerRow, codes }) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const hex = (window as any).__useHexStore.getState();
        const va =
          hex.vaSpanStart + Math.floor(0 / bytesPerRow) * bytesPerRow;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const store = (window as any).__useConsensusStore;
        store.setState({ vaClassifications: new Map([[va, codes]]) });
        return va;
      },
      { bytesPerRow: BYTES_PER_ROW, codes: ROW_CLASSIFICATIONS },
    );
    expect(
      Number.isFinite(vaBase),
      "vaSpanStart must resolve to a finite VA base",
    ).toBe(true);

    // The stable getClassificationAt callback's identity rotates on
    // vaClassifications change, so HexRow's memo invalidates on the
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

  // The other half of getClassificationAtStable: raw (non-.msl) dumps keep the
  // container-offset `pageClassifications` lookup and are NOT forced into the
  // "va" view. Guards that the .msl/VA fix above did not break the raw path.
  test("raw dumps paint consensus-* classes from container-offset classifications", async ({
    browser,
  }) => {
    const context = await browser.newContext();
    const page = await context.newPage();

    await enterWorkspaceWithMsl(page, GDB_RAW);
    await waitForHexBytes(page);

    // Sanity: this dump must NOT take the .msl branch, otherwise the test
    // would be a duplicate of the one above rather than covering the raw path.
    const format = await page.evaluate(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (window as any).__useHexStore.getState().format as string;
    });
    expect(format, "gdb_raw.bin must load as a non-msl dump").not.toBe("msl");

    await page.evaluate((codes) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const store = (window as any).__useConsensusStore;
      store.setState({
        available: true,
        size: 1024,
        numDumps: 2,
        overlayEnabled: true,
        // Row-aligned CONTAINER offset — the raw-branch key.
        pageClassifications: new Map([[0, codes]]),
      });
    }, ROW_CLASSIFICATIONS);
    await page.waitForTimeout(500);

    const byte0 = page.locator('[data-offset="0"][data-col="hex"]').first();
    const byte1 = page.locator('[data-offset="1"][data-col="hex"]').first();
    const byte2 = page.locator('[data-offset="2"][data-col="hex"]').first();
    const byte3 = page.locator('[data-offset="3"][data-col="hex"]').first();

    await expect(byte0).toHaveClass(/consensus-invariant/);
    await expect(byte1).toHaveClass(/consensus-structural/);
    await expect(byte2).toHaveClass(/consensus-pointer/);
    await expect(byte3).toHaveClass(/consensus-key-candidate/);

    await page.evaluate(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (window as any).__useConsensusStore.setState({ overlayEnabled: false });
    });
    await page.waitForTimeout(500);

    await expect(byte0).not.toHaveClass(/consensus-invariant/);
    await expect(byte1).not.toHaveClass(/consensus-structural/);
    await expect(byte2).not.toHaveClass(/consensus-pointer/);
    await expect(byte3).not.toHaveClass(/consensus-key-candidate/);

    await context.close();
  });
});
