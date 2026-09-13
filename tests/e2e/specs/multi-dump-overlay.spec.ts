/**
 * E2E for the aligned OVERLAY view: N dumps superimposed, byte by byte.
 *
 * Runs on the same committed ASLR-shifted `.msl` pair as
 * `multi-dump-panes.spec.ts` (see that file's header for why the pair is built
 * the way it is). The two runs are padded with 0x00 and 0xFE respectively, so
 * essentially every aligned byte disagrees — which makes the `cross-dump-differs`
 * ring a fact about the corpus rather than a hope. If no byte carries it, the
 * differ plumbing is broken and this spec must fail, not be relaxed.
 *
 * The alignment assertion is the point of the whole view. These are native
 * `.msl` captures with module metadata, so `build_from_sources` routes them to
 * MODULE-OFFSET alignment; `file_offset` here would mean the panes were stacked
 * by raw position, i.e. "the same byte index in two different files", which is
 * the silent-misalignment failure `HexAlignmentChip` exists to prevent.
 *
 * View mode: as in the panes spec, the aligned-window endpoint refuses
 * `view="raw"` for an `.msl` anchor, so the session is put in "Memory (VAS)"
 * before a second dump joins it.
 */
import { test, expect, type Page } from "@playwright/test";
import {
  aslrMslPairAvailable,
  aslrMslRun1Path,
  aslrMslRun2Path,
} from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
  installErrorGuards,
} from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

const RUN_1 = "run_1.msl";
const RUN_2 = "run_2.msl";

/** A byte offset well inside the first captured page, on a row boundary. */
const INSPECT_OFFSET = 32;

async function dumpIdByName(page: Page, name: string): Promise<string> {
  const row = page.locator('[data-testid="dump-row"]').filter({ hasText: name }).first();
  await expect(row).toBeVisible({ timeout: 15_000 });
  const id = await row.getAttribute("data-dump-id");
  expect(id, `the ${name} row must carry data-dump-id`).toBeTruthy();
  return id as string;
}

/**
 * Count painted bytes per consensus class INSIDE the scroller.
 *
 * `HexOverlayPane`'s legend swatches carry the very same class names, so a
 * document-wide `.consensus-invariant` selector would report a legend as
 * evidence that bytes were painted.
 */
async function paintedClassCounts(page: Page): Promise<Record<string, number>> {
  return page.evaluate(() => {
    const scroller = document.querySelector('[data-testid="hex-overlay-scroll"]');
    const names = [
      "consensus-invariant",
      "consensus-structural",
      "consensus-pointer",
      "consensus-key-candidate",
      "cross-dump-differs",
    ];
    const out: Record<string, number> = {};
    for (const name of names) {
      out[name] = scroller ? scroller.querySelectorAll(`.hex-byte.${name}`).length : -1;
    }
    out["hex-byte"] = scroller ? scroller.querySelectorAll(".hex-byte").length : -1;
    return out;
  });
}

test.describe("multi-dump aligned overlay", () => {
  test.skip(!aslrMslPairAvailable, "ASLR .msl fixture pair missing");

  test("consensus over 2 dumps paints classified, differing bytes and names the alignment", async ({
    page,
  }) => {
    test.setTimeout(150_000);
    const guards = installErrorGuards(page);

    await enterWorkspaceWithMsl(page, aslrMslRun1Path);

    // The aligned-window endpoint has no ".msl container offset" coordinate.
    await page.getByRole("tab", { name: "Memory (VAS)" }).click();

    await page.locator(tab("dumps")).first().click();
    const addInput = page.getByPlaceholder("Server path to dump file");
    await expect(addInput).toBeVisible({ timeout: 15_000 });
    await addInput.fill(aslrMslRun2Path);
    await addInput.press("Enter");

    const id1 = await dumpIdByName(page, RUN_1);
    const id2 = await dumpIdByName(page, RUN_2);

    // --- 1. Run the consensus over the SELECTION, from the Dumps tab. The
    // button only exists in exploration mode, and its label names its scope.
    await switchToExplorationMode(page);
    await page.locator(tab("dumps")).first().click();
    const runConsensus = page.getByTestId("dump-run-consensus");
    await expect(runConsensus).toHaveText("Run consensus on 2 dumps");
    await expect(runConsensus).toBeEnabled();
    await runConsensus.click();
    await expect(runConsensus).toHaveText("Run consensus on 2 dumps", {
      timeout: 90_000,
    });

    // --- 2. Switch to Overlay. A consensus exists, so the empty state must be
    // gone and the live pane mounted.
    const overlayTab = page.getByTestId("main-view-overlay");
    await expect(overlayTab).toBeEnabled();
    await overlayTab.click();
    await expect(page.getByTestId("hex-overlay-pane")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId("hex-overlay-no-consensus")).toHaveCount(0);

    // --- 5. The alignment is stated in words, and it is MODULE offset.
    // `.msl` captures carry a module map, so file-offset stacking here would be
    // the silent-misalignment bug, not a lesser-but-acceptable answer.
    const alignmentMethod = page.getByTestId("hex-alignment-method");
    await expect(alignmentMethod).toHaveAttribute("data-method", "module_offset", {
      timeout: 30_000,
    });
    await expect(alignmentMethod).toHaveText("Aligned by module offset");
    await expect(page.getByTestId("hex-alignment-file-offset-warning")).toHaveCount(0);
    await expect(page.getByTestId("hex-overlay-raw-offset")).toHaveCount(0);

    // Bytes have to be on screen before anything can be painted on them.
    await expect(
      page.locator('[data-testid="hex-overlay-scroll"] .hex-byte[data-offset="0"]'),
    ).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 30_000 });

    // --- 3. Consensus classes reach real byte cells, and --- 4. at least one
    // byte is ringed as differing across the dumps. The pair pads run 1 with
    // 0x00 and run 2 with 0xFE, so an empty differ set is a REAL BUG.
    await expect(
      page.locator('[data-testid="hex-overlay-scroll"] .hex-byte.cross-dump-differs').first(),
    ).toBeVisible({ timeout: 30_000 });

    const counts = await paintedClassCounts(page);
    expect(counts["hex-byte"]).toBeGreaterThan(0);
    const classified =
      counts["consensus-invariant"] +
      counts["consensus-structural"] +
      counts["consensus-pointer"] +
      counts["consensus-key-candidate"];
    expect(
      classified,
      `no byte carries a consensus-* class: ${JSON.stringify(counts)}`,
    ).toBeGreaterThan(0);
    expect(
      counts["cross-dump-differs"],
      `two dumps padded 0x00 vs 0xFE must differ somewhere: ${JSON.stringify(counts)}`,
    ).toBeGreaterThan(0);

    // --- 6. Clicking a byte lists it across EVERY selected dump, with the
    // anchor called out. This is the only place the overlay answers "which
    // dumps disagree here", so it is the panel the ring points at.
    await page
      .locator(`[data-testid="hex-overlay-scroll"] .hex-byte[data-offset="${INSPECT_OFFSET}"]`)
      .first()
      .click();

    const inspector = page.getByTestId("overlay-byte-inspector");
    await expect(inspector).toBeVisible();
    await expect(page.getByTestId("overlay-inspector-summary")).toContainText("0x0000_0020");
    await expect(page.locator('[data-testid^="overlay-inspector-row-"]')).toHaveCount(2);
    await expect(page.getByTestId(`overlay-inspector-row-${id1}`)).toBeVisible();
    await expect(page.getByTestId(`overlay-inspector-row-${id2}`)).toBeVisible();

    // run_1 is the session origin and the focused dump, so it anchors the
    // comparison; exactly one row may claim that.
    await expect(page.getByTestId(`overlay-inspector-anchor-${id1}`)).toHaveText("(anchor)");
    await expect(page.locator('[data-testid^="overlay-inspector-anchor-"]')).toHaveCount(1);
    await expect(page.getByTestId(`overlay-inspector-row-${id1}`)).toHaveAttribute(
      "data-differs",
      "false",
    );
    await expect(page.getByTestId(`overlay-inspector-row-${id2}`)).toHaveAttribute(
      "data-differs",
      "true",
    );
    await expect(page.getByTestId("overlay-inspector-differ-count")).toHaveText(
      "1 of 2 dumps differ",
    );

    // 5xx only: the console channel currently carries the 400s from the
    // multi-hex loader's past-the-end prefetch, which
    // multi-dump-panes.spec.ts pins directly.
    expect(guards.serverErrors).toEqual([]);
  });
});
