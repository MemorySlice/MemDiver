/**
 * E2E for the multi-dump hex workspace: two dumps, two aligned panes.
 *
 * The fixture pair is REAL, and deliberately hostile to a naive implementation.
 * `tests/e2e/fixtures/aslr_msl/` holds two ASLR-shifted `.msl` captures of the
 * "same" process in which TWO regions move by DIFFERENT run-to-run deltas
 * (0x1000 for the extra region, 0x10000000 for the heap). A viewer that carries
 * one scalar VA delta per dump cannot line them up, so an alignment bug here is
 * visible rather than theoretical.
 *
 * The flagship assertion is §5: on EVERY rendered virtual row, EVERY pane must
 * be showing the same offset. `MultiHexViewer` computes one `rowOffset` per
 * virtual row and hands the identical value to every pane, so the property is
 * structural — but "structural" is a claim about the code, and this spec is the
 * claim about the DOM. It is checked twice, before and after a scroll, because
 * a mirrored-scroll regression satisfies it on a still frame and violates it
 * mid-flight.
 *
 * Note on the toolbar label: `HexToolbar`'s file name is a `flex-1 truncate`
 * span that the view-mode tabs, the go-to box and the find box squeeze to ZERO
 * pixels at the default 1280px viewport (the main panel is 572px wide and those
 * three groups occupy 542px of it). That is true of the SINGLE-dump viewer too,
 * so it is not a multi-dump regression — but it does mean the label's content,
 * not its visibility, is what §6 can assert.
 *
 * Note on the view mode: the panes are driven in "Memory (VAS)", not the
 * default "Raw file". `POST /api/analysis/consensus/aligned-window` rejects
 * `view="raw"` for an `.msl` anchor outright ("view='raw' names a block header
 * inside an .msl container, not the byte at that address"), so raw is not a
 * coordinate in which N dumps can be aligned at all. The switch is part of the
 * flow under test, not a workaround for a flaky assertion.
 */
import { test, expect, type Page } from "@playwright/test";
import {
  aslrMslPairAvailable,
  aslrMslRun1Path,
  aslrMslRun2Path,
} from "../fixtures/dataset";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

const RUN_1 = "run_1.msl";
const RUN_2 = "run_2.msl";

/** Dump ids are `crypto.randomUUID()`, so every per-dump testid is dynamic. */
async function dumpIdByName(page: Page, name: string): Promise<string> {
  const row = page.locator('[data-testid="dump-row"]').filter({ hasText: name }).first();
  await expect(row).toBeVisible({ timeout: 15_000 });
  const id = await row.getAttribute("data-dump-id");
  expect(id, `the ${name} row must carry data-dump-id`).toBeTruthy();
  return id as string;
}

/**
 * `HexToolbar`'s "<name> — <size> KB" label. It reports `hex-store.dumpPath`,
 * i.e. the ANCHOR dump, which is what makes it a readout of pane focus.
 */
function toolbarFileLabel(page: Page) {
  return page.locator("span.md-text-secondary.truncate.flex-1").first();
}

/** Add a second dump through the Dumps-tab server-path input. */
async function addDumpByPath(page: Page, dumpPath: string): Promise<void> {
  const addInput = page.getByPlaceholder("Server path to dump file");
  await expect(addInput).toBeVisible({ timeout: 15_000 });
  await addInput.fill(dumpPath);
  await addInput.press("Enter");
}

/**
 * Session dump A + dump B added by server path, in the VAS coordinate, with the
 * side-by-side layout mounted. Returns both dump ids.
 */
async function twoDumpsSideBySide(page: Page): Promise<{ id1: string; id2: string }> {
  await enterWorkspaceWithMsl(page, aslrMslRun1Path);
  await page.getByRole("tab", { name: "Memory (VAS)" }).click();
  await page.locator(tab("dumps")).first().click();
  await addDumpByPath(page, aslrMslRun2Path);
  const id1 = await dumpIdByName(page, RUN_1);
  const id2 = await dumpIdByName(page, RUN_2);
  await page.getByTestId("main-view-sideBySide").click();
  await expect(page.getByTestId("multi-hex-viewer")).toBeVisible({ timeout: 20_000 });
  return { id1, id2 };
}

interface RowProbe {
  /** `data-row-offset` of every rendered virtual row, in DOM order. */
  rowOffsets: string[];
  /** Panes seen per row. */
  paneCounts: number[];
  /** Human-readable description of every misalignment found. */
  problems: string[];
}

/**
 * Walk every rendered virtual row and compare what each pane is ACTUALLY
 * showing — the `data-offset` of its first hex cell and the text of its offset
 * gutter — against the row's single `data-row-offset`.
 *
 * Reading the byte cells rather than a prop mirror is deliberate: `HexRow`
 * carries no testid of its own, and the question worth answering is whether the
 * bytes on screen are at the same address, not whether a prop was passed.
 */
async function probeRowAlignment(page: Page): Promise<RowProbe> {
  return page.evaluate(() => {
    const problems: string[] = [];
    const rowOffsets: string[] = [];
    const paneCounts: number[] = [];

    document.querySelectorAll("[data-row-offset][data-index]").forEach((row) => {
      const expected = row.getAttribute("data-row-offset") ?? "MISSING";
      rowOffsets.push(expected);

      const panes = row.querySelectorAll("[data-pane-id]");
      paneCounts.push(panes.length);

      const gutters = new Set<string>();
      panes.forEach((pane) => {
        const paneId = pane.getAttribute("data-pane-id") ?? "?";
        const firstCell = pane.querySelector('.hex-byte[data-col="hex"]');
        const got = firstCell ? firstCell.getAttribute("data-offset") : "NO-BYTE-CELLS";
        if (got !== expected) {
          problems.push(`row ${expected}: pane ${paneId} starts at ${got}`);
        }
        gutters.add((pane.querySelector(".hex-offset")?.textContent ?? "MISSING").trim());
      });

      if (gutters.size > 1) {
        problems.push(`row ${expected}: offset gutters disagree — ${[...gutters].join(" vs ")}`);
      }
    });

    return { rowOffsets, paneCounts, problems };
  });
}

test.describe("multi-dump side-by-side panes", () => {
  test.skip(!aslrMslPairAvailable, "ASLR .msl fixture pair missing");

  test("two dumps line up byte-for-byte in two panes, before and after a scroll", async ({
    page,
  }) => {
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);

    // --- 1. Dump A is the session dump; the wizard registers it in the store.
    await enterWorkspaceWithMsl(page, aslrMslRun1Path);

    // --- 3a. The multi-dump layouts are DISABLED but PRESENT at one dump.
    // A control that vanishes is undiscoverable, which is half of "I loaded a
    // second dump and nothing in the UI changed". Assert the disabled state as
    // its own guarantee, not as a stepping stone.
    const sideBySide = page.getByTestId("main-view-sideBySide");
    const overlay = page.getByTestId("main-view-overlay");
    await expect(sideBySide).toBeVisible({ timeout: 20_000 });
    await expect(overlay).toBeVisible();
    await expect(sideBySide).toBeDisabled();
    await expect(sideBySide).toHaveAttribute("aria-disabled", "true");
    await expect(sideBySide).toHaveAttribute("title", /at least 2 dumps/i);
    await expect(page.getByTestId("main-view-single")).toHaveAttribute(
      "aria-selected",
      "true",
    );

    // The aligned-window endpoint has no notion of ".msl container offset", so
    // put the session in the VAS coordinate before adding the second dump.
    await page.getByRole("tab", { name: "Memory (VAS)" }).click();
    await expect(page.getByRole("tab", { name: "Memory (VAS)" })).toHaveAttribute(
      "aria-selected",
      "true",
    );

    // --- 1b/2. Add dump B via the Dumps tab's server-path input.
    await page.locator(tab("dumps")).first().click();
    await addDumpByPath(page, aslrMslRun2Path);

    const id1 = await dumpIdByName(page, RUN_1);
    const id2 = await dumpIdByName(page, RUN_2);
    expect(id1).not.toBe(id2);

    // --- 2. Both dumps are listed, both take part, exactly one is the origin.
    await expect(page.locator('[data-testid="dump-row"]')).toHaveCount(2);
    await expect(page.getByTestId(`dump-select-${id1}`)).toBeChecked();
    await expect(page.getByTestId(`dump-select-${id2}`)).toBeChecked();
    await expect(page.getByTestId("dump-selection-count")).toHaveText("2 of 2 selected");
    await expect(page.getByTestId(`dump-origin-${id1}`)).toHaveText("ORIGIN");
    await expect(page.getByTestId(`dump-origin-${id2}`)).toHaveCount(0);

    // --- 3b. Two selected dumps enable the layout, and the label names the
    // pane count so the user is not guessing what "side by side" will produce.
    await expect(sideBySide).toBeEnabled();
    await expect(sideBySide).not.toHaveAttribute("aria-disabled", "true");
    await expect(sideBySide).toHaveText("Side by side (2)");

    // --- 4. Two panes render.
    await sideBySide.click();
    await expect(page.getByTestId("multi-hex-viewer")).toBeVisible({ timeout: 20_000 });
    await expect(page.getByTestId(`hex-pane-header-${id1}`)).toBeVisible();
    await expect(page.getByTestId(`hex-pane-header-${id2}`)).toBeVisible();
    await expect(page.locator('[data-testid^="hex-pane-header-"]')).toHaveCount(2);

    // Bytes must actually arrive — an alignment check over two panes of "--"
    // would pass while showing nothing.
    await expect(
      page.locator(`[data-testid="hex-pane-${id1}"] .hex-byte[data-col="hex"]`).first(),
    ).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 30_000 });
    await expect(
      page.locator(`[data-testid="hex-pane-${id2}"] .hex-byte[data-col="hex"]`).first(),
    ).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 30_000 });
    // --- 5. THE flagship assertion, take one: every pane, every rendered row.
    const before = await probeRowAlignment(page);
    expect(before.rowOffsets.length, "no virtual rows rendered").toBeGreaterThan(0);
    expect(new Set(before.paneCounts), "every row must carry both panes").toEqual(
      new Set([2]),
    );
    expect(before.problems, "panes disagree about the offset they are showing").toEqual([]);

    // --- 5b. Scroll, then re-assert. A static-only check would miss drift.
    const scroller = page.getByTestId("multi-hex-scroll");
    await scroller.evaluate((el) => {
      el.scrollTop = 1_600;
      el.dispatchEvent(new Event("scroll"));
    });
    const firstBefore = before.rowOffsets[0];
    await page.waitForFunction(
      (previousFirst) => {
        const first = document.querySelector("[data-row-offset][data-index]");
        return first !== null && first.getAttribute("data-row-offset") !== previousFirst;
      },
      firstBefore,
      { timeout: 20_000 },
    );

    const after = await probeRowAlignment(page);
    expect(after.rowOffsets.length).toBeGreaterThan(0);
    expect(
      after.rowOffsets[0],
      "the scroll must actually have moved the rendered window",
    ).not.toBe(firstBefore);
    expect(new Set(after.paneCounts)).toEqual(new Set([2]));
    expect(after.problems, "panes drifted apart during a scroll").toEqual([]);

    // --- 6. Clicking a pane focuses it, and the toolbar follows the anchor.
    await expect(page.getByTestId(`hex-pane-header-${id1}`)).toHaveAttribute(
      "aria-current",
      "true",
    );
    await expect(toolbarFileLabel(page)).toHaveText(new RegExp(`^${RUN_1} — `));

    await page.locator(`[data-testid="hex-pane-${id2}"]`).first().click();
    await expect(page.getByTestId(`hex-pane-header-${id2}`)).toHaveAttribute(
      "aria-current",
      "true",
    );
    await expect(page.getByTestId(`hex-pane-header-${id1}`)).not.toHaveAttribute(
      "aria-current",
      "true",
    );
    await expect(toolbarFileLabel(page)).toHaveText(new RegExp(`^${RUN_2} — `), {
      timeout: 15_000,
    });

    // --- 7. Dropping back to one selected dump degrades the layout (I4).
    await page.locator(tab("dumps")).first().click();
    await page.getByTestId(`dump-select-${id2}`).uncheck();
    await expect(page.getByTestId("dump-selection-count")).toHaveText("1 of 2 selected");
    await expect(page.getByTestId("main-view-single")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(sideBySide).toHaveAttribute("aria-selected", "false");
    await expect(sideBySide).toBeDisabled();
    await expect(page.getByTestId("multi-hex-viewer")).toHaveCount(0);
    await expect(page.locator('[data-testid^="hex-pane-header-"]')).toHaveCount(0);
    // …and the single viewer is what remains, still showing bytes.
    await expect(page.locator(".hex-byte").first()).toBeVisible({ timeout: 20_000 });

    // Only the 5xx channel is asserted here. The console channel currently
    // carries the 400s from the past-the-end prefetch, which the dedicated test
    // below pins on its own rather than as a side effect of this one.
    expect(guards.serverErrors).toEqual([]);
  });


  /**
   * RED against the current build — it pins a real product bug, and must not be
   * relaxed to make the suite green.
   *
   * `chunkRangeForRows` (frontend/src/components/hex/multi-window-utils.ts:89)
   * widens the visible rows by `prefetchChunksForPaneCount(n)` chunks on EACH
   * side and clamps only the LOW end at 0. With two panes that is 2 chunks of
   * 8 KiB ahead, so an 8192-byte addressable window makes the loader ask for
   * offsets 8192 and 16384, which
   * `POST /api/analysis/consensus/aligned-window` rejects:
   *
   *   400 {"error":"anchor offset does not name an addressable byte",
   *        "category":"INVALID_INPUT"}
   *
   * Two consequences, both user-visible:
   *
   *  1. `multi-hex-store.ensureLoaded`'s catch block scopes the failure to
   *     "the panes it was requested for" — which is EVERY selected pane — so
   *     one out-of-range prefetch makes both pane headers read
   *     "Could not load <name>: {\"error\":…}" while the bytes on screen are
   *     perfectly correct. The raw JSON envelope is shown verbatim.
   *  2. Nothing clears that error once a later in-range chunk lands.
   *
   * It is not a small-file artefact: the same prefetch runs off the end of any
   * dump as soon as the user scrolls to the last screen.
   */
  test("the pane loader must not request a window past the end of the dump", async ({
    page,
  }) => {
    test.setTimeout(120_000);

    const rejected: string[] = [];
    page.on("response", async (resp) => {
      if (resp.status() !== 400) return;
      if (!resp.url().includes("/api/analysis/consensus/aligned-window")) return;
      let body = "";
      try {
        body = (await resp.text()).slice(0, 160);
      } catch {
        body = "<unreadable>";
      }
      rejected.push(body);
    });

    const { id1, id2 } = await twoDumpsSideBySide(page);

    // Let the visible window AND its prefetch settle.
    await expect(
      page.locator(`[data-testid="hex-pane-${id1}"] .hex-byte[data-col="hex"]`).first(),
    ).toHaveText(/^[0-9a-f]{2}$/i, { timeout: 30_000 });
    await page.waitForTimeout(2_500);

    await expect(page.getByTestId(`hex-pane-header-${id1}`)).not.toContainText(
      "Could not load",
    );
    await expect(page.getByTestId(`hex-pane-header-${id2}`)).not.toContainText(
      "Could not load",
    );
    expect(
      rejected,
      "the loader asked the backend for a window past the end of the dump",
    ).toEqual([]);
  });
});
