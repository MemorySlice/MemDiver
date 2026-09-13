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
import {
  cursorOffset,
  enterAlignedOverlay,
  OVERLAY_SETUP_TIMEOUT,
  type AlignedOverlayHandles,
} from "../fixtures/overlay";
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

/**
 * ── The overlay's BROWSE surface, end to end in a real browser ──────────────
 *
 * Everything below shares ONE consensus build. Standing the overlay up costs a
 * wizard run, a second dump and a real `POST /api/analysis/consensus`, and
 * paying that five times would make these tests the slowest thing in the suite
 * for no extra coverage — every assertion here is about the SAME painted
 * window. `mode: "serial"` is therefore not a convenience, it is the contract:
 * each test restores the state it changed so the next one starts from the same
 * screen, and the LAST one is the only one that leaves the VA coordinate.
 *
 * ── What this fixture can and cannot show, measured rather than assumed ─────
 * The committed ASLR pair aligns to 8192 bytes (two page slices) padded 0x00 in
 * run 1 and 0xFE in run 2, so the consensus classifies EVERY byte of it
 * `key_candidate` and the regions endpoint returns exactly ONE region per
 * category — `Key Candidate 8,192 bytes`, `Invariant —`, `Structural —`,
 * `Pointer —`. That is a real property of the corpus, not a defect, and it has
 * two consequences the tests below state out loud rather than paper over:
 *
 *   - there is exactly ONE occurrence to walk, so `n`'s "advance to the NEXT
 *     one" cannot be demonstrated here; the single-occurrence contract (jump,
 *     then clamp) is asserted instead and the test says which branch it took.
 *   - in "Memory (VAS)" the anchor's file IS the aligned build, so no cell can
 *     be absent. The VA coordinate is where the void vocabulary is reachable —
 *     at offset 0x1000 the heap's FAILED second page renders as `byte-gap`
 *     beside classified bytes — which is why the void test, and only the void
 *     test, switches coordinate.
 */
test.describe("aligned overlay: browse, keyboard, render modes, rail, void", () => {
  test.describe.configure({ mode: "serial" });
  test.skip(!aslrMslPairAvailable, "ASLR .msl fixture pair missing");

  /** Chip id → the class `HexRow` paints on a byte of that class. */
  const CHIP_BYTE_CLASS: Record<string, string> = {
    invariant: "consensus-invariant",
    structural: "consensus-structural",
    pointer: "consensus-pointer",
    key_candidate: "consensus-key-candidate",
  };
  /** What the `Changing` union chip covers — `core.variance`'s three bands. */
  const UNION_BYTE_CLASSES = [
    "consensus-structural",
    "consensus-pointer",
    "consensus-key-candidate",
  ];
  /** The four "there is no byte here" classes, from `utils/absence-classes`. */
  const ABSENCE_CLASSES = ["byte-gap", "byte-absent", "byte-error", "hex-loading"];
  /** Everything that means "this byte is a finding" — never on a void cell. */
  const PRESENCE_CLASSES = [
    "consensus-invariant",
    "consensus-structural",
    "consensus-pointer",
    "consensus-key-candidate",
    "cross-dump-differs",
    "variant-1",
    "variant-2",
    "variant-3",
    "variant-4",
    "variant-5",
  ];
  /** The heap's FAILED second page, in the VA coordinate. See the header. */
  const VA_VOID_OFFSET = 4096;

  let page: Page;
  let ids: AlignedOverlayHandles;

  test.beforeAll(async ({ browser }) => {
    test.setTimeout(OVERLAY_SETUP_TIMEOUT);
    page = await browser.newPage();
    ids = await enterAlignedOverlay(page);
  });

  test.afterAll(async () => {
    await page?.close();
  });

  /** The classes on the byte cell at `offset`, or `null` if it is not rendered. */
  async function cellClassesAt(offset: number): Promise<string[] | null> {
    return page.evaluate((off) => {
      const cell = document.querySelector(
        `[data-testid="hex-overlay-scroll"] .hex-byte[data-offset="${off}"]`,
      );
      return cell ? Array.from(cell.classList) : null;
    }, offset);
  }

  /** The hex store's selection — `anchor` is where a region jump started. */
  async function selectionRange(): Promise<{ anchor: number; active: number } | null> {
    return page.evaluate(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (window as any).__useHexStore.getState().selection ?? null;
    });
  }

  /** The printed text of the first `n` byte cells — "which bytes are painted". */
  async function paintedText(n = 256): Promise<string> {
    return page.evaluate((count) => {
      const cells = document.querySelectorAll(
        '[data-testid="hex-overlay-scroll"] .hex-byte',
      );
      const out: string[] = [];
      for (let i = 0; i < Math.min(count, cells.length); i++) {
        out.push(cells[i].textContent ?? "");
      }
      return out.join(" ");
    }, n);
  }

  /** Every chip's accessible text — label + whole-build count. */
  async function chipTexts(): Promise<Record<string, string>> {
    return page.evaluate(() => {
      const out: Record<string, string> = {};
      document
        .querySelectorAll('[data-testid^="hex-overlay-class-chip-"]')
        .forEach((el) => {
          const id = el.getAttribute("data-testid")!.replace("hex-overlay-class-chip-", "");
          out[id] = (el.textContent ?? "").replace(/\s+/g, " ").trim();
        });
      return out;
    });
  }

  /** Ramp tints (`variant-1…5`) and the glyph marks, inside the scroller. */
  async function paintedRampCounts(): Promise<{
    ramp: number;
    identicalGlyph: number;
    voidGlyph: number;
    digitGlyph: number;
  }> {
    return page.evaluate(() => {
      const scroller = document.querySelector('[data-testid="hex-overlay-scroll"]');
      if (!scroller) return { ramp: -1, identicalGlyph: -1, voidGlyph: -1, digitGlyph: -1 };
      let ramp = 0;
      for (let step = 1; step <= 5; step++) {
        ramp += scroller.querySelectorAll(`.hex-byte.variant-${step}`).length;
      }
      let identicalGlyph = 0;
      let voidGlyph = 0;
      let digitGlyph = 0;
      scroller.querySelectorAll(".hex-byte").forEach((cell) => {
        const text = (cell.textContent ?? "").trim();
        if (text === "■") identicalGlyph++;
        else if (text === "░") voidGlyph++;
        else if (/^[2-6]$/.test(text)) digitGlyph++;
      });
      return { ramp, identicalGlyph, voidGlyph, digitGlyph };
    });
  }

  /** Sum of the four backend consensus classes actually painted on bytes. */
  function classifiedCount(counts: Record<string, number>): number {
    return (
      counts["consensus-invariant"] +
      counts["consensus-structural"] +
      counts["consensus-pointer"] +
      counts["consensus-key-candidate"]
    );
  }

  /**
   * Click a category chip and wait for its page of regions to SETTLE.
   *
   * Settled means: not loading, and the browser has committed to an answer —
   * a list, "no region of this class", or an error. Polling on the row count
   * alone would race the request and read the PREVIOUS category's page.
   *
   * Returns the number of JUMPABLE rows (`tabIndex=0`, i.e. `isJumpable` and a
   * jumpable page); an inert row is not an occurrence anything can navigate to.
   */
  async function selectChip(chip: string): Promise<number> {
    await page.getByTestId(`hex-overlay-class-chip-${chip}`).click();
    await expect(page.getByTestId(`hex-overlay-class-chip-${chip}`)).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    // Selecting a class REVEALS the list; a chip that quietly did nothing would
    // look identical otherwise.
    await expect(page.getByTestId("overlay-detail-tab-regions")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(page.getByTestId("variance-class-browser")).toBeVisible();

    await expect
      .poll(
        async () =>
          page.evaluate(() => {
            const q = (sel: string) => document.querySelector(sel) !== null;
            if (q('[data-testid="variance-class-browser-loading"]')) return "loading";
            if (q('[data-testid="variance-class-browser-error"]')) return "error";
            if (q('[data-testid="variance-class-browser-empty"]')) return "empty";
            if (q('[data-testid="variance-class-browser-list"]')) return "list";
            return "loading";
          }),
        { timeout: 45_000, message: `regions for '${chip}' never settled` },
      )
      .not.toBe("loading");

    return page.locator('[data-testid="variance-region-row"][tabindex="0"]').count();
  }

  /**
   * The first category chip that yields at least one jumpable occurrence, with
   * the byte class(es) a jump into it must land on.
   *
   * Single-class chips come first because their landing class is exactly
   * predictable. `Changing` is the fallback and is the UNION, so the honest
   * assertion there is membership of the three non-invariant bands — still
   * strong enough to catch a jump onto an invariant or unclassified byte.
   */
  async function firstPopulatedChip(): Promise<{ chip: string; expected: string[] } | null> {
    for (const chip of Object.keys(CHIP_BYTE_CLASS)) {
      if ((await selectChip(chip)) > 0) return { chip, expected: [CHIP_BYTE_CLASS[chip]] };
    }
    if ((await selectChip("non_invariant")) > 0) {
      return { chip: "non_invariant", expected: UNION_BYTE_CLASSES };
    }
    return null;
  }

  // ── (a) CLICK TO JUMP ─────────────────────────────────────────────────────
  //
  // The coordinate check alone is not enough, and that is the whole point of
  // this test: a jump that lands on the wrong byte still satisfies an
  // offset-equality check (the store simply copied the number through), and the
  // only thing that catches it is asking what CLASS the byte it landed on
  // turned out to be. That is the defect class that produced this session's
  // `---` bands.
  test("clicking a category chip then a region row lands on a byte OF THAT CLASS", async () => {
    test.setTimeout(120_000);

    const chosen = await firstPopulatedChip();
    expect(
      chosen,
      "no category chip yields a jumpable region over the ASLR pair — the browse surface is unreachable",
    ).not.toBeNull();

    const rows = page.locator('[data-testid="variance-region-row"][tabindex="0"]');
    const firstRow = rows.first();
    await expect(firstRow).toBeVisible();

    const anchorAttr = await firstRow.getAttribute("data-anchor-offset");
    const anchorOffset = Number(anchorAttr);
    expect(
      Number.isInteger(anchorOffset) && anchorOffset >= 0,
      `a jumpable row must carry a real anchor offset, got ${anchorAttr}`,
    ).toBe(true);

    await firstRow.click();
    await expect(firstRow).toHaveAttribute("aria-current", "true");

    // 1. The row's `anchor_offset` reaches the viewer UNMODIFIED. The selection
    // ANCHOR is where the jump started — the server-supplied number, passed
    // through with no client-side arithmetic, which is the invariant
    // `consensus-regions.ts` Fact 1 exists to protect.
    //
    // (`cursorOffset` is asserted separately, by the test below that owns the
    // cursor rule; here the ANCHOR is the thing that pins the pass-through.)
    await expect
      .poll(async () => (await selectionRange())?.anchor ?? null, {
        timeout: 20_000,
        message: "the jump must select from the row's own anchor_offset",
      })
      .toBe(anchorOffset);

    // 2. …and the byte the viewer landed on really IS of the class that was
    // asked for. Polled because the jump can slide the bounded window and the
    // new chunk has to land before the cell carries anything at all.
    await expect
      .poll(
        async () => {
          const classes = await cellClassesAt(anchorOffset);
          if (!classes) return "not-rendered";
          const hit = chosen!.expected.find((c) => classes.includes(c));
          return hit ?? `wrong-class: ${classes.join(" ")}`;
        },
        {
          timeout: 30_000,
          message: `jumped to 0x${anchorOffset.toString(16)} for '${chosen!.chip}' but the byte there is not of that class`,
        },
      )
      .toMatch(/^consensus-/);

    // The announce line is the only feedback a screen-reader user gets for a
    // scroll two panes away, so it has to actually say where the jump went.
    await expect(page.getByTestId("variance-class-browser-status")).toContainText(
      `0x${anchorOffset.toString(16).padStart(8, "0")}`,
    );
  });

  /**
   * THE CURSOR RULE — was a product bug, now the pinned contract.
   *
   * `variance-regions-store.jumpToIndex` used to scroll to `anchor_offset` and
   * then compose `startSelection(anchor_offset)` +
   * `extendSelection(anchor_offset_end - 1)`. `hex-store.extendSelection` moves
   * `cursorOffset` to the selection's ACTIVE end, so the cursor finished on the
   * region's LAST byte while the viewport sat at its FIRST. On this fixture's
   * single 8192-byte region the cursor landed at 0x1fff — 511 rows below
   * anything on screen — and the status footer's `Agreement k/N` and the whole
   * Byte inspector described a byte the analyst never navigated to and could
   * not see. It was inconsistent too: a region with `anchor_contiguous ===
   * false` takes no selection and always DID leave the cursor on
   * `anchor_offset`.
   *
   * The jump now applies its selection with `hex-store.selectRange`, which does
   * not move the cursor, so BOTH branches land on the region's first byte.
   * `extendSelection`'s own contract is untouched — the grid's drag gesture
   * still needs the cursor to track the active end.
   */
  test(
    "a region jump leaves the cursor ON the region's first byte",
    async () => {
      const chosen = await firstPopulatedChip();
      expect(chosen).not.toBeNull();
      const firstRow = page.locator('[data-testid="variance-region-row"][tabindex="0"]').first();
      const anchorOffset = Number(await firstRow.getAttribute("data-anchor-offset"));
      await firstRow.click();
      await expect.poll(() => cursorOffset(page), { timeout: 20_000 }).toBe(anchorOffset);
    },
  );

  // ── (b) KEYBOARD ──────────────────────────────────────────────────────────
  test("n / p walk the occurrences from a focused chip, and n is inert in the goto field", async () => {
    test.setTimeout(120_000);

    // Force a FRESH page so `activeIndex` starts at -1 and the first `n` is a
    // real "go to the first occurrence" rather than a step from wherever (a)
    // left the list cursor.
    await selectChip("invariant");
    const chosen = await firstPopulatedChip();
    expect(chosen, "no category yields a jumpable region to walk").not.toBeNull();
    const jumpable = await page
      .locator('[data-testid="variance-region-row"][tabindex="0"]')
      .count();

    const chipButton = page.getByTestId(`hex-overlay-class-chip-${chosen!.chip}`);
    await chipButton.focus();
    await expect(chipButton).toBeFocused();
    // Enter ACTIVATES the chip — the keyboard equivalent of the click in (a).
    await page.keyboard.press("Enter");
    await expect(chipButton).toHaveAttribute("aria-pressed", "true");

    // `n` / `p` are bound on the overlay PANE, so they fire while focus is
    // still on the chip — which is what lets a keyboard user walk the list
    // without first hunting for the grid.
    await page.keyboard.press("n");
    await expect
      .poll(() => cursorOffset(page), {
        timeout: 20_000,
        message: "'n' from a focused chip must move the viewer onto an occurrence",
      })
      .not.toBeNull();
    const first = await cursorOffset(page);

    if (jumpable >= 2) {
      // The full walk: forward to the next occurrence, back to this one.
      await page.keyboard.press("n");
      await expect
        .poll(() => cursorOffset(page), {
          timeout: 20_000,
          message: "'n' must advance to the NEXT occurrence",
        })
        .not.toBe(first);
      await page.keyboard.press("p");
      await expect
        .poll(() => cursorOffset(page), {
          timeout: 20_000,
          message: "'p' must return to the previous occurrence",
        })
        .toBe(first);
      test.info().annotations.push({
        type: "walk",
        description: `full n/p walk over ${jumpable} occurrences`,
      });
    } else {
      // This corpus holds exactly ONE region per category (see the describe
      // header), so "advance to the next one" has nothing to advance to. What
      // IS assertable is the clamp at both ends — `jumpNext` / `jumpPrev` clamp
      // rather than wrap — and that `p` re-navigates after the user has moved
      // the cursor away by hand, which is the half of "and returns" this
      // fixture can honestly show.
      await page.keyboard.press("n");
      expect(
        await cursorOffset(page),
        "with one occurrence, a second 'n' must clamp rather than wrap",
      ).toBe(first);

      // Move the cursor away by hand, then walk back to the occurrence.
      await page
        .locator('[data-testid="hex-overlay-scroll"] .hex-byte[data-offset="0"]')
        .first()
        .click();
      await expect.poll(() => cursorOffset(page), { timeout: 10_000 }).toBe(0);
      await page.getByTestId("hex-overlay-pane").focus();
      await page.keyboard.press("p");
      await expect
        .poll(() => cursorOffset(page), {
          timeout: 20_000,
          message: "'p' must navigate back to the occurrence the list is on",
        })
        .toBe(first);
      test.info().annotations.push({
        type: "walk",
        description:
          "single-occurrence corpus: asserted jump + clamp + return instead of a multi-step walk",
      });
    }

    // The goto field lives INSIDE the pane, so a bare letter shortcut that did
    // not check its target would eat the `n` of a hex offset the user is
    // typing. `useHexKeyboard.isTextEntry` is what stops it; this is the proof.
    const goto = page.getByTestId("hex-overlay-pane").getByPlaceholder("0x offset");
    await goto.click();
    await expect(goto).toBeFocused();
    const before = await cursorOffset(page);
    await page.keyboard.press("n");
    await page.waitForTimeout(300);
    expect(
      await cursorOffset(page),
      "'n' must not jump regions while the goto input has focus",
    ).toBe(before);
    expect(await goto.inputValue(), "the keystroke belongs to the text field").toBe("n");
    await goto.fill("");
  });

  // ── (c) RENDER MODES ──────────────────────────────────────────────────────
  //
  // The three modes are mutually exclusive ON A CELL by construction
  // (`HexRow`), and that is the thing worth pinning in a real browser: two
  // colour vocabularies on one byte is precisely what the switch exists to
  // prevent, and it is invisible to a unit test of either mode alone.
  test("Variants and Glyph replace the class vocabulary, and Class restores it", async () => {
    test.setTimeout(120_000);

    const classCounts = await paintedClassCounts(page);
    expect(classifiedCount(classCounts)).toBeGreaterThan(0);

    await expect(page.getByTestId("hex-overlay-render-mode")).toHaveAttribute(
      "data-enabled",
      "true",
    );

    // --- Variants: ramp tints, and NOT ONE consensus class.
    await page.getByTestId("hex-overlay-render-mode-variants").click();
    await expect(page.getByTestId("hex-overlay-render-mode-variants")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    // The legend is the contract for what is on screen, so it changes too.
    await expect(page.getByTestId("hex-overlay-legend-ramp")).toBeVisible();
    await expect(page.getByTestId("hex-overlay-class-chips")).toHaveCount(0);
    await expect
      .poll(async () => (await paintedRampCounts()).ramp, { timeout: 20_000 })
      .toBeGreaterThan(0);
    const variantCounts = await paintedClassCounts(page);
    expect(
      classifiedCount(variantCounts) + variantCounts["cross-dump-differs"],
      `variants mode must paint no consensus-* class: ${JSON.stringify(variantCounts)}`,
    ).toBe(0);

    // --- Glyph: colour-free marks in place of the values.
    await page.getByTestId("hex-overlay-render-mode-glyph").click();
    await expect(page.getByTestId("hex-overlay-render-mode-glyph")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(page.getByTestId("hex-overlay-legend-glyphs")).toBeVisible();
    await expect
      .poll(
        async () => {
          const g = await paintedRampCounts();
          return g.identicalGlyph + g.digitGlyph + g.voidGlyph;
        },
        {
          timeout: 20_000,
          message: "glyph mode must print ■ / 2–6 / ░ instead of hex values",
        },
      )
      .toBeGreaterThan(0);
    const glyphCounts = await paintedClassCounts(page);
    expect(
      classifiedCount(glyphCounts) + glyphCounts["cross-dump-differs"],
      `glyph mode must paint no consensus-* class: ${JSON.stringify(glyphCounts)}`,
    ).toBe(0);

    // --- Back to Class: the class counts come back, and the ramp goes.
    await page.getByTestId("hex-overlay-render-mode-class").click();
    await expect(page.getByTestId("hex-overlay-render-mode-class")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(page.getByTestId("hex-overlay-class-chips")).toBeVisible();
    await expect
      .poll(async () => classifiedCount(await paintedClassCounts(page)), { timeout: 20_000 })
      .toBe(classifiedCount(classCounts));
    expect((await paintedRampCounts()).ramp).toBe(0);
  });

  // ── (d) THE RAIL ──────────────────────────────────────────────────────────
  test("solo names the dump in the footer, the eye changes bytes but not counts, and the weight cycles", async () => {
    test.setTimeout(120_000);

    // A server-side category, so the chip counts under test are the build's own
    // histogram rather than the window-scoped `differs` figure.
    await selectChip("non_invariant");

    const layer = page.getByTestId("hex-status-layer");
    await expect(layer).toHaveText("Viewing: Overlay · weighted plurality of 2");

    // --- Solo: a VIEW change. The footer is the only thing on screen that says
    // whose bytes these are, so it has to name the dump.
    await page.getByTestId(`dump-rail-solo-${ids.id2}`).click();
    await expect(page.getByTestId(`dump-rail-solo-${ids.id2}`)).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await expect(layer).toHaveText(`Viewing: ${RUN_2} · solo`);
    await expect(page.getByTestId(`dump-rail-chip-${ids.id2}`)).toHaveAttribute(
      "data-active",
      "true",
    );
    // Solo takes the row out of the render-mode vocabulary, so the switch dims.
    await expect(page.getByTestId("hex-overlay-render-mode")).toHaveAttribute(
      "data-enabled",
      "false",
    );

    // --- Σ Overlay: back to the plurality, by the same gesture.
    await page.getByTestId("dump-rail-overlay").click();
    await expect(page.getByTestId("dump-rail-overlay")).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await expect(layer).toHaveText("Viewing: Overlay · weighted plurality of 2");
    await expect(page.getByTestId("hex-overlay-render-mode")).toHaveAttribute(
      "data-enabled",
      "true",
    );

    // --- The eye: MEMBERSHIP, not view. Excluding run_1 removes its 0x00 votes
    // from the plurality and the grid falls back to run_2's 0xFE — while the
    // chip counts, which describe the BUILD the backend computed over every
    // SELECTED dump, must not move at all. Conflating the two would mean "let
    // me look without dump 1" silently rewrote every number on the screen.
    const beforeBytes = await paintedText();
    const beforeChips = await chipTexts();

    const eye = page.getByTestId(`dump-rail-include-${ids.id1}`);
    await expect(eye).toBeEnabled();
    await eye.click();
    await expect(eye).toHaveAttribute("aria-pressed", "false");
    await expect(page.getByTestId(`dump-rail-chip-${ids.id1}`)).toHaveAttribute(
      "data-included",
      "false",
    );
    await expect(layer).toHaveText("Viewing: Overlay · weighted plurality of 1");

    await expect
      .poll(() => paintedText(), {
        timeout: 20_000,
        message:
          "excluding a dump must change the plurality the grid paints (the pair is padded 0x00 vs 0xFE)",
      })
      .not.toBe(beforeBytes);
    expect(
      await chipTexts(),
      "exclusion reduces only the painted byte, never the comparison set the counts describe",
    ).toEqual(beforeChips);

    // The consensus must keep a voter: the last included dump's eye is refused.
    await expect(page.getByTestId(`dump-rail-include-${ids.id2}`)).toBeDisabled();

    await eye.click();
    await expect(eye).toHaveAttribute("aria-pressed", "true");
    await expect(layer).toHaveText("Viewing: Overlay · weighted plurality of 2");
    await expect.poll(() => paintedText(), { timeout: 20_000 }).toBe(beforeBytes);

    // --- The weight button: three named positions, in cycle order.
    const weight = page.getByTestId(`dump-rail-weight-${ids.id2}`);
    await expect(weight).toHaveAttribute("data-weight", "1");
    await expect(weight).toHaveText("1.0×");
    await weight.click();
    await expect(weight).toHaveAttribute("data-weight", "1.5");
    await expect(page.getByTestId("dump-rail-overlay-mode")).toHaveAttribute(
      "data-weighted",
      "true",
    );
    await weight.click();
    await expect(weight).toHaveAttribute("data-weight", "0.5");
    await weight.click();
    await expect(weight).toHaveAttribute("data-weight", "1");
    // Back to the default, which the store records as ABSENCE — so the rail is
    // once again honestly describing an unweighted reading.
    await expect(page.getByTestId("dump-rail-overlay-mode")).toHaveAttribute(
      "data-weighted",
      "false",
    );
  });

  // ── (e) VOID HONESTY ──────────────────────────────────────────────────────
  //
  // The design's central refusal, pinned STRUCTURALLY in a real browser: "this
  // page was not captured" and "this byte changed" are different findings, and
  // a cell carrying both vocabularies at once would invent a disagreement the
  // data does not contain.
  //
  // Runs LAST, because it is the one test that leaves the VAS coordinate: in
  // "Memory (VAS)" the anchor's file IS the aligned build and nothing can be
  // absent, whereas the VA coordinate addresses the whole span — and at 0x1000
  // the heap's FAILED second page (`page_state_map = 0x10` in the fixture
  // generator) renders as `byte-gap` in the same window as classified bytes.
  test("an absent cell carries exactly one absence class and never a class or ramp tint", async () => {
    test.setTimeout(120_000);

    await page
      .getByTestId("hex-overlay-pane")
      .getByRole("tab", { name: "VA", exact: true })
      .click();
    await expect
      .poll(
        () =>
          page.evaluate(() => {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            return (window as any).__useHexStore.getState().viewMode as string;
          }),
        { timeout: 20_000 },
      )
      .toBe("va");

    await page.evaluate((off) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (window as any).__useHexStore.getState().scrollToOffset(off);
    }, VA_VOID_OFFSET);

    const survey = async () =>
      page.evaluate(
        ({ absenceClasses, presenceClasses }) => {
          const scroller = document.querySelector('[data-testid="hex-overlay-scroll"]');
          if (!scroller) return null;
          const byKind: Record<string, number> = {};
          const offenders: string[] = [];
          let multiAbsence = 0;
          let painted = 0;
          let sample: { offset: string | null; classes: string[]; text: string } | null = null;

          scroller.querySelectorAll(".hex-byte").forEach((cell) => {
            const classes = Array.from(cell.classList);
            const present = presenceClasses.filter((c) => classes.includes(c));
            const kinds = absenceClasses.filter((c) => classes.includes(c));
            if (present.length > 0) painted++;
            if (kinds.length === 0) return;
            for (const k of kinds) byKind[k] = (byKind[k] ?? 0) + 1;
            if (kinds.length > 1) multiAbsence++;
            if (present.length > 0) {
              offenders.push(`${cell.getAttribute("data-offset")}: ${classes.join(" ")}`);
            }
            // Prefer a REAL absence over a transient "still loading" one.
            const real = kinds.some((k) => k !== "hex-loading");
            if (sample === null || (real && sample.classes.includes("hex-loading"))) {
              sample = {
                offset: cell.getAttribute("data-offset"),
                classes,
                text: (cell.textContent ?? "").trim(),
              };
            }
          });
          return { byKind, offenders, multiAbsence, painted };
        },
        { absenceClasses: ABSENCE_CLASSES, presenceClasses: PRESENCE_CLASSES },
      );

    // Wait for the window that actually holds BOTH vocabularies: a screenful of
    // nothing but `hex-loading` would satisfy the exclusivity rule trivially,
    // and prove nothing about a real void sitting beside a real finding.
    await expect
      .poll(
        async () => {
          const s = await survey();
          if (!s) return "no-scroller";
          const real = Object.keys(s.byKind).filter((k) => k !== "hex-loading");
          return real.length > 0 && s.painted > 0 ? "mixed" : JSON.stringify(s.byKind);
        },
        {
          timeout: 60_000,
          message: `no window at VA offset 0x${VA_VOID_OFFSET.toString(16)} holds both an absent cell and a painted one`,
        },
      )
      .toBe("mixed");

    const final = (await survey())!;
    // eslint-disable-next-line no-console
    console.log(
      `void honesty @ VA 0x${VA_VOID_OFFSET.toString(16)}: ` +
        `${final.painted} painted bytes, absences ${JSON.stringify(final.byKind)}`,
    );

    expect(
      final.multiAbsence,
      "a cell may state exactly ONE reason there is no byte here",
    ).toBe(0);
    expect(
      final.offenders,
      `an absent cell also carries a consensus/ramp class — "not captured" and "changed" have been conflated:\n  ${final.offenders.join("\n  ")}`,
    ).toEqual([]);
  });
});
