/**
 * The a11y gap this file exists to close.
 *
 * `a11y-axe.spec.ts`, `a11y-accessible-name.spec.ts` and
 * `a11y-focus-ring.spec.ts` all iterate `fixtures/a11y.ts`'s `TABS` — a list of
 * SIDE and BOTTOM tabs reached by one click from a freshly mounted workspace.
 * The aligned overlay is not on that list and cannot be: it is a MAIN VIEW, and
 * getting to it needs two dumps, a coordinate switch and a finished consensus
 * build. So its controls — the six category chips, the rail's eye and weight
 * buttons, the Byte|Regions tablist and the three segmented switches — have
 * never been axe-checked. The suite's 51/51 was real and simply did not reach
 * here.
 *
 * ── Why a separate file rather than an eighteenth `TABS` entry ──────────────
 * `navigateToTab` is "mount the workspace, click one tab", and every one of the
 * three specs is one `test()` per tab sharing that. The overlay's setup is a
 * ~90 s consensus build, so folding it into `TABS` would make THREE specs pay
 * it (they each mount their own page) and would push a `TabDef` into carrying a
 * bespoke async setup that no other entry has. Here the build is paid ONCE and
 * all three checks read the same screen — which is also stricter, since they
 * then agree about what was on it.
 *
 * The BASELINE machinery is reused verbatim (`fixtures/a11y-baseline.json`,
 * keyed `axe`/`accessibleName`/`focusRing` by tab id) under the ids
 * `overlay` and `overlay-contrast`, so `npm run test:a11y:seed` re-seeds these
 * exactly like the rest and a newly introduced violation is a failure here for
 * the same reason it is there.
 *
 * ── Contrast is checked, not disabled ───────────────────────────────────────
 * The three tab specs `disableRules(["color-contrast"])`. Today's controls are
 * the first ones in this app to paint text on `--md-bg-accent` (the selected
 * segment of three separate segmented groups) and muted counts inside a
 * pressed chip, so a contrast-only pass over the overlay is the single most
 * likely place for a real, new violation. It gets its own baseline key so it
 * can be tightened independently of the general sweep.
 */
import AxeBuilder from "@axe-core/playwright";
import { test, expect, type BrowserContext, type Page } from "@playwright/test";

import { aslrMslPairAvailable } from "../fixtures/dataset";
import {
  seedMode,
  writeBaselineMerge,
  diffAgainstBaseline,
} from "../fixtures/a11y";
import {
  enterAlignedOverlay,
  OVERLAY_SETUP_TIMEOUT,
  type AlignedOverlayHandles,
} from "../fixtures/overlay";

const PER_TAB_GUARD = 30;

/** How far the Tab walk goes. Long enough to leave the overlay pane entirely. */
const MAX_TABS = 60;

/** The overlay surfaces axe is pointed at for the contrast-only pass. */
const OVERLAY_SCOPES = [
  '[data-testid="hex-overlay-pane"]',
  '[data-testid="overlay-detail-tabs"]',
  '[data-testid="variance-class-browser"]',
];

/**
 * The virtualized byte grid, kept OUT of the contrast pass.
 *
 * Two reasons, and neither is "it fails". (1) Its rows are addressed by axe as
 * `div[data-index="N"] > .hex-row > .hex-offset`, and N is whatever the
 * virtualizer happened to render — a baseline keyed on that churns with the
 * viewport and turns a ratchet into a flake. (2) The `.hex-offset` gutter
 * (#808080 on #1e1e1e, 4.22:1) is the SINGLE-dump hex grid's existing token
 * debt, shared by every viewer, and folding it in here would file it against
 * the overlay's new controls, which is not where it is fixed. It is reported in
 * this task's write-up instead.
 */
const GRID_SCOPE = '[data-testid="hex-overlay-scroll"]';

test.describe("a11y: the aligned overlay (chips, rail, detail tabs, switches)", () => {
  test.describe.configure({ mode: "serial" });
  test.skip(!aslrMslPairAvailable, "ASLR .msl fixture pair missing");

  let context: BrowserContext;
  let page: Page;
  let ids: AlignedOverlayHandles;

  test.beforeAll(async ({ browser }) => {
    test.setTimeout(OVERLAY_SETUP_TIMEOUT);
    // An EXPLICIT context, not `browser.newPage()`: `@axe-core/playwright`
    // refuses a page whose context it did not see created ("Please use
    // browser.newContext()"), because it injects axe into every frame through
    // the context's init scripts.
    context = await browser.newContext();
    page = await context.newPage();
    ids = await enterAlignedOverlay(page);
    // Open the Regions list too: half the new controls live in the detail
    // panel, and a sweep that never opened it would report a clean bill of
    // health for a pane it did not look at.
    await page.getByTestId("hex-overlay-class-chip-non_invariant").click();
    await expect(page.getByTestId("overlay-detail-tab-regions")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(page.getByTestId("variance-class-browser")).toBeVisible();
  });

  test.afterAll(async () => {
    await page?.close();
    await context?.close();
  });

  /**
   * Everything this file promises to cover, present and on screen.
   *
   * Without it a green run proves nothing: if the rail failed to mount, every
   * check below would pass by finding no controls to object to.
   */
  test("the controls under test are all mounted", async () => {
    // The six category chips, `Changing` selected by default.
    for (const chip of [
      "invariant",
      "structural",
      "pointer",
      "key_candidate",
      "differs",
      "non_invariant",
    ]) {
      await expect(page.getByTestId(`hex-overlay-class-chip-${chip}`)).toBeVisible();
    }
    await expect(page.getByTestId("hex-overlay-class-chips")).toHaveAttribute(
      "role",
      "group",
    );

    // The rail: Σ Overlay, plus an eye and a weight button per dump.
    await expect(page.getByTestId("dump-rail")).toBeVisible();
    await expect(page.getByTestId("dump-rail-overlay")).toBeVisible();
    for (const id of [ids.id1, ids.id2]) {
      await expect(page.getByTestId(`dump-rail-solo-${id}`)).toBeVisible();
      await expect(page.getByTestId(`dump-rail-include-${id}`)).toBeVisible();
      await expect(page.getByTestId(`dump-rail-weight-${id}`)).toBeVisible();
    }

    // The Byte | Regions tablist.
    await expect(page.getByTestId("overlay-detail-tab-byte")).toBeVisible();
    await expect(page.getByTestId("overlay-detail-tab-regions")).toBeVisible();

    // The three segmented switches.
    await expect(page.getByTestId("hex-overlay-align-switch")).toBeVisible();
    await expect(page.getByTestId("hex-overlay-render-mode")).toBeVisible();
    await expect(page.getByTestId("overlay-detail-tabs")).toBeVisible();

    // The alignment chip's discard note is CONDITIONAL — it only exists when
    // the alignment actually threw bytes away (`discarded > 0`). On this pair
    // the two page slices intersect exactly, so nothing is discarded and the
    // `<details>` is correctly absent. Asserted as the conditional it is, so a
    // future fixture that does discard bytes still gets the control checked
    // rather than silently skipped.
    const discardText = (await page.getByTestId("dump-rail-stats-discarded").textContent()) ?? "";
    const discardsBytes = !/^0 discarded/.test(discardText.trim());
    // eslint-disable-next-line no-console
    console.log(`alignment discard: "${discardText.trim()}"`);
    await expect(page.getByTestId("hex-alignment-discard-note")).toHaveCount(
      discardsBytes ? 1 : 0,
    );
  });

  test("axe-core (WCAG 2.0 A/AA, critical+serious)", async () => {
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .disableRules(["color-contrast"])
      .analyze();

    const violations = results.violations
      .filter((v) => v.impact === "critical" || v.impact === "serious")
      .flatMap((v) => v.nodes.map((n) => `${v.id}#${n.target.join(" ")}`))
      .sort();

    expect(
      violations.length,
      `Guard: > ${PER_TAB_GUARD} critical+serious axe hits suggests misconfiguration, not real a11y debt.`,
    ).toBeLessThanOrEqual(PER_TAB_GUARD);

    if (seedMode()) {
      writeBaselineMerge("axe", "overlay", violations);
      return;
    }

    const { newHits } = diffAgainstBaseline(violations, "axe", "overlay");
    expect(
      newHits,
      `New axe violations in the aligned overlay. Fix or re-seed via 'npm run test:a11y:seed':\n  ${newHits.join("\n  ")}`,
    ).toEqual([]);
  });

  test("axe-core colour contrast, scoped to the overlay", async () => {
    let builder = new AxeBuilder({ page }).withRules(["color-contrast"]);
    for (const scope of OVERLAY_SCOPES) builder = builder.include(scope);
    const results = await builder.exclude(GRID_SCOPE).analyze();

    const violations = results.violations
      .flatMap((v) =>
        v.nodes.map(
          (n) => `${v.id}#${n.target.join(" ")}`,
        ),
      )
      .sort();

    // The failure summaries carry the measured ratios, which is the only part
    // worth reading when this goes red — print them rather than making the
    // next reader re-run with a debugger.
    if (violations.length > 0) {
      // eslint-disable-next-line no-console
      console.log(
        "overlay contrast findings:\n" +
          results.violations
            .flatMap((v) => v.nodes.map((n) => `  ${n.target.join(" ")}: ${n.failureSummary}`))
            .join("\n"),
      );
    }

    if (seedMode()) {
      writeBaselineMerge("axe", "overlay-contrast", violations);
      return;
    }

    const { newHits } = diffAgainstBaseline(violations, "axe", "overlay-contrast");
    expect(
      newHits,
      `New colour-contrast violations in the aligned overlay. Fix or re-seed:\n  ${newHits.join("\n  ")}`,
    ).toEqual([]);
  });

  test("every icon-only button has an accessible name", async () => {
    // Same predicate as `a11y-accessible-name.spec.ts`, deliberately: the eye
    // (`◉`/`◌`) and the rail's collapse caret are single glyphs, so `title` and
    // `aria-label` are the only things standing between them and anonymity.
    const offenders = await page.evaluate(() => {
      const bad: string[] = [];
      const seen = new Set<string>();
      document.querySelectorAll<HTMLButtonElement>("button:not([aria-label])").forEach((b) => {
        const text = (b.textContent ?? "").replace(/\s+/g, " ").trim();
        const hasLabelledBy = !!b.getAttribute("aria-labelledby");
        const hasTitle = !!b.getAttribute("title");
        const hasImgAlt = !!b.querySelector("img[alt]:not([alt=''])");
        if (text.length >= 2 || hasLabelledBy || hasTitle || hasImgAlt) return;
        const snippet = b.outerHTML.slice(0, 140).replace(/\s+/g, " ");
        if (!seen.has(snippet)) {
          seen.add(snippet);
          bad.push(snippet);
        }
      });
      return bad;
    });

    const sorted = offenders.sort();

    if (seedMode()) {
      writeBaselineMerge("accessibleName", "overlay", sorted);
      return;
    }

    const { newHits } = diffAgainstBaseline(sorted, "accessibleName", "overlay");
    expect(
      newHits,
      `Nameless button(s) in the aligned overlay. Add aria-label, visible text, or aria-labelledby.\n  ${newHits.join("\n  ")}`,
    ).toEqual([]);
  });

  /**
   * A visible focus ring on EVERY new control, checked one control at a time.
   *
   * Not a Tab walk, and that is a finding rather than a shortcut: the overlay
   * pane is a KEYBOARD TRAP (see the `test.fixme` below), so a walk gets stuck
   * on the pane wrapper and reports a clean bill of health for controls it
   * never reached — the same vacuous pass the three tab specs' empty
   * `focusRing` baseline is hiding today.
   *
   * `:focus-visible` still engages here: Chromium keeps the modality of the
   * LAST user interaction, so one real `Tab` press before the sweep makes every
   * subsequent programmatic `.focus()` match the pseudo-class. That is asserted
   * rather than assumed — `focusVisible` is reported per control, and a false
   * would mean this test is measuring `:focus` and proving nothing.
   */
  test("visible focus ring on the overlay's controls", async () => {
    const targets = [
      // the three segmented switches
      "hex-overlay-align-delta-fit",
      "hex-overlay-align-raw-offsets",
      "hex-overlay-render-mode-class",
      "hex-overlay-render-mode-variants",
      "hex-overlay-render-mode-glyph",
      "overlay-detail-tab-byte",
      "overlay-detail-tab-regions",
      // the six category chips
      "hex-overlay-class-chip-invariant",
      "hex-overlay-class-chip-structural",
      "hex-overlay-class-chip-pointer",
      "hex-overlay-class-chip-key_candidate",
      "hex-overlay-class-chip-differs",
      "hex-overlay-class-chip-non_invariant",
      // the rail
      "dump-rail-overlay",
      "dump-rail-collapse",
      `dump-rail-solo-${ids.id1}`,
      `dump-rail-include-${ids.id1}`,
      `dump-rail-weight-${ids.id1}`,
      `dump-rail-solo-${ids.id2}`,
      `dump-rail-weight-${ids.id2}`,
    ];

    // Establish KEYBOARD modality with one real press, outside the trapped
    // pane, so `:focus-visible` applies to the programmatic focuses below.
    await page.getByTestId("overlay-detail-tab-byte").focus();
    await page.keyboard.press("Tab");

    const results = await page.evaluate((testids) => {
      return testids.map((id) => {
        const el = document.querySelector(`[data-testid="${id}"]`) as HTMLElement | null;
        if (!el) return { id, missing: true, focusVisible: false, ring: false };
        el.focus();
        const cs = getComputedStyle(el);
        const hasOutline = cs.outlineStyle !== "none" && parseFloat(cs.outlineWidth) > 0;
        const hasRingShadow = /rgba?\(|\bring/.test(cs.boxShadow);
        return {
          id,
          missing: false,
          focusVisible: el.matches(":focus-visible"),
          ring: hasOutline || hasRingShadow,
        };
      });
    }, targets);

    expect(
      results.filter((r) => r.missing).map((r) => r.id),
      "a control this sweep promises to cover is not on screen",
    ).toEqual([]);
    expect(
      results.filter((r) => !r.focusVisible).map((r) => r.id),
      "`:focus-visible` did not engage — this sweep would be measuring `:focus` and proving nothing",
    ).toEqual([]);

    const offenders = results.filter((r) => !r.ring).map((r) => r.id).sort();

    if (seedMode()) {
      writeBaselineMerge("focusRing", "overlay", offenders);
      return;
    }

    const { newHits } = diffAgainstBaseline(offenders, "focusRing", "overlay");
    expect(
      newHits,
      `New focus-ring offenders in the aligned overlay. Fix or re-seed.\n  ${newHits.join("\n  ")}`,
    ).toEqual([]);
  });

  /**
   * WCAG 2.1.2 "No Keyboard Trap", Level A — was a real bug, now the contract.
   *
   * `useHexKeyboard` binds `keydown` to the viewer's CONTAINER and used to
   * handle `case "Tab": e.preventDefault(); setFocusColumn(...)`
   * unconditionally. Keydown bubbles, so that `preventDefault` swallowed EVERY
   * Tab and Shift+Tab raised anywhere inside `hex-overlay-pane` — which since
   * the overlay landed also contains the align switch, the render-mode switch,
   * the six chips, the whole dump rail, the window-error retry and the status
   * bar's Prev/Next.
   *
   * Measured from `<body>` with the overlay open: three Tab presses reached
   * `hex-overlay-pane` (`tabIndex={0}`) and the next 42 went nowhere; Shift+Tab
   * was equally dead. It was not new either — `HexViewer` and `MultiHexViewer`
   * mount the same hook, which is why `a11y-focus-ring.spec.ts`'s `focusRing`
   * baseline was empty for all 17 tabs: those walks got stuck on the hex
   * container after ~3 presses and reported a pass over controls they never
   * visited.
   *
   * The hex/ASCII column toggle survives, scoped to the grid: Tab is handled
   * only when the grid CONTAINER ITSELF is the event target (the cells are not
   * in the tab order, so that is exactly "focus is on the byte grid"), and only
   * for the `hex` -> `ascii` step. The next Tab falls through and leaves the
   * pane; Shift+Tab is never prevented at all.
   */
  test("the overlay pane is not a keyboard trap", async () => {
    await page.evaluate(() => (document.body as HTMLElement).focus());
    const visited: string[] = [];
    for (let i = 0; i < MAX_TABS; i++) {
      await page.keyboard.press("Tab");
      visited.push(
        await page.evaluate(() => {
          const el = document.activeElement as HTMLElement | null;
          return el?.getAttribute("data-testid") ?? el?.tagName ?? "null";
        }),
      );
    }
    const distinct = new Set(visited);
    expect(
      distinct.size,
      `Tab is trapped: ${MAX_TABS} presses visited ${distinct.size} element(s) — ${[...distinct].join(", ")}`,
    ).toBeGreaterThan(3);
  });
});
