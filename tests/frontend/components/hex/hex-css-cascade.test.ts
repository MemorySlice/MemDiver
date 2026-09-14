/**
 * The CASCADE, tested — not the class names, the winner.
 *
 * `HexRow` tests prove a cell carries both `selected` and `consensus-invariant`.
 * That was already true while the bug was live: the classes were on the cell and
 * the selection was still invisible, because `.hex-byte.consensus-invariant`
 * sets a `background` at the same (0,2,0) specificity as `.hex-byte.selected`
 * and is declared later, so it won. Only a test that resolves the real
 * stylesheet can tell those two situations apart.
 *
 * Every cell below is composed through `markRings`, exactly as `HexRow` composes
 * it. That is deliberate: the fix is split across a module and a stylesheet, and
 * a test that hand-wrote the marker would pass with `HexRow` no longer applying
 * it. What is asserted here is the pair.
 *
 * jsdom does resolve specificity and source order across rules, and leaves
 * `var()` / `color-mix()` values as written — which is enough: what matters
 * here is WHICH rule supplies the winning value, not what colour it computes to.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { GROUND_CLASSES, markRings } from "@/components/hex/ground-classes";

const HEX_CSS = readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), "../../../../frontend/src/styles/hex.css"),
  "utf8",
);

/** The value `.hex-byte.selected` alone paints, i.e. selection at full strength. */
const SELECTED_BACKGROUND = "var(--md-bg-selected, #094771)";

const SELECTION_OUTLINE = "2px solid var(--md-text-primary)";
const SEARCH_OUTLINE = "2px solid var(--md-hl-search)";

/**
 * A cell carrying `classes`, with the REAL `hex.css` applied.
 *
 * `classes` is passed through `markRings` first, so the cell under test is the
 * one `HexRow` would render rather than an idealised version of it.
 *
 * `theme` lets one call describe the same cell in the high-contrast theme,
 * which is where the compensating outlines have competition.
 */
function cellStyle(classes: string[], theme: "" | "high-contrast" = ""): CSSStyleDeclaration {
  const marked = [...classes];
  markRings(marked);

  const style = document.createElement("style");
  style.textContent = HEX_CSS;
  document.head.appendChild(style);
  const root = document.createElement("div");
  if (theme) root.className = theme;
  const cell = document.createElement("span");
  cell.className = marked.join(" ");
  root.appendChild(cell);
  document.body.appendChild(root);
  return getComputedStyle(cell);
}

afterEach(() => {
  document.head.innerHTML = "";
  document.body.innerHTML = "";
});

/**
 * The classes `hex.css` gives a `background` to, read back off the stylesheet.
 *
 * Every cell rule in the file is declared for `.hex-byte` and `.hex-char`
 * together, so matching the `.hex-byte` half finds them all.
 */
function stylesheetGrounds(): Set<string> {
  const withoutComments = HEX_CSS.replace(/\/\*[\s\S]*?\*\//g, "");
  const grounds = new Set<string>();
  for (const [, selector, body] of withoutComments.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    // `background-image` is a different longhand: `.var-tier-*` composites over
    // whatever ground won instead of replacing it, so it is not a competitor.
    if (!/(^|[;{\s])background\s*:/.test(body)) continue;
    for (const [, name] of selector.matchAll(/\.hex-byte\.([A-Za-z0-9_-]+)/g)) {
      grounds.add(name);
    }
  }
  // The mark itself is not a competitor for its own ground.
  grounds.delete("selected");
  return grounds;
}

describe("ground-classes stays in step with hex.css", () => {
  /**
   * THE anti-drift guard, and the reason this fix is not another `:is(...)`
   * list. Add a `background` rule for a new cell class to `hex.css` without
   * naming it in `GROUND_CLASSES` and this fails — instead of the selection
   * silently disappearing on that class a year later, which is exactly how the
   * field colours and the neighborhood tints came to be missed.
   */
  it("names every class hex.css gives a background to", () => {
    expect([...stylesheetGrounds()].sort()).toEqual([...GROUND_CLASSES].sort());
  });

  /**
   * The parser above splits on braces, which is only sound while the file has
   * no nested at-rules. It has none, and this says so out loud rather than
   * letting a future `@media` block quietly turn the guard into a no-op.
   */
  it("reads a stylesheet with no nested at-rules", () => {
    expect(HEX_CSS).not.toMatch(/@(media|supports|layer|container)[^;]*\{/);
  });
});

describe("hex.css selection survives a tinted cell", () => {
  it("paints the plain selection background where nothing competes", () => {
    expect(cellStyle(["hex-byte", "selected"]).background).toBe(SELECTED_BACKGROUND);
  });

  /**
   * A selection with no competition stays a clean contiguous band. The ring is
   * the compensation for a lost ground, not decoration — if it appeared on
   * every selected cell a drag across plain bytes would read as a row of
   * separate boxes rather than one range.
   */
  it("leaves an uncontested selection unringed", () => {
    expect(cellStyle(["hex-byte", "selected"]).outline).toBe("");
  });

  /**
   * The bug, stated as the fact it is: the class tint DOES take the background.
   * Pinning it keeps the fix honest — the answer is not to win the background
   * back (that would erase a meaning-bearing colour), it is to express the
   * selection in a property nothing here competes for.
   */
  it("lets the invariant tint keep the background, and marks the cell anyway", () => {
    const cell = cellStyle(["hex-byte", "selected", "consensus-invariant"]);

    expect(cell.background).not.toBe(SELECTED_BACKGROUND);
    expect(cell.outline).toBe(SELECTION_OUTLINE);
  });

  it("marks a selected variant cell at every step of the ramp", () => {
    for (const step of [1, 2, 3, 4, 5]) {
      const cell = cellStyle(["hex-byte", "selected", `variant-${step}`]);
      expect(cell.outline, `variant-${step}`).toBe(SELECTION_OUTLINE);
    }
  });

  it("marks the ascii column the same way", () => {
    expect(cellStyle(["hex-char", "selected", "consensus-invariant"]).outline).toBe(
      SELECTION_OUTLINE,
    );
  });

  /** The void cells this treatment was originally written for must not regress. */
  it("still marks a selected void cell", () => {
    for (const cls of ["byte-gap", "byte-absent", "byte-error"]) {
      expect(cellStyle(["hex-byte", "selected", cls]).outline, cls).toBe(SELECTION_OUTLINE);
    }
  });

  /**
   * The four families the old `:is(...)` list left out. Each of these was a
   * live, reachable way to lose a selection: a structure field, a neighborhood
   * region, an `.msl` page state and any of the nine highlight bands.
   */
  it("marks a selected structure-field cell at every colour in the cycle", () => {
    for (let colour = 0; colour < 8; colour++) {
      const cell = cellStyle(["hex-byte", "selected", `field-color-${colour}`]);
      expect(cell.outline, `field-color-${colour}`).toBe(SELECTION_OUTLINE);
    }
  });

  it("marks a selected neighborhood cell", () => {
    for (const cls of ["nb-static", "nb-key", "nb-dynamic"]) {
      expect(cellStyle(["hex-byte", "selected", cls]).outline, cls).toBe(SELECTION_OUTLINE);
    }
  });

  it("marks a selected page-state cell", () => {
    for (const cls of ["page-failed", "page-unmapped"]) {
      expect(cellStyle(["hex-byte", "selected", cls]).outline, cls).toBe(SELECTION_OUTLINE);
    }
  });

  it("marks a selected cell under every highlight band", () => {
    for (const cls of [...GROUND_CLASSES].filter((c) => c.startsWith("highlight-"))) {
      expect(cellStyle(["hex-byte", "selected", cls]).outline, cls).toBe(SELECTION_OUTLINE);
    }
  });

  /**
   * High contrast gives every tinted and hatched cell an outline of its own, at
   * the SAME (0,3,0) specificity as the selection's. A user who asked for
   * maximum separation has not asked to lose track of their selection, so the
   * selection rule is declared last and wins.
   */
  it("keeps the selection visible in high contrast", () => {
    expect(cellStyle(["hex-byte", "selected", "variant-5"], "high-contrast").outline).toBe(
      SELECTION_OUTLINE,
    );
    expect(cellStyle(["hex-byte", "selected", "byte-absent"], "high-contrast").outline).toBe(
      SELECTION_OUTLINE,
    );
  });
});

describe("hex.css search highlight survives a tinted cell", () => {
  it("keeps its own ground where nothing competes", () => {
    expect(cellStyle(["hex-byte", "highlight-search"]).background).toMatch(/--md-hl-search/);
  });

  /** Its ground is intact, so the hit is not ringed on top of it. */
  it("leaves an uncontested search hit unringed", () => {
    expect(cellStyle(["hex-byte", "highlight-search"]).outline).toBe("");
  });

  it("marks an invariant search hit that lost its ground", () => {
    const cell = cellStyle(["hex-byte", "highlight-search", "consensus-invariant"]);

    expect(cell.background).not.toMatch(/--md-hl-search/);
    expect(cell.outline).toBe(SEARCH_OUTLINE);
  });

  it("marks a tinted variant search hit", () => {
    expect(cellStyle(["hex-byte", "highlight-search", "variant-3"]).outline).toBe(
      SEARCH_OUTLINE,
    );
  });

  it("marks a search hit sitting on a structure field", () => {
    expect(cellStyle(["hex-byte", "highlight-search", "field-color-5"]).outline).toBe(
      SEARCH_OUTLINE,
    );
  });

  /**
   * A cell that is both is one the user is actively dragging over, so the
   * SELECTION is the mark that paints — one outline, deliberately, rather than
   * two rules fighting for the same property with no defined winner.
   */
  it("gives the selection the last word on a cell that is both", () => {
    expect(
      cellStyle(["hex-byte", "selected", "highlight-search", "variant-2"]).outline,
    ).toBe(SELECTION_OUTLINE);
  });

  /**
   * The search band is itself a ground, and it is declared after `.selected`.
   * A selection dragged across a search hit therefore loses its fill to the
   * hit even when no other tint is on the cell — so this pairing needs the
   * ring too, which the old `:is(...)` list had no way to express.
   */
  it("marks a selection whose only competitor is the search hit", () => {
    const cell = cellStyle(["hex-byte", "selected", "highlight-search"]);

    expect(cell.background).toMatch(/--md-hl-search/);
    expect(cell.outline).toBe(SELECTION_OUTLINE);
  });
});
