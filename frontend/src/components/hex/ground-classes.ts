/**
 * Which classes own a hex cell's BACKGROUND — and therefore when the selection
 * and search marks have to be drawn as outlines instead.
 *
 * ── The problem this exists to solve ─────────────────────────────────────────
 * `.hex-byte.selected` and `.hex-byte.highlight-search` paint a `background` at
 * specificity (0,2,0), and so does every class named below — all of them
 * declared LATER in `hex.css`, so all of them win outright. The visible effect
 * was that dragging a selection across a tinted cell made the selection VANISH
 * under the pointer.
 *
 * `hex.css` used to compensate by naming the competing classes inline, in four
 * `:is(...)` lists. That list held nine of the THIRTY-ONE classes that actually
 * take the ground — the structure field colours, the neighborhood tints, the
 * page-state tints and every `highlight-*` band were all missing, and the
 * stylesheet's own comment had already warned that enumerating them is an arms
 * race. This module is that enumeration moved to the one place it can be kept
 * honest: beside the code that pushes the classes, and covered by a test that
 * re-derives the same set from the stylesheet and fails when the two disagree.
 *
 * The FIX itself is unchanged and stays the design's: an outline, because an
 * outline is a different property from a fill, so the cascade never puts the
 * two in competition and the cell keeps BOTH its meaning-bearing tint and the
 * user's mark.
 */

/**
 * Every class whose `hex.css` rule sets the `background` shorthand on a cell.
 *
 * Note what is NOT here, and why:
 *  - `selected` itself — it is the mark, not a competitor for it.
 *  - `var-tier-1…3`, which set `background-image` only. A different longhand,
 *    so they composite over whatever ground won rather than replacing it.
 *  - `cross-dump-differs` (`box-shadow`), `variant-underline-1…5`
 *    (`border-bottom`), `cursor` / `active-field` (`outline`) and the three
 *    text-only consensus classes — none of them touch the ground.
 */
export const GROUND_CLASSES: ReadonlySet<string> = new Set([
  // Highlight bands (`highlightClass()` in ./highlight-utils).
  "highlight-exact-match",
  "highlight-entropy",
  "highlight-change-point",
  "highlight-pattern",
  "highlight-structure",
  "highlight-search",
  "highlight-differential",
  "highlight-constraint",
  "highlight-strings",
  // Structure field colour cycling.
  "field-color-0",
  "field-color-1",
  "field-color-2",
  "field-color-3",
  "field-color-4",
  "field-color-5",
  "field-color-6",
  "field-color-7",
  // Neighborhood overlay field semantics.
  "nb-static",
  "nb-key",
  "nb-dynamic",
  // MSL page-state tints (the byte IS there; the backend zero-filled it).
  "page-failed",
  "page-unmapped",
  // Consensus classes — only INVARIANT carries a tint; the other three are
  // text colour alone.
  "consensus-invariant",
  // The distinct-value ramp.
  "variant-1",
  "variant-2",
  "variant-3",
  "variant-4",
  "variant-5",
  // Absence: two hatches and a flat load-failure tint.
  "byte-gap",
  "byte-absent",
  "byte-error",
]);

/** The mark a selected cell carries; also the class `hex.css` keys on. */
export const SELECTED_CLASS = "selected";

/** The mark a search hit carries. It is itself a ground — see `markRings`. */
export const SEARCH_CLASS = "highlight-search";

/** Appended when a selection needs its outline because the ground is taken. */
export const SELECTION_RING = "selection-ring";

/** Appended when a search hit needs its outline for the same reason. */
export const SEARCH_RING = "search-ring";

/**
 * Append the outline markers `classes` needs, in place.
 *
 * Called once per cell on the hot render path, so it makes a single pass and
 * allocates nothing unless a ring is actually due.
 *
 * The two marks ask slightly different questions of the same count, and the
 * difference is not an accident:
 *
 *  - A SELECTION needs its ring as soon as ANY ground class is present —
 *    `highlight-search` included, since that rule is declared after
 *    `.selected` and takes the ground from it.
 *  - A SEARCH HIT needs one only when something OTHER than itself took the
 *    ground, which is why the count has to clear two rather than one. A plain
 *    search hit keeps its yellow fill and stays unringed.
 *
 * A cell that is both selected and a search hit gets both markers; `hex.css`
 * declares the selection rule last, so the selection is the mark that paints —
 * it is the one the user is actively dragging.
 */
export function markRings(classes: string[]): void {
  let grounds = 0;
  let selected = false;
  let searchHit = false;

  for (const cls of classes) {
    if (GROUND_CLASSES.has(cls)) grounds++;
    if (cls === SELECTED_CLASS) selected = true;
    else if (cls === SEARCH_CLASS) searchHit = true;
  }

  if (grounds === 0) return;
  if (searchHit && grounds > 1) classes.push(SEARCH_RING);
  if (selected) classes.push(SELECTION_RING);
}
