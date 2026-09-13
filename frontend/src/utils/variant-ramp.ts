/**
 * One description of the "how many distinct values live at this offset"
 * vocabulary, shared by the hex grid, the legend and the render-mode switch.
 *
 * This is a DIFFERENT question from the one `variance-classes.ts` answers. A
 * ByteClass says what the backend consensus *concluded* about an offset
 * ("pointer-like", "key candidate"); a variant count says only what the
 * selected dumps literally hold there. Keeping the two vocabularies apart is
 * the same refusal `absence-classes.ts` makes: a cell may carry one reading or
 * the other, never a blend of both, or a colour stops meaning one thing.
 *
 * Modelled on `variance-classes.ts`: a frozen tuple, a derived type, and pure
 * functions every consumer reads instead of re-deriving the mapping.
 */

/*
 * ── The SOLO treatment (the resolved `TODO(solo-dump)`) ─────────────────────
 * When the rail solos one dump, the grid paints THAT dump's own bytes rather
 * than the overlay's computed plurality. The variance of the aligned set is
 * still worth seeing there — it is the reason the analyst soloed a dump in the
 * first place ("what does dump 3 actually hold where they disagree?") — but a
 * fill would be exactly the wrong mark for it: the value is now a real byte
 * read from one file, and the one thing that must not happen is for it to
 * become hard to read.
 *
 * So in solo view the same five ramp steps are spent on a `border-bottom:
 * 2px solid` instead of a background: the hex value keeps full contrast on the
 * plain row ground, and the variance sits under it as a rule whose weight rises
 * with the number of distinct values. `variantUnderlineClass` is the class,
 * `--md-variant-underline-1…5` in `hex.css` are the tokens, and they are a
 * SEPARATE ramp from `--md-variant-1…5` for a physical reason: the fill
 * percentages are capped at 48% so hex text stays readable ON them, while a
 * 2 px rule carries no text and would be invisible at 12%.
 */

/** The number of steps on the tint ramp. Step 1 is the faintest. */
export const VARIANT_RAMP_STEPS = 5;

/** The largest count the vocabulary names; anything above reads as "6+". */
export const VARIANT_COUNT_CAP = VARIANT_RAMP_STEPS + 1;

/** The glyph for "every dump holds the same byte here". */
export const GLYPH_IDENTICAL = "■";

/** The glyph for "there is no byte here at all". */
export const GLYPH_VOID = "░";

/**
 * Variant count → ramp step `1…5`, or `null` for "paint nothing".
 *
 * The design's rule verbatim: index the ramp at `min(variants - 1, 5)`, where
 * index 0 is the empty string. So ONE variant — every dump agreeing — gets no
 * background at all, which is the whole point: agreement is the background the
 * signal stands out against, and tinting it would tint the entire screen.
 *
 * `0` ("nobody is present here") and `undefined` ("no answer yet") also paint
 * nothing. A zero-variant offset is a void cell, and `HexRow` has already
 * excluded those before it asks; answering `1` for it would be the same silent
 * lie `varianceCategoryForCode(-1)` refuses to tell.
 */
export function variantRampStep(variants: number | undefined): number | null {
  if (variants === undefined || variants < 2) return null;
  return Math.min(variants - 1, VARIANT_RAMP_STEPS);
}

/** The class `HexRow` puts on a tinted cell; styled by `hex.css`. */
export function variantRampClass(step: number): string {
  return `variant-${step}`;
}

/**
 * What the hex column prints in `glyph` mode, or `null` to keep the hex value.
 *
 * Colour-blind and print safe by construction: the mark is readable with no
 * colour at all. `undefined` — the store has no answer for this offset yet —
 * deliberately keeps the byte rather than claiming agreement.
 */
export function variantGlyph(variants: number | undefined): string | null {
  if (variants === undefined) return null;
  if (variants <= 1) return GLYPH_IDENTICAL;
  return String(Math.min(variants, VARIANT_COUNT_CAP));
}

/**
 * The class a SOLO cell puts on a byte whose value varies across the set.
 *
 * Same step, same ordinal meaning, different mark — see the solo note above.
 * `HexRow` picks between this and `variantRampClass` on one flag, so the two
 * can never both land on the same cell: one vocabulary per cell, the rule the
 * whole render-mode switch exists to keep.
 */
export function variantUnderlineClass(step: number): string {
  return `variant-underline-${step}`;
}
