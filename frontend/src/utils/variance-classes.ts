/**
 * One description of the cross-dump variance vocabulary, shared by every
 * surface that paints or explains it.
 *
 * Before this map each consumer carried its own copy of the palette, and the
 * copies disagreed: the N-dump overlay painted invariant GREEN while the hex
 * grid painted structural green, so one colour meant two different things two
 * panes apart, and the candidate table was off by one against the consensus
 * histogram. Colour here is always a `var(--md-variance-*)` token, never a
 * literal, so a theme switch re-themes every surface at once.
 *
 * Modelled on `highlight-types.ts`: a frozen tuple of names, a type derived
 * from it, and one record that every consumer reads.
 */

import type { VarianceThresholds } from "@/stores/consensus-store";

export const VARIANCE_CATEGORIES = [
  "invariant",
  "structural",
  "pointer",
  "key_candidate",
  "differs",
] as const;

export type VarianceCategory = (typeof VARIANCE_CATEGORIES)[number];

export interface VarianceMeta {
  /**
   * Backend `ByteClass` code (core/variance.py), or `null` for `differs` —
   * which is not a class at all but a CLIENT-side observation ("the aligned
   * dumps hold different values here") computed without the consensus vector.
   */
  code: number | null;
  /** The class `HexRow` puts on a painted cell; styled by `hex.css`. */
  byteClass: string;
  /** The modifier a `.md-variance-swatch` legend element carries. */
  swatchClass: string;
  /** Token reference, for the inline-style surfaces (minimap, charts). */
  colorVar: string;
  /** Existing i18n key in the `hex` namespace. */
  labelKey: string;
  /** i18n key for the longer explanation; the strings land in a later task. */
  descriptionKey: string;
  /**
   * The band boundary a legend quotes for this class, as a field of the build's
   * own `VarianceThresholds` -- or `null` when the class has no boundary of its
   * own to quote.
   *
   * `key_candidate` shares `pointer_max` deliberately: it is the band ABOVE it,
   * so the number that separates the two is the one worth printing. `differs`
   * is not a variance band at all (it is a client-side cross-dump observation),
   * so it has none.
   */
  thresholdKey: keyof VarianceThresholds | null;
}

export const VARIANCE_META: Record<VarianceCategory, VarianceMeta> = {
  invariant: {
    code: 0,
    byteClass: "consensus-invariant",
    swatchClass: "variance-invariant",
    colorVar: "var(--md-variance-invariant)",
    labelKey: "ndump.legendInvariant",
    descriptionKey: "varianceLegend.desc.invariant",
    thresholdKey: "invariant_max",
  },
  structural: {
    code: 1,
    byteClass: "consensus-structural",
    swatchClass: "variance-structural",
    colorVar: "var(--md-variance-structural)",
    labelKey: "ndump.legendStructural",
    descriptionKey: "varianceLegend.desc.structural",
    thresholdKey: "structural_max",
  },
  pointer: {
    code: 2,
    byteClass: "consensus-pointer",
    swatchClass: "variance-pointer",
    colorVar: "var(--md-variance-pointer)",
    labelKey: "ndump.legendPointer",
    descriptionKey: "varianceLegend.desc.pointer",
    thresholdKey: "pointer_max",
  },
  key_candidate: {
    code: 3,
    byteClass: "consensus-key-candidate",
    swatchClass: "variance-key-candidate",
    colorVar: "var(--md-variance-key-candidate)",
    labelKey: "ndump.legendKeyCandidate",
    descriptionKey: "varianceLegend.desc.keyCandidate",
    thresholdKey: "pointer_max",
  },
  differs: {
    code: null,
    byteClass: "cross-dump-differs",
    swatchClass: "variance-differs",
    colorVar: "var(--md-accent-yellow)",
    labelKey: "ndump.legendDiffers",
    descriptionKey: "varianceLegend.desc.differs",
    thresholdKey: null,
  },
};

/** Categories that come from the backend consensus vector, in code order. */
const CATEGORIES_BY_CODE: readonly VarianceCategory[] = [
  "invariant",
  "structural",
  "pointer",
  "key_candidate",
];

/**
 * Backend `ByteClass` code → category, or `null` when the code names none.
 *
 * `-1` is the gap / unclassified marker and MUST yield `null`: returning
 * `invariant` (code 0) for it would be a silent lie — "every dump agrees here"
 * about a byte no dump holds. `multi-hex-store.getClassAt` makes the same
 * refusal at the store boundary.
 */
export function varianceCategoryForCode(code: number): VarianceCategory | null {
  return CATEGORIES_BY_CODE[code] ?? null;
}
