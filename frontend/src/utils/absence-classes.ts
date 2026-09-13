/**
 * One description of the "there is no byte here" vocabulary, shared by the hex
 * grid and by every legend that explains it.
 *
 * ── The rule this map exists to enforce ──────────────────────────────────────
 * A byte present in some dumps and absent in others gets a VOID cell, and a
 * void cell is never folded into "mismatch": "this page was not captured" and
 * "this byte changed" are different findings, and a viewer that paints them
 * alike invents disagreement that the data does not contain. `HexRow` makes
 * that structural — a void cell takes the absence branch and never reaches the
 * consensus-class branch — and this map is what both branches read.
 *
 * The four causes are likewise not folded into each other. They are told apart
 * by GLYPH plus TREATMENT, never by colour alone: `hex.css` paints the two
 * "genuinely absent" states as 45° hatches (so they read as void even in
 * greyscale or high contrast), `error` as a flat tint with a bottom rule, and
 * `loading` with no hatch at all — a window that has not arrived yet is not a
 * finding, and must not look like one.
 *
 * Modelled on `variance-classes.ts`, deliberately as a SEPARATE map: folding
 * absence into the variance vocabulary is exactly the conflation above.
 */

import type { ByteAbsence } from "@/stores/multi-hex-store";

/**
 * The absence vocabulary as `HexRow` consumes it.
 *
 * Wider than `ByteAbsence` by the two MSL page states, so the single-dump
 * viewer's `getPageStateAt` can flow through the same funnel instead of a
 * second, view-gated code path — that gate is why the page-state tints never
 * rendered in the `"vas"` coordinate at all.
 */
export type AbsenceKind = ByteAbsence | "unmapped" | "failed";

export interface AbsenceMeta {
  /** The class `HexRow` puts on the cell; styled by `hex.css`. */
  cellClass: string;
  /**
   * What the hex column prints INSTEAD of a value, or `null` to keep printing
   * the byte — the MSL page-state tints colour a byte the backend did send
   * (zero-filled), so they tint rather than void.
   */
  glyph: string | null;
  /**
   * Whether this cause means the cell carries NO byte. A void cell suppresses
   * the consensus tint; a tint-only cause composes with it as before.
   */
  voids: boolean;
  /** i18n key (`hex` namespace) for the per-cell `title`, or `null`. */
  titleKey: string | null;
  /** The modifier a `.md-variance-swatch` legend element carries, or `null`. */
  swatchClass: string | null;
  /** i18n key for the legend label, or `null` when it is not a legend entry. */
  labelKey: string | null;
}

export const ABSENCE_META: Record<AbsenceKind, AbsenceMeta> = {
  loading: {
    cellClass: "hex-loading",
    glyph: "··",
    voids: true,
    titleKey: "row.absence.loading",
    // Deliberately NOT in the legend: it is a transient state of this client,
    // not something to look for in the data.
    swatchClass: null,
    labelKey: null,
  },
  "no-correspondence": {
    cellClass: "byte-gap",
    glyph: "--",
    voids: true,
    titleKey: "row.absence.gap",
    swatchClass: "absence-gap",
    labelKey: "absence.legendGap",
  },
  "not-in-dump": {
    cellClass: "byte-absent",
    glyph: "--",
    voids: true,
    titleKey: "row.absence.notInDump",
    swatchClass: "absence-absent",
    labelKey: "absence.legendNotInDump",
  },
  error: {
    cellClass: "byte-error",
    glyph: "!!",
    voids: true,
    titleKey: "row.absence.error",
    swatchClass: "absence-error",
    labelKey: "absence.legendError",
  },
  // The two MSL page states keep their existing tints and their existing
  // behaviour: the byte IS there (the backend zero-fills a non-captured page),
  // so it is still printed and still classified.
  unmapped: {
    cellClass: "page-unmapped",
    glyph: null,
    voids: false,
    titleKey: null,
    swatchClass: null,
    labelKey: null,
  },
  failed: {
    cellClass: "page-failed",
    glyph: null,
    voids: false,
    titleKey: null,
    swatchClass: null,
    labelKey: null,
  },
};

/** The legend entries, in the order a reader meets them in the grid. */
export const ABSENCE_LEGEND: readonly AbsenceKind[] = [
  "no-correspondence",
  "not-in-dump",
  "error",
];

/**
 * An `.msl` PAGE STATE, as an absence kind — or `undefined` when the page says
 * nothing about this byte.
 *
 * The ladder existed twice, in `HexViewer` and in `HexOverlayPane`, and the
 * copies disagreed about the fall-through. They were BOTH right, which is why
 * this returns `undefined` and leaves the fall-through to the caller:
 *
 *  - `HexViewer` only ever consults it for a byte its chunk has not produced,
 *    so "CAPTURED", "not yet resolved" and "no page state at all" all mean the
 *    same thing there — the chunk has not arrived — and it answers `"loading"`.
 *  - `HexOverlayPane` consults it for EVERY byte, after the store has already
 *    said the byte is present. Answering `"loading"` there would hatch a byte
 *    the grid is printing.
 *
 * Note the caller still owns the coordinate gate: `getPageStateAt` reads
 * `vaSpanStart + offset`, so it only answers in the `"va"` view and feeding it
 * a `"vas"` or `"raw"` offset would tint a byte by another byte's page.
 */
export function absenceForPageState(
  pageState: string | undefined | null,
): AbsenceKind | undefined {
  if (pageState === "FAILED") return "failed";
  if (pageState === "UNMAPPED") return "unmapped";
  return undefined;
}
