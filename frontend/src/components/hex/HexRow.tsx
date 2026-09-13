import { memo, type ReactElement } from "react";
import { useTranslation } from "react-i18next";
import type { RegionIndex } from "./highlight-utils";
import { getRegionForOffset, highlightClass } from "./highlight-utils";
import { byteToHex, byteToAscii, offsetToHex } from "@/utils/hex-codec";
import type { HexViewMode } from "@/stores/hex-store";
import { ABSENCE_META, type AbsenceKind } from "@/utils/absence-classes";
import { VARIANCE_META, varianceCategoryForCode } from "@/utils/variance-classes";
import {
  GLYPH_IDENTICAL,
  GLYPH_VOID,
  VARIANT_COUNT_CAP,
  VARIANT_RAMP_STEPS,
  variantGlyph,
  variantRampClass,
  variantRampStep,
  variantUnderlineClass,
} from "@/utils/variant-ramp";
import type { OverlayRenderMode } from "@/stores/overlay-render-store";

/** Variance tiers for heatmap CSS classes (aligned with core/variance.py STRUCTURAL_MAX). */
const VAR_TIER_LOW = 50;
const VAR_TIER_HIGH = 200;

/**
 * ── Closed domains, resolved ONCE at module load ─────────────────────────────
 *
 * Every table below answers a question whose answer set is FINITE and known
 * before the first row renders: 256 byte values, five ramp steps, seven glyphs,
 * one grouping gap. The row loop used to re-derive each of them per cell, which
 * at the ~65 rows a frame actually renders is ~7,700 freshly allocated strings
 * and objects a frame for a few dozen distinct results.
 *
 * These are lookups, not caches: nothing is ever evicted and nothing can grow,
 * because the vocabulary modules they mirror (`hex-codec`, `variant-ramp`) are
 * the ones defining the domains.
 */
const HEX_BYTE: string[] = Array.from({ length: 256 }, (_, b) => byteToHex(b));
const ASCII_BYTE: string[] = Array.from({ length: 256 }, (_, b) => byteToAscii(b));
const RAMP_CLASS: string[] = Array.from({ length: VARIANT_RAMP_STEPS + 1 }, (_, step) =>
  variantRampClass(step),
);
const UNDERLINE_CLASS: string[] = Array.from(
  { length: VARIANT_RAMP_STEPS + 1 },
  (_, step) => variantUnderlineClass(step),
);
/** `variantGlyph` for counts `0..VARIANT_COUNT_CAP`; anything above reads as the cap. */
const VARIANT_GLYPH: (string | null)[] = Array.from(
  { length: VARIANT_COUNT_CAP + 1 },
  (_, n) => variantGlyph(n),
);

/** `variantGlyph`, off the table. */
function glyphFor(variants: number | undefined): string | null {
  if (variants === undefined) return null;
  if (variants <= 1) return GLYPH_IDENTICAL;
  return VARIANT_GLYPH[Math.min(variants, VARIANT_COUNT_CAP)];
}

/** Per-column React keys, grown on demand and never rebuilt. */
const HEX_KEYS: string[] = [];
const ASCII_KEYS: string[] = [];
function cellKeys(bytesPerRow: number): void {
  for (let i = HEX_KEYS.length; i < bytesPerRow; i++) {
    HEX_KEYS.push(`h${i}`);
    ASCII_KEYS.push(`a${i}`);
  }
}

/** The 8-byte grouping gap. One object for the whole app, not one per row. */
const GROUP_GAP_STYLE = { marginLeft: "6px" } as const;

/**
 * The `nb-*` class a neighborhood region's label implies, or `null`.
 *
 * A fact about the REGION, not about the byte — and a region spans many
 * consecutive cells, so the row loop remembers the last one it resolved rather
 * than lowercasing the same label sixteen times.
 */
function neighborhoodClass(label: string): string | null {
  const lower = label.toLowerCase();
  if (lower.startsWith("key")) return "nb-key";
  if (lower.startsWith("static")) return "nb-static";
  if (lower.startsWith("dynamic")) return "nb-dynamic";
  return null;
}


interface HexRowProps {
  rowOffset: number;
  getByteAt: (offset: number) => number | undefined;
  getVarianceAt?: (offset: number) => number | undefined;
  cursorOffset: number | null;
  selectionStart: number | null;
  selectionEnd: number | null;
  regionIndex: RegionIndex;
  bytesPerRow?: number;
  activeFieldStart?: number | null;
  activeFieldEnd?: number | null;
  overlayEnabled?: boolean;
  getClassificationAt?: (offset: number) => number | undefined;
  /**
   * The coordinate the rows are addressed in.
   *
   * Deliberately NOT consulted any more: it used to gate the page-state tints
   * behind `view === "va"`, which is precisely why a `"vas"` window painted
   * every absent byte as an anonymous `--`. Absence is a fact about the bytes,
   * not about the coordinate they are addressed in, so `getAbsenceAt` answers
   * it in every view. Kept on the props because all three viewers declare the
   * coordinate they are painting, and that is worth reading at the call site.
   */
  view?: HexViewMode;
  /**
   * WHY there is no byte at `offset` — see `@/utils/absence-classes`.
   *
   * Replaces the `view === "va"`-gated page-state block: the single-dump
   * viewer adapts its own `getPageStateAt` into this vocabulary, the
   * multi-dump viewers read `multi-hex-store.absenceAt`, and both then get the
   * SAME treatment for the same cause. Omitted, an unloaded byte falls back to
   * `"loading"`, which is what it always was.
   */
  getAbsenceAt?: (offset: number) => AbsenceKind | undefined;
  /**
   * Cross-dump disagreement at this offset, for the N-dump aligned overlay.
   *
   * Purely ADDITIVE: omitted (the single-dump viewer) it changes nothing, and
   * where it is supplied it only ever APPENDS `cross-dump-differs` — which
   * `hex.css` paints as an inset ring, never a background — so it composes with
   * the consensus, variance, search-highlight and page-state styling already on
   * the same byte instead of replacing any of it.
   */
  getDiffersAt?: (offset: number) => boolean;
  /**
   * How many DISTINCT byte values the aligned dumps hold at `offset`.
   *
   * A different question from `getClassificationAt`, which reports what the
   * backend consensus concluded. Read only in the `variants` and `glyph` render
   * modes; `undefined` means "no answer here yet" and paints nothing rather
   * than claiming agreement.
   */
  getVariantsAt?: (offset: number) => number | undefined;
  /**
   * Which reading of the aligned window this row paints — see
   * `@/stores/overlay-render-store`.
   *
   * The three modes are mutually EXCLUSIVE by construction, the same way the
   * absence and consensus vocabularies are: `class` paints the consensus bands
   * and the cross-dump ring, `variants` paints the distinct-value ramp, and
   * `glyph` paints the ramp *and* replaces the printed value with a mark that
   * needs no colour to read. A cell carrying two of these at once would make
   * one colour mean two things in the same grid.
   *
   * Defaults to `class`, so every caller that does not know about the switch —
   * the single-dump viewer and the side-by-side panes — is unaffected.
   */
  renderMode?: OverlayRenderMode;
  /**
   * SOLO view: paint the variance as an underline and leave the value alone.
   *
   * Set when the rail is showing ONE dump's own bytes instead of the overlay's
   * computed plurality. It OVERRIDES `renderMode` rather than composing with
   * it — which is exactly why the `Class │ Variants │ Glyph` switch dims in
   * solo — because all three modes describe a relationship between dumps and
   * there is only one dump on screen. What survives is the cross-dump variant
   * count, and it moves from a fill to a `border-bottom` so that the real byte
   * this dump holds stays readable. See `@/utils/variant-ramp`.
   */
  soloUnderline?: boolean;
}

export const HexRow = memo(function HexRow({
  rowOffset,
  getByteAt,
  getVarianceAt,
  cursorOffset,
  selectionStart,
  selectionEnd,
  regionIndex,
  bytesPerRow = 16,
  activeFieldStart = null,
  activeFieldEnd = null,
  overlayEnabled = false,
  getClassificationAt,
  getAbsenceAt,
  getDiffersAt,
  getVariantsAt,
  renderMode = "class",
  soloUnderline = false,
}: HexRowProps) {
  const { t } = useTranslation("hex");
  const hexCells: ReactElement[] = [];
  const asciiCells: ReactElement[] = [];
  cellKeys(bytesPerRow);

  // Solo takes the row out of the render-mode vocabulary entirely: with one
  // dump on screen, "class", "variants" and "glyph" are three names for the
  // same picture, and the underline below is the reading that still means
  // something. Both flags are row-invariant, so they are settled once here
  // rather than re-tested on all sixteen cells.
  const classMode = !soloUnderline && renderMode === "class";
  const glyphMode = !soloUnderline && renderMode === "glyph";
  // Fully constant strings, looked up once per row instead of once per cell.
  const variesText = t("ndump.variesNote");
  const absenceTitles: Record<string, string> = {};
  // The last region the loop resolved an `nb-*` class for. Regions are
  // contiguous, so this is a reference compare in place of a `toLowerCase`.
  let lastRegionLabel: string | null = null;
  let lastNeighborhoodClass: string | null = null;

  for (let i = 0; i < bytesPerRow; i++) {
    const byteOffset = rowOffset + i;
    const byteVal = getByteAt(byteOffset);
    const loaded = byteVal !== undefined;
    // WHY there is no byte here. A cell with no reader and no byte is simply
    // one whose window has not arrived, which is what it always meant.
    const absence: AbsenceKind | undefined =
      getAbsenceAt?.(byteOffset) ?? (loaded ? undefined : "loading");
    const absenceMeta = absence ? ABSENCE_META[absence] : undefined;
    /**
     * A VOID cell: no byte, and a stated reason for it.
     *
     * The `!loaded` half is not belt-and-braces. A cause that means "no byte"
     * must never blank a cell that HAS one, so a reader disagreeing with the
     * byte source resolves in favour of the byte — and the page-state causes,
     * whose bytes the backend really does send (zero-filled), stay tints.
     */
    const isVoidCell = absenceMeta?.voids === true && !loaded;

    // Determine classes
    const classes: string[] = [];
    const isCursor = cursorOffset === byteOffset;
    const isSelected =
      selectionStart !== null &&
      selectionEnd !== null &&
      byteOffset >= selectionStart &&
      byteOffset <= selectionEnd;

    if (isCursor) classes.push("cursor");
    if (isSelected) classes.push("selected");

    const isActiveField =
      activeFieldStart !== null &&
      activeFieldEnd !== null &&
      byteOffset >= activeFieldStart &&
      byteOffset < activeFieldEnd;
    if (isActiveField) classes.push("active-field");

    // Highlight region
    const region = getRegionForOffset(regionIndex, byteOffset);
    if (region) {
      classes.push(highlightClass(region.type));
      if (region.colorIndex !== undefined) {
        classes.push(`field-color-${region.colorIndex % 8}`);
      }
      if (region.type === "neighborhood") {
        if (region.label !== lastRegionLabel) {
          lastRegionLabel = region.label;
          lastNeighborhoodClass = neighborhoodClass(region.label);
        }
        if (lastNeighborhoodClass) classes.push(lastNeighborhoodClass);
      }
    }

    // Void cells take neither the variance tier nor the consensus class below.
    // This is the design's exclusivity rule made STRUCTURAL rather than
    // conventional: a hatched cell that also carried a class colour would say
    // "this byte is a key candidate" about a byte no dump holds.
    const varianceVal = isVoidCell ? undefined : getVarianceAt?.(byteOffset);
    if (varianceVal !== undefined) {
      if (varianceVal >= VAR_TIER_HIGH) classes.push("var-tier-3");
      else if (varianceVal >= VAR_TIER_LOW) classes.push("var-tier-2");
      else classes.push("var-tier-1");
    }

    if (classMode && overlayEnabled && getClassificationAt && !isVoidCell) {
      // Backend ByteClass code → the CSS class hex.css paints. An unknown or
      // gap code (-1) yields no category and therefore no class, rather than
      // defaulting to INVARIANT.
      const code = getClassificationAt(byteOffset);
      const category = code === undefined ? null : varianceCategoryForCode(code);
      if (category) {
        classes.push(VARIANCE_META[category].byteClass);
      }
    }

    /**
     * The distinct-value ramp, inside the SAME `!isVoidCell` gate as the class
     * branch above — for the same reason. A hatched cell that also carried a
     * ramp tint would say "three dumps disagree here" about a byte no dump
     * holds.
     *
     * `variantRampStep` supplies the design's rule: one variant (or none) gets
     * no background at all, so agreement stays the quiet background the signal
     * stands out against.
     */
    const variantCount = classMode || isVoidCell ? undefined : getVariantsAt?.(byteOffset);
    const rampStep = variantRampStep(variantCount);
    // One mark per cell: a fill in the overlay, a rule under the value in solo.
    // The branch is on the FLAG, never on both, so the two ramps can never
    // land on the same byte.
    if (rampStep !== null) {
      classes.push(soloUnderline ? UNDERLINE_CLASS[rampStep] : RAMP_CLASS[rampStep]);
    }

    // Cross-dump disagreement ring. Appended after the consensus class so the
    // ring reads as sitting ON TOP of the class colour; it carries no
    // background of its own, so nothing below is clobbered.
    //
    // Class mode only: in the other two the variant count already SAYS that the
    // dumps disagree, and ringing every tinted cell would double-encode one
    // fact as two marks — the noise that makes a grid unreadable.
    const differsAcrossDumps = classMode && (getDiffersAt?.(byteOffset) ?? false);
    if (differsAcrossDumps) classes.push(VARIANCE_META.differs.byteClass);

    // The absence treatment, composed LAST so a hatch or a page-state tint
    // reads as sitting on top of the search highlight and the selection —
    // neither of which it may clobber. A void cause only paints where there is
    // genuinely no byte; a page-state cause tints the zero-filled byte the
    // backend did send, exactly as it did before.
    if (absenceMeta && (!absenceMeta.voids || !loaded)) {
      classes.push(absenceMeta.cellClass);
    }

    const classStr = classes.join(" ");
    let tooltip = region?.label ?? "";
    if (varianceVal !== undefined) {
      const varText = t("row.variance", { value: varianceVal.toFixed(1) });
      tooltip = tooltip ? `${tooltip} | ${varText}` : varText;
    }
    // Cheap hover fallback for the cross-dump ring. The real affordance is
    // `OverlayByteInspector`, which a tooltip cannot replace — it shows a table
    // and is reachable by keyboard — but a hover that says nothing at all when
    // a byte is visibly ringed is worse than one word. Reuses NDumpOverlay's
    // existing string rather than adding a near-duplicate.
    if (differsAcrossDumps) {
      tooltip = tooltip ? `${tooltip} | ${variesText}` : variesText;
    }
    // In the two count-driven modes the hover carries the exact number, which
    // the ramp step deliberately does not: five steps cannot name six counts.
    if (variantCount !== undefined) {
      const variantText = t("row.variants", { n: variantCount });
      tooltip = tooltip ? `${tooltip} | ${variantText}` : variantText;
    }
    // The whole point of the vocabulary is that the analyst can find out WHICH
    // absence this is without consulting a legend.
    if (isVoidCell && absenceMeta?.titleKey) {
      // Four possible keys across the whole vocabulary; `t` is asked once each.
      const titleKey = absenceMeta.titleKey;
      const absenceText = (absenceTitles[titleKey] ??= t(titleKey));
      tooltip = tooltip ? `${tooltip} | ${absenceText}` : absenceText;
    }

    /**
     * What the hex column prints.
     *
     * `glyph` mode trades the byte value for a mark that survives greyscale,
     * a monochrome print and every form of colour blindness. A void cell keeps
     * its absence CLASS — and therefore its hatch and its `title`, which is
     * where the four causes stay told apart — but prints the design's single
     * `░`, because in this mode the reader is scanning marks, not values.
     */
    let printed: string;
    if (glyphMode) {
      printed = isVoidCell
        ? GLYPH_VOID
        : (glyphFor(variantCount) ?? (loaded ? HEX_BYTE[byteVal] : "--"));
    } else {
      printed = loaded ? HEX_BYTE[byteVal] : (absenceMeta?.glyph ?? "--");
    }

    // Add gap after 8th byte for visual grouping
    const extraStyle = i === 8 ? GROUP_GAP_STYLE : undefined;

    hexCells.push(
      <span
        key={HEX_KEYS[i]}
        data-offset={byteOffset}
        data-col="hex"
        className={`hex-byte ${classStr}`}
        style={extraStyle}
        title={tooltip || undefined}
      >
        {printed}
      </span>
    );

    asciiCells.push(
      <span
        key={ASCII_KEYS[i]}
        data-offset={byteOffset}
        data-col="ascii"
        className={`hex-char ${classStr}`}
        title={tooltip || undefined}
      >
        {loaded ? ASCII_BYTE[byteVal] : "."}
      </span>
    );
  }

  return (
    <div className="hex-row">
      <span className="hex-offset">{offsetToHex(rowOffset)}</span>
      <span className="hex-bytes">{hexCells}</span>
      <span className="hex-separator" />
      <span className="hex-ascii">{asciiCells}</span>
    </div>
  );
});
