import { useTranslation } from "react-i18next";

import { useVarianceRegionsLoader } from "@/hooks/useVarianceRegions";
import { useConsensusStore } from "@/stores/consensus-store";
import { useOverlayDetailStore } from "@/stores/overlay-detail-store";
import {
  useVarianceRegionsStore,
  type VarianceBrowseCategory,
} from "@/stores/variance-regions-store";
import { NON_INVARIANT_UNION } from "@/api/consensus-regions";
import type { ByteClassName } from "@/api/candidates";
import { VARIANCE_CATEGORIES, VARIANCE_META } from "@/utils/variance-classes";
import { AbsenceLegend } from "./AbsenceLegend";

/**
 * The legend, made CLICKABLE — "click pointer, land on a pointer".
 *
 * The five coloured words this replaces said what the colours mean and stopped
 * there: the analyst could see that a byte on screen is a key candidate and had
 * no way to ask where the OTHER key candidates are. Each chip is now a real
 * `<button aria-pressed>` that selects a category in `variance-regions-store`
 * and reveals `VarianceClassBrowser` in the detail panel.
 *
 * ── The sixth chip is the one that works ────────────────────────────────────
 * `Changing` maps to the server's NON-INVARIANT UNION, and it is the default
 * selection because a per-class query does not find key material. Measured on
 * real data: a planted 48-byte TLS secret classifies as 27 key_candidate + 18
 * pointer + 3 structural bytes, so `classes=["key_candidate"], min_length=8`
 * returns **total 0** — the secret is shattered into sub-8-byte shards and lost
 * entirely. The four class chips are still worth having (they answer "show me
 * the pointers"), but they are not the way in, and the explainer says so.
 *
 * ── Why the counts are WHOLE-BUILD, not window-scoped ───────────────────────
 * `counts` is the histogram the regions endpoint ships with page one, over the
 * entire build. A window-scoped count would change as the user scrolls, and a
 * chip reading "Key candidate (0)" because this screen happens to hold none
 * reads as "this dump has none" — the same silent lie `getClassAt`'s
 * `-1 -> undefined` mapping exists to refuse. `differs` is the ONE genuine
 * exception: there is no server-side whole-dump enumeration of cross-dump
 * disagreement, so its count is what is loaded and it is labelled "in view"
 * rather than dressed up as a total.
 */

/** The six chips, in the order they are rendered. See the module doc. */
const BROWSE_CHIPS: readonly VarianceBrowseCategory[] = [
  ...VARIANCE_CATEGORIES,
  NON_INVARIANT_UNION,
];

/** The classes the union covers — `core.variance`'s three non-invariant bands. */
const UNION_CLASSES: readonly ByteClassName[] = ["structural", "pointer", "key_candidate"];

/**
 * `1234567` -> `1,234,567`. Grouped so a byte count is readable at a glance.
 *
 * Pinned to `en-US` rather than left to `toLocaleString()`'s ambient default:
 * `en` is the only locale this app ships, and the host default makes the SAME
 * number render `9,000` on one machine and `9.000` on another — which is a
 * different number to an English reader, and made a legend assertion pass or
 * fail on the developer's system settings.
 */
const GROUPED = new Intl.NumberFormat("en-US");

function formatCount(n: number): string {
  return GROUPED.format(n);
}

/**
 * How many BYTES this chip stands for, or `null` for "no honest answer yet".
 *
 * `null` is rendered as a dash, never as `0`: before page one lands the store
 * has no histogram, and "Pointer (0)" would be a claim about the dump rather
 * than about the request.
 */
function chipCount(
  category: VarianceBrowseCategory,
  counts: Partial<Record<ByteClassName, number>>,
  differsTotal: number | null,
): number | null {
  if (category === "differs") return differsTotal;
  if (category === NON_INVARIANT_UNION) {
    const known = UNION_CLASSES.filter((name) => counts[name] !== undefined);
    if (known.length === 0) return null;
    return known.reduce((sum, name) => sum + (counts[name] ?? 0), 0);
  }
  return counts[category] ?? null;
}

/**
 * The browse vocabulary: the five variance classes, PLUS the union chip.
 *
 * Derived from `VARIANCE_META` rather than replacing it, and deliberately kept
 * module-local. Widening `VARIANCE_META` itself with a `non_invariant` row
 * would put a category into the map `HexRow` reads for `byteClass` — and there
 * is no such byte class, because the union is a QUERY over three bands, not a
 * fourth colour the grid ever paints.
 *
 * The union's own swatch is a blend of the three bands it covers.
 */
const BROWSE_META: Record<VarianceBrowseCategory, { labelKey: string; swatchClass: string }> = {
  ...VARIANCE_META,
  [NON_INVARIANT_UNION]: {
    labelKey: "regions.category.changing",
    swatchClass: "variance-non-invariant",
  },
};

export function VarianceClassChips() {
  const { t } = useTranslation("hex");

  // The single mounted loader. Living here — in the always-present legend —
  // rather than in the browser means the counts are real before the user has
  // opened the Regions tab, which is what makes the chips worth clicking.
  useVarianceRegionsLoader();

  const category = useVarianceRegionsStore((s) => s.category);
  const counts = useVarianceRegionsStore((s) => s.counts);
  const total = useVarianceRegionsStore((s) => s.total);
  const windowScoped = useVarianceRegionsStore((s) => s.windowScoped);
  const selectCategory = useVarianceRegionsStore((s) => s.selectCategory);
  const setTab = useOverlayDetailStore((s) => s.setTab);

  // Only meaningful while `differs` is the loaded category — the runs are
  // derived from the byte cache, so there is nothing to count otherwise.
  const differsTotal = category === "differs" && windowScoped ? total : null;

  return (
    <div
      role="group"
      aria-label={t("regions.chipsLabel")}
      data-testid="hex-overlay-class-chips"
      className="flex flex-wrap items-center gap-1"
    >
      {BROWSE_CHIPS.map((chip) => {
        const count = chipCount(chip, counts, differsTotal);
        const pressed = category === chip;
        return (
          <button
            key={chip}
            type="button"
            aria-pressed={pressed}
            data-testid={`hex-overlay-class-chip-${chip}`}
            title={
              chip === "differs"
                ? t("regions.differsWindowOnly")
                : t("regions.chipTitle", { label: t(BROWSE_META[chip].labelKey) })
            }
            onClick={() => {
              selectCategory(chip);
              // The list is in the OTHER pane; selecting a class without
              // revealing it would look like the chip did nothing.
              setTab("regions");
            }}
            className={
              "inline-flex items-center gap-1 px-1.5 py-0.5 rounded border " +
              (pressed
                ? "border-[var(--md-accent)] bg-[var(--md-bg-tertiary)] font-medium"
                : "border-transparent hover:bg-[var(--md-bg-hover)]")
            }
          >
            <span
              aria-hidden="true"
              data-testid={`hex-overlay-class-swatch-${chip}`}
              className={`md-variance-swatch ${BROWSE_META[chip].swatchClass}`}
            />
            <span>{t(BROWSE_META[chip].labelKey)}</span>{" "}
            {/*
              Inside the button, so the count is part of the ACCESSIBLE NAME —
              "Pointer 1,204 bytes" — rather than a visual-only decoration a
              screen-reader user would have to go hunting for.
            */}
            <span className="md-text-muted">
              {count === null
                ? t("regions.countUnknown")
                : chip === "differs"
                  ? t("regions.countInView", { value: formatCount(count) })
                  : t("regions.countBytes", { value: formatCount(count) })}
            </span>
          </button>
        );
      })}
      {/*
        The absence vocabulary belongs in the SAME strip as the classes: a byte
        present in some dumps and absent in others is a finding of its own, and
        the one thing it must never be confused with is a mismatch. It is not
        clickable because there is no server-side enumeration of it to browse.
      */}
      <AbsenceLegend />
      <VarianceColourLegend />
    </div>
  );
}

/**
 * What the colours MEAN, in terms of cross-dump variance.
 *
 * A `<details>`/`<summary>`, modelled on `CandidateLegend`: axe-clean and
 * keyboard-operable with no JavaScript, and collapsed by default so it costs
 * the legend strip one word.
 *
 * The band boundaries are read from the build's OWN `thresholds`, echoed by
 * `POST /api/analysis/consensus` from `core.variance`. They are deliberately
 * not written here: a hard-coded `0 / 200 / 3000` would be a second copy of
 * those bands, and the first thing a caller with custom thresholds would see is
 * a legend confidently describing a classification that never ran.
 */
export function VarianceColourLegend() {
  const { t } = useTranslation("hex");
  const thresholds = useConsensusStore((s) => s.thresholds);

  const band = (key: string, value: number | undefined) =>
    value === undefined ? null : <> {t(key, { value: formatCount(value) })}</>;

  return (
    <details className="text-[11px]" data-testid="hex-overlay-colour-legend">
      <summary className="cursor-pointer md-text-muted">
        {t("varianceLegend.summary")}
      </summary>
      <div className="mt-1 space-y-1.5 md-text-muted max-w-prose">
        <ul className="space-y-0.5">
          {VARIANCE_CATEGORIES.map((name) => {
            const meta = VARIANCE_META[name];
            return (
              <li key={name} className="flex items-start gap-1">
                {/*
                  Left as bare elements rather than a `VarianceSwatch`: this row
                  is `items-start` with a `mt-0.5` chip so the swatch aligns to
                  the FIRST line of a description that wraps, and the shared
                  component is deliberately `items-center`. It already carries
                  the `aria-hidden` that component exists to guarantee.
                */}
                <span
                  aria-hidden="true"
                  className={`md-variance-swatch ${meta.swatchClass} mt-0.5 shrink-0`}
                />
                <span>
                  <span className="font-medium">{t(meta.labelKey)}</span>
                  {/* The band the BUILD was cut at, named by the meta map rather
                      than rebuilt as a five-entry record on every iteration. */}
                  {band(
                    `varianceLegend.band.${name}`,
                    meta.thresholdKey ? thresholds?.[meta.thresholdKey] : undefined,
                  )}{" "}
                  {t(meta.descriptionKey)}
                </span>
              </li>
            );
          })}
        </ul>
        {thresholds === null && <p>{t("varianceLegend.thresholdsUnknown")}</p>}
        <p>{t("varianceLegend.invariantDimmed")}</p>
        <p>{t("varianceLegend.differsRing")}</p>
        <p>{t("varianceLegend.mixedClass")}</p>
      </div>
    </details>
  );
}
