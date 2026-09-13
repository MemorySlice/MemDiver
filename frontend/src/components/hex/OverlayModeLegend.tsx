import { useTranslation } from "react-i18next";

import { VarianceSwatch } from "@/components/common/VarianceSwatch";
import { ABSENCE_META } from "@/utils/absence-classes";
import {
  GLYPH_IDENTICAL,
  GLYPH_VOID,
  VARIANT_RAMP_STEPS,
  variantRampClass,
} from "@/utils/variant-ramp";
import type { OverlayRenderMode } from "@/stores/overlay-render-store";
import { VarianceClassChips } from "./VarianceClassChips";

/** `1 … VARIANT_RAMP_STEPS`, for the ramp strip. */
const RAMP = Array.from({ length: VARIANT_RAMP_STEPS }, (_, i) => i + 1);

/**
 * The legend for the ACTIVE render mode, and only that one.
 *
 * Showing all three at once would be the same mistake the mode switch exists to
 * avoid: three vocabularies competing for the same grid. The legend is the
 * contract for what is currently on screen, so it changes with the mode.
 *
 * Every entry reads the same tokens and the same class names as the byte rules
 * in `hex.css`, so a legend cannot drift from the grid it explains.
 */
export function OverlayModeLegend({ mode }: { mode: OverlayRenderMode }) {
  const { t } = useTranslation("hex");

  if (mode === "class") {
    /*
      The five coloured words that used to live here are now `<button>`s.
      Nothing was lost — each chip still carries the class swatch and the same
      `ndump.legend*` string — and two things were gained: a COUNT, and the
      click that answers "where are the others?". `VarianceClassChips` owns the
      absence legend and the colour explainer too, so this branch stays what it
      always was: one expression of "the legend for `class` mode".

      It is deliberately NOT rendered in the other two modes. The legend is the
      contract for what is on screen, and `variants` / `glyph` do not paint the
      class palette at all — a class chip beside a variant ramp would offer a
      colour key for colours the grid is not using.
    */
    return <VarianceClassChips />;
  }

  if (mode === "variants") {
    return (
      <span
        data-testid="hex-overlay-legend-ramp"
        className="inline-flex items-center gap-1 md-text-muted"
      >
        {/*
          The identical end carries NO swatch, because an identical byte carries
          no tint. A swatch here would promise a colour the grid never paints.
        */}
        <span>{t("renderMode.legendIdentical")}</span>
        {RAMP.map((step) => (
          <span
            key={step}
            aria-hidden="true"
            data-testid={`hex-overlay-legend-variant-${step}`}
            className={`md-variance-swatch ${variantRampClass(step)}`}
          />
        ))}
        <span>{t("renderMode.legendMaxVariants")}</span>
        <VarianceSwatch
          swatchTestId="hex-overlay-legend-void"
          swatchClass={ABSENCE_META["no-correspondence"].swatchClass!}
          label={t("renderMode.legendVoid")}
        />
      </span>
    );
  }

  return (
    <span
      data-testid="hex-overlay-legend-glyphs"
      className="inline-flex items-center gap-3 md-text-muted"
    >
      <span className="inline-flex items-center gap-1">
        <span aria-hidden="true">{GLYPH_IDENTICAL}</span>
        {t("renderMode.legendGlyphIdentical")}
      </span>
      <span className="inline-flex items-center gap-1">
        <span aria-hidden="true">2–6</span>
        {t("renderMode.legendGlyphVariants")}
      </span>
      <span className="inline-flex items-center gap-1">
        <span aria-hidden="true">{GLYPH_VOID}</span>
        {t("renderMode.legendGlyphVoid")}
      </span>
    </span>
  );
}
