import { useTranslation } from "react-i18next";

import { VarianceSwatch } from "@/components/common/VarianceSwatch";
import { ABSENCE_LEGEND, ABSENCE_META } from "@/utils/absence-classes";

/**
 * The three ways a cell can hold no byte, as swatches.
 *
 * Swatches rather than words because the treatments (two hatches and a ruled
 * tint) are what the analyst has to recognise on sight, and because a legend
 * that shows only a COLOUR teaches the wrong thing to look for — the same
 * argument `hex.css` makes for the `differs` ring.
 *
 * Shared by both multi-dump viewers so the side-by-side grid and the overlay
 * cannot end up calling the same hatch two different things. `loading` is
 * deliberately absent: it is a state of this client, not a finding.
 */
export function AbsenceLegend() {
  const { t } = useTranslation("hex");
  return (
    <>
      {ABSENCE_LEGEND.map((kind) => {
        const meta = ABSENCE_META[kind];
        if (!meta.swatchClass || !meta.labelKey) return null;
        return (
          <VarianceSwatch
            key={kind}
            testId={`hex-absence-legend-${meta.swatchClass}`}
            className="md-text-muted"
            swatchClass={meta.swatchClass}
            label={t(meta.labelKey)}
          />
        );
      })}
    </>
  );
}
