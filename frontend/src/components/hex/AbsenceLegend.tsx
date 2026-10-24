import { useTranslation } from "react-i18next";

import { VarianceSwatch } from "@/components/common/VarianceSwatch";
import { usePageStateTintsActive } from "@/hooks/usePageStateTintsActive";
import {
  ABSENCE_LEGEND,
  ABSENCE_META,
  isPageStateAbsence,
  type AbsenceKind,
} from "@/utils/absence-classes";

export interface AbsenceLegendProps {
  /**
   * Whether the grid this legend sits over can paint the MSL page-state tints
   * (failed / unmapped / not resident). Only the viewers that consult
   * `getPageStateAt` can; a legend entry for a tint the grid never paints
   * teaches a colour the analyst will not find. Even when `true`, the entries
   * appear only while page states are actually loaded for the "va" view —
   * see `usePageStateTintsActive`.
   */
  pageStates?: boolean;
  /**
   * Whether the page-state tints are live for THIS grid, overriding the
   * single-view gate (`usePageStateTintsActive`, which reads `hex-store`).
   * The aligned panes read their page states from the aligned window instead,
   * so they pass `useAlignedPageStateTintsActive()` here. Still requires
   * `pageStates`. Omitted = the single-view gate, as before.
   */
  pageStatesActive?: boolean;
  /** Restrict the legend to these kinds (default: the whole `ABSENCE_LEGEND`). */
  kinds?: readonly AbsenceKind[];
}

/**
 * The ways a cell can hold no byte, as swatches — plus, where the grid paints
 * them, the MSL page states that tint a zero-filled byte.
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
export function AbsenceLegend({
  pageStates = false,
  pageStatesActive,
  kinds = ABSENCE_LEGEND,
}: AbsenceLegendProps) {
  const { t } = useTranslation("hex");
  const pageStateTintsActive = usePageStateTintsActive();
  const showPageStates = pageStates && (pageStatesActive ?? pageStateTintsActive);
  return (
    <>
      {kinds.map((kind) => {
        const meta = ABSENCE_META[kind];
        if (!meta.swatchClass || !meta.labelKey) return null;
        if (isPageStateAbsence(kind) && !showPageStates) return null;
        return (
          <VarianceSwatch
            key={kind}
            testId={`hex-absence-legend-${meta.swatchClass}`}
            className="md-text-muted"
            swatchClass={meta.swatchClass}
            label={t(meta.labelKey)}
            title={meta.titleKey ? t(meta.titleKey) : undefined}
          />
        );
      })}
    </>
  );
}
