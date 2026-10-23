import { useTranslation } from "react-i18next";

import { HEAP_ROLES } from "@/api/heap";
import { selectHeapDump, useHeapStore } from "@/stores/heap-store";
// The swatch table moved to `@/utils/heap-roles` so the overlay's Heap render
// mode legend reads the very same classes.
import { HEAP_ROLE_SWATCH as ROLE_SWATCH } from "@/utils/heap-roles";

interface Props {
  dumpPath: string;
}

/**
 * Legend entries for the heap role layer, rendered inside `HexLegend` while
 * the layer is on. Every swatch reads the same `--md-hl-heap-*` token as its
 * byte rule, so the legend cannot drift from the grid.
 */
export function HeapLegend({ dumpPath }: Props) {
  const { t } = useTranslation("heap");
  const layerError = useHeapStore((s) => selectHeapDump(dumpPath)(s).layerError);

  return (
    <span className="flex items-center gap-2 flex-wrap" data-testid="heap-legend">
      <span className="font-semibold">{t("legend.title")}</span>
      {HEAP_ROLES.map((role) => (
        <span key={role} className="flex items-center gap-1" data-heap-role={role}>
          <span className={`md-variance-swatch ${ROLE_SWATCH[role]}`} aria-hidden="true" />
          <span>{t(`roles.${role}`)}</span>
        </span>
      ))}
      <span className="flex items-center gap-1">
        <span className="md-variance-swatch heap-swatch-chunk-start" aria-hidden="true" />
        <span>{t("legend.chunkStart")}</span>
      </span>
      {layerError && (
        <span className="md-text-error" role="status" title={layerError}>
          {t("legend.layerError")}
        </span>
      )}
    </span>
  );
}
