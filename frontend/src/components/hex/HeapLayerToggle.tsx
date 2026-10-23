/**
 * Hex-toolbar switch for the heap role layer. Offered only in heap mode
 * (where the layer is turned on for the active dump) so the analyst can hide
 * it to read the plain bytes underneath without leaving the mode.
 */

import { useTranslation } from "react-i18next";

import { useAppStore } from "@/stores/app-store";
import { selectHeapLayerEnabled, useHeapStore } from "@/stores/heap-store";

export function HeapLayerToggle({ dumpPath }: { dumpPath: string | null }) {
  const { t } = useTranslation("heap");
  const heapMode = useAppStore((s) => s.mode === "heap");
  const enabled = useHeapStore(selectHeapLayerEnabled(dumpPath));
  const toggleLayer = useHeapStore((s) => s.toggleLayer);

  if (!heapMode || !dumpPath) return null;
  return (
    <button
      type="button"
      onClick={() => toggleLayer(dumpPath)}
      aria-pressed={enabled}
      title={t(enabled ? "layer.disable" : "layer.enable")}
      data-testid="heap-layer-toggle"
      className={`px-2 py-0.5 rounded border border-[var(--md-border)] shrink-0 ${
        enabled ? "md-bg-cyan-subtle font-semibold" : "hover:bg-[var(--md-bg-hover)]"
      }`}
    >
      {t("layer.toggle")}
    </button>
  );
}
