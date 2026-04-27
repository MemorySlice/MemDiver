/**
 * EntropyChart dispatcher.
 *
 * Reads `settings.display.chartBackend` from the settings store and
 * renders the matching implementation. Both implementations are
 * lazy-loaded so the Plotly chunk is code-split away from the main
 * bundle — users who never switch to Plotly (or who stay on SVG) don't
 * pay the ~2.3 MB download.
 *
 * Call sites continue to `import { EntropyChart } from
 * "@/components/charts/EntropyChart"` — no churn elsewhere.
 */
import { lazy, Suspense } from "react";
import { useSettingsStore } from "@/stores/settings-store";
import type { EntropyChartProps } from "./types";

const PlotlyImpl = lazy(() => import("./plotly/EntropyChart"));
const SvgImpl = lazy(() => import("./svg/EntropyChart"));

export function EntropyChart(props: EntropyChartProps) {
  const backend = useSettingsStore((s) => s.display.chartBackend);
  const Impl = backend === "svg" ? SvgImpl : PlotlyImpl;
  return (
    <Suspense fallback={null}>
      <Impl {...props} />
    </Suspense>
  );
}
