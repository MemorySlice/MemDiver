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
 *
 * See ChartDispatcher.tsx for the shared retry/lazy/Suspense/
 * ErrorBoundary wiring this delegates to.
 */
import { ChartDispatcher } from "@/components/charts/ChartDispatcher";
import type { EntropyChartProps } from "./types";

export function EntropyChart(props: EntropyChartProps) {
  return (
    <ChartDispatcher<EntropyChartProps>
      loadPlotly={() => import("./plotly/EntropyChart")}
      loadSvg={() => import("./svg/EntropyChart")}
      {...props}
    />
  );
}
