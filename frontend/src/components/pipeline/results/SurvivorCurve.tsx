/**
 * SurvivorCurve dispatcher. Reads `settings.display.chartBackend` and
 * delegates to Plotly or SVG implementation. Both are lazy-loaded for
 * code splitting (Plotly chunk is ~2.3 MB).
 *
 * Call sites continue to import `{ SurvivorCurve }` from this path.
 *
 * See @/components/charts/ChartDispatcher.tsx for the shared
 * retry/lazy/Suspense/ErrorBoundary wiring this delegates to.
 */
import { ChartDispatcher } from "@/components/charts/ChartDispatcher";

export function SurvivorCurve() {
  return (
    <ChartDispatcher
      loadPlotly={() => import("./plotly/SurvivorCurve")}
      loadSvg={() => import("./svg/SurvivorCurve")}
    />
  );
}
