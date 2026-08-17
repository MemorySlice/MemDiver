/**
 * VarianceMap dispatcher. See ./EntropyChart.tsx for design rationale
 * and ./ChartDispatcher.tsx for the shared retry/lazy/Suspense/
 * ErrorBoundary wiring this delegates to.
 */
import { ChartDispatcher } from "@/components/charts/ChartDispatcher";
import type { VarianceMapProps } from "./types";

export function VarianceMap(props: VarianceMapProps) {
  return (
    <ChartDispatcher<VarianceMapProps>
      loadPlotly={() => import("./plotly/VarianceMap")}
      loadSvg={() => import("./svg/VarianceMap")}
      {...props}
    />
  );
}
