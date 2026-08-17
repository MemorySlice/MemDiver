/**
 * VasChart dispatcher. See ./EntropyChart.tsx for design rationale and
 * ./ChartDispatcher.tsx for the shared retry/lazy/Suspense/
 * ErrorBoundary wiring this delegates to.
 */
import { ChartDispatcher } from "@/components/charts/ChartDispatcher";
import type { VasChartProps } from "./types";

export function VasChart(props: VasChartProps) {
  return (
    <ChartDispatcher<VasChartProps>
      loadPlotly={() => import("./plotly/VasChart")}
      loadSvg={() => import("./svg/VasChart")}
      {...props}
    />
  );
}
