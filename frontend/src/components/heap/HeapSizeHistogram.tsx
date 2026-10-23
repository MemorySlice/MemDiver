/**
 * Chunk-size histogram dispatcher: Plotly or SVG per
 * `settings.display.chartBackend`, both lazy, via the shared
 * `ChartDispatcher` (see `@/components/charts/VarianceMap.tsx`).
 */
import { ChartDispatcher } from "@/components/charts/ChartDispatcher";
import type { HeapSizeHistogramProps } from "./histogram-types";

export function HeapSizeHistogram(props: HeapSizeHistogramProps) {
  return (
    <ChartDispatcher<HeapSizeHistogramProps>
      loadPlotly={() => import("./plotly/HeapSizeHistogram")}
      loadSvg={() => import("./svg/HeapSizeHistogram")}
      {...props}
    />
  );
}
