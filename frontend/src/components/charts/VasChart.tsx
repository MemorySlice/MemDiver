/**
 * VasChart dispatcher. See ./EntropyChart.tsx for design rationale.
 */
import { lazy, Suspense } from "react";
import { useSettingsStore } from "@/stores/settings-store";
import type { VasChartProps } from "./types";

const PlotlyImpl = lazy(() => import("./plotly/VasChart"));
const SvgImpl = lazy(() => import("./svg/VasChart"));

export function VasChart(props: VasChartProps) {
  const backend = useSettingsStore((s) => s.display.chartBackend);
  const Impl = backend === "svg" ? SvgImpl : PlotlyImpl;
  return (
    <Suspense fallback={null}>
      <Impl {...props} />
    </Suspense>
  );
}
