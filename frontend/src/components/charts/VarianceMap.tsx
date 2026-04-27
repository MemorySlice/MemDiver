/**
 * VarianceMap dispatcher. See ./EntropyChart.tsx for design rationale.
 */
import { lazy, Suspense } from "react";
import { useSettingsStore } from "@/stores/settings-store";
import type { VarianceMapProps } from "./types";

const PlotlyImpl = lazy(() => import("./plotly/VarianceMap"));
const SvgImpl = lazy(() => import("./svg/VarianceMap"));

export function VarianceMap(props: VarianceMapProps) {
  const backend = useSettingsStore((s) => s.display.chartBackend);
  const Impl = backend === "svg" ? SvgImpl : PlotlyImpl;
  return (
    <Suspense fallback={null}>
      <Impl {...props} />
    </Suspense>
  );
}
