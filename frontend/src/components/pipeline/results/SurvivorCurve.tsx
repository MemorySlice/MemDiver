/**
 * SurvivorCurve dispatcher. Reads `settings.display.chartBackend` and
 * delegates to Plotly or SVG implementation. Both are lazy-loaded for
 * code splitting (Plotly chunk is ~2.3 MB).
 *
 * Call sites continue to import `{ SurvivorCurve }` from this path.
 */
import { lazy, Suspense } from "react";
import { useSettingsStore } from "@/stores/settings-store";

const PlotlyImpl = lazy(() => import("./plotly/SurvivorCurve"));
const SvgImpl = lazy(() => import("./svg/SurvivorCurve"));

export function SurvivorCurve() {
  const backend = useSettingsStore((s) => s.display.chartBackend);
  const Impl = backend === "svg" ? SvgImpl : PlotlyImpl;
  return (
    <Suspense fallback={null}>
      <Impl />
    </Suspense>
  );
}
