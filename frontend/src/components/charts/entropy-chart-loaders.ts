/**
 * Module loaders for the two EntropyChart implementations, shared by the
 * dispatcher (`./EntropyChart.tsx`) and by callers that want the chart code
 * warm before they render it (see `preloadEntropyChart`). Kept out of the
 * component file so React Fast Refresh keeps working there.
 */
import { useSettingsStore } from "@/stores/settings-store";
import { loadChartModule } from "./chart-module-cache";

export const loadPlotlyEntropyChart = () => import("./plotly/EntropyChart");
export const loadSvgEntropyChart = () => import("./svg/EntropyChart");

/**
 * Start downloading + evaluating the chart implementation for the current
 * backend without rendering it. Called while the entropy request is in
 * flight, so the (multi-MB) Plotly chunk is ready when the data lands instead
 * of being fetched only after it; once resolved, ChartDispatcher renders it
 * without suspending (see chart-module-cache.ts). Failures are
 * swallowed here: the real render path reports them through its error
 * boundary (with Retry).
 */
export function preloadEntropyChart(): Promise<unknown> {
  const backend = useSettingsStore.getState().display.chartBackend;
  const load = backend === "svg" ? loadSvgEntropyChart : loadPlotlyEntropyChart;
  return loadChartModule(load).catch(() => undefined);
}
