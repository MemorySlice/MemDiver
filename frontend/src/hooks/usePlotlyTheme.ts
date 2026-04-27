/**
 * Legacy thin shim over `useChartTheme()` kept so existing Plotly chart
 * call sites (EntropyChart, VarianceMap, VasChart) keep compiling without
 * churn. New charts should consume `useChartTheme()` directly and pick
 * the slice (`.plotly` / `.plotlyColors` / `.svg`) they need.
 */
import { useChartTheme } from "./useChartTheme";

export function usePlotlyTheme() {
  return useChartTheme().plotly;
}

export function usePlotlyColors() {
  return useChartTheme().plotlyColors;
}
