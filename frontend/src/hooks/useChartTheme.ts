/**
 * Backend-agnostic chart theme hook.
 *
 * Returns:
 *   - `plotly`: layout fragment consumed by Plotly-based charts (shape
 *     identical to the legacy `usePlotlyTheme()` return value so call
 *     sites don't churn).
 *   - `plotlyColors`: accent + variance palette for Plotly charts.
 *   - `svg`: `chartTokens()` result — the SVG-friendly token map used by
 *     hand-rolled SVG charts (ConvergenceChart, ConsensusChart, and the
 *     new svg/ implementations).
 *   - `resolvedTheme`, `highContrast`: observed theme flags for callers
 *     that need to branch on them (e.g. choosing a different line style).
 *
 * The hook re-memoises on theme change so Plotly's layout object identity
 * rotates, ensuring Plotly picks up new colors even though the underlying
 * CSS vars also drive it. SVG charts read tokens at render time via
 * `chartTokens()` and are theme-reactive automatically.
 */
import { useMemo } from "react";
import { useTheme } from "@/providers/ThemeProvider";
import { chartTokens } from "@/components/charts/tokens";

export function useChartTheme() {
  const { resolvedTheme, highContrast } = useTheme();

  return useMemo(() => {
    // One getComputedStyle call amortized across every CSS var lookup,
    // rather than re-reading the root element per variable.
    const style = typeof window === "undefined"
      ? null
      : getComputedStyle(document.documentElement);
    const read = (name: string) => (style ? style.getPropertyValue(name).trim() : "");

    const plotly = {
      paper_bgcolor: read("--md-chart-paper"),
      plot_bgcolor: read("--md-chart-plot"),
      font: {
        color: read("--md-chart-text"),
        family: "JetBrains Mono, Cascadia Code, Fira Code, monospace",
        size: 11,
      },
      xaxis: {
        gridcolor: read("--md-chart-grid"),
        zerolinecolor: read("--md-chart-grid"),
      },
      yaxis: {
        gridcolor: read("--md-chart-grid"),
        zerolinecolor: read("--md-chart-grid"),
      },
      margin: { l: 50, r: 20, t: 40, b: 40 },
    };

    const plotlyColors = {
      accentBlue: read("--md-accent-blue"),
      accentRed: read("--md-accent-red"),
      accentGreen: read("--md-accent-green"),
      accentCyan: read("--md-accent-cyan"),
      accentPurple: read("--md-accent-purple"),
      invariant: read("--md-variance-invariant"),
      structural: read("--md-variance-structural"),
      pointer: read("--md-variance-pointer"),
      keyCandidate: read("--md-variance-key-candidate"),
      heatmapPresent: read("--md-heatmap-present"),
      heatmapAbsent: read("--md-heatmap-absent"),
    };

    const svg = chartTokens();

    return { plotly, plotlyColors, svg, resolvedTheme, highContrast };
  }, [resolvedTheme, highContrast]);
}
