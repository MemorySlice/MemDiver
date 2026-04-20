import { useMemo } from "react";
import { useTheme } from "@/providers/ThemeProvider";

function getCssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function usePlotlyTheme() {
  const { resolvedTheme } = useTheme();
  return useMemo(() => ({
    paper_bgcolor: getCssVar("--md-chart-paper"),
    plot_bgcolor: getCssVar("--md-chart-plot"),
    font: {
      color: getCssVar("--md-chart-text"),
      family: "JetBrains Mono, Cascadia Code, Fira Code, monospace",
      size: 11,
    },
    xaxis: { gridcolor: getCssVar("--md-chart-grid"), zerolinecolor: getCssVar("--md-chart-grid") },
    yaxis: { gridcolor: getCssVar("--md-chart-grid"), zerolinecolor: getCssVar("--md-chart-grid") },
    margin: { l: 50, r: 20, t: 40, b: 40 },
  }), [resolvedTheme]);
}

export function usePlotlyColors() {
  const { resolvedTheme } = useTheme();
  return useMemo(() => ({
    accentBlue: getCssVar("--md-accent-blue"),
    accentRed: getCssVar("--md-accent-red"),
    accentGreen: getCssVar("--md-accent-green"),
    accentCyan: getCssVar("--md-accent-cyan"),
    accentPurple: getCssVar("--md-accent-purple"),
    invariant: getCssVar("--md-variance-invariant"),
    structural: getCssVar("--md-variance-structural"),
    pointer: getCssVar("--md-variance-pointer"),
    keyCandidate: getCssVar("--md-variance-key-candidate"),
    heatmapPresent: getCssVar("--md-heatmap-present"),
    heatmapAbsent: getCssVar("--md-heatmap-absent"),
  }), [resolvedTheme]);
}
