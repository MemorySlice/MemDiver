/**
 * Shared trace palette for the SurvivorCurve Plotly + SVG renderers.
 * Keeping one definition means both backends stay visually coherent.
 */
export const SURVIVOR_TRACES = [
  { key: "variance", label: "variance", color: "#60a5fa", dash: undefined },
  { key: "aligned", label: "aligned", color: "#34d399", dash: undefined },
  { key: "high_entropy", label: "high_entropy", color: "#fbbf24", dash: undefined },
  { key: "candidates", label: "candidates", color: "#f87171", dash: "dot" as const },
] as const;

export type SurvivorTraceKey = (typeof SURVIVOR_TRACES)[number]["key"];
