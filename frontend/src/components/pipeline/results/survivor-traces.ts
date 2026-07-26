/**
 * Shared trace palette for the SurvivorCurve Plotly + SVG renderers.
 * Keeping one definition means both backends stay visually coherent.
 */
export const SURVIVOR_TRACES = [
  { key: "variance", label: "variance", token: "--md-accent-blue", dash: undefined },
  { key: "aligned", label: "aligned", token: "--md-accent-cyan", dash: undefined },
  { key: "high_entropy", label: "high_entropy", token: "--md-accent-yellow", dash: undefined },
  { key: "candidates", label: "candidates", token: "--md-accent-red", dash: "dot" as const },
] as const;

export type SurvivorTraceKey = (typeof SURVIVOR_TRACES)[number]["key"];
