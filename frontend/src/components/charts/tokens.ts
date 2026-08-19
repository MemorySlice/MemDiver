/**
 * Runtime resolver for CSS-variable design tokens.
 *
 * Plotly and other JS-driven chart libraries accept colour strings but do not
 * resolve `var(--md-accent-green)` themselves. Call `getToken("--md-accent-green")`
 * at render time to get the computed value (e.g. `"#3d7a28"` in light mode,
 * `"#6a9955"` in dark mode).
 *
 * Values are cached per invocation but invalidated on theme changes via the
 * `dark` / `high-contrast` class mutation on `<html>`. Call `tokens()` on each
 * render to stay theme-reactive — memoisation happens at the MutationObserver
 * level inside `watchTokens()` if you want it.
 */

export function getToken(name: string, fallback = ""): string {
  if (typeof window === "undefined") return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

// Canonical light-theme hex fallbacks, so a pre-paint / non-DOM (jsdom) render
// never yields an empty colour string. Single source of truth: both
// getChartColor() and chartTokens() resolve through this table.
const TOKEN_FALLBACKS: Record<string, string> = {
  "--md-accent-blue": "#2a6db5",
  "--md-accent-green": "#3d7a28",
  "--md-accent-orange": "#b05a2e",
  "--md-accent-red": "#cc3333",
  "--md-accent-purple": "#8b3d85",
  "--md-accent-cyan": "#1a8a70",
  "--md-accent-yellow": "#a68a00",
  "--md-chart-paper": "#f7f7f7",
  "--md-chart-plot": "#ffffff",
  "--md-chart-grid": "#e0e0e0",
  "--md-chart-text": "#333333",
  "--md-text-primary": "#212121",
  "--md-text-secondary": "#666666",
  "--md-text-muted": "#888888",
  "--md-border": "#d4d4d8",
  "--md-variance-invariant": "#cccccc",
  "--md-variance-structural": "#3d7a28",
  "--md-variance-pointer": "#2a6db5",
  "--md-variance-key-candidate": "#cc2222",
};

/** Resolve a design-token colour with its canonical fallback baked in. */
export function getChartColor(name: string): string {
  return getToken(name, TOKEN_FALLBACKS[name] ?? "");
}

/**
 * Ordinal single-hue ramp — 6 steps, light→dark, one hue — for ordered/ranked
 * marks (e.g. funnel stages) as opposed to the unordered categorical accents
 * above. A funnel stage is a *position in a sequence*, not an independent
 * identity, so it takes a monotone-lightness ramp rather than a rotating hue.
 *
 * Exposed as ready-to-use `var(--md-seq-N)` references rather than resolved
 * hex: a plain CSS/JSX `style` prop can consume a CSS custom property
 * directly and stays theme-reactive for free (the browser recomputes it the
 * moment the `.dark` class toggles), so no `getComputedStyle()` call or
 * re-render wiring is needed here the way it is for Plotly (see
 * `chartTokens()` below for that case).
 */
export const SEQUENTIAL_RAMP: readonly string[] = [
  "var(--md-seq-1)",
  "var(--md-seq-2)",
  "var(--md-seq-3)",
  "var(--md-seq-4)",
  "var(--md-seq-5)",
  "var(--md-seq-6)",
];

/** Token set commonly used by charts. Call at render time; do not cache across renders. */
export function chartTokens() {
  return {
    accentBlue: getChartColor("--md-accent-blue"),
    accentGreen: getChartColor("--md-accent-green"),
    accentOrange: getChartColor("--md-accent-orange"),
    accentRed: getChartColor("--md-accent-red"),
    accentPurple: getChartColor("--md-accent-purple"),
    accentCyan: getChartColor("--md-accent-cyan"),
    accentYellow: getChartColor("--md-accent-yellow"),
    chartPaper: getChartColor("--md-chart-paper"),
    chartPlot: getChartColor("--md-chart-plot"),
    chartGrid: getChartColor("--md-chart-grid"),
    chartText: getChartColor("--md-chart-text"),
    textPrimary: getChartColor("--md-text-primary"),
    textSecondary: getChartColor("--md-text-secondary"),
    textMuted: getChartColor("--md-text-muted"),
    border: getChartColor("--md-border"),
    varianceInvariant: getChartColor("--md-variance-invariant"),
    varianceStructural: getChartColor("--md-variance-structural"),
    variancePointer: getChartColor("--md-variance-pointer"),
    varianceKeyCandidate: getChartColor("--md-variance-key-candidate"),
  };
}
