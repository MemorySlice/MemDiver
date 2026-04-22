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

/** Token set commonly used by charts. Call at render time; do not cache across renders. */
export function chartTokens() {
  return {
    accentBlue: getToken("--md-accent-blue", "#2a6db5"),
    accentGreen: getToken("--md-accent-green", "#3d7a28"),
    accentOrange: getToken("--md-accent-orange", "#b05a2e"),
    accentRed: getToken("--md-accent-red", "#cc3333"),
    accentPurple: getToken("--md-accent-purple", "#8b3d85"),
    accentCyan: getToken("--md-accent-cyan", "#1a8a70"),
    accentYellow: getToken("--md-accent-yellow", "#a68a00"),
    chartPaper: getToken("--md-chart-paper", "#f7f7f7"),
    chartPlot: getToken("--md-chart-plot", "#ffffff"),
    chartGrid: getToken("--md-chart-grid", "#e0e0e0"),
    chartText: getToken("--md-chart-text", "#333333"),
    textPrimary: getToken("--md-text-primary", "#212121"),
    textSecondary: getToken("--md-text-secondary", "#666666"),
    textMuted: getToken("--md-text-muted", "#888888"),
    border: getToken("--md-border", "#d4d4d8"),
    varianceInvariant: getToken("--md-variance-invariant", "#cccccc"),
    varianceStructural: getToken("--md-variance-structural", "#3d7a28"),
    variancePointer: getToken("--md-variance-pointer", "#2a6db5"),
    varianceKeyCandidate: getToken("--md-variance-key-candidate", "#cc2222"),
  };
}
