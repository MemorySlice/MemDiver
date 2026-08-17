/**
 * Shared chart-backend dispatcher.
 *
 * Every backend-switchable chart (EntropyChart, VarianceMap, VasChart,
 * SurvivorCurve) reads `settings.display.chartBackend` and renders the
 * matching implementation. Both implementations are lazy-loaded so the
 * Plotly chunk is code-split away from the main bundle — users who never
 * switch to Plotly (or who stay on SVG) don't pay the ~2.3 MB download.
 *
 * Wrapped in a `ChartErrorBoundary` with a `ChartSkeleton` Suspense
 * fallback so a failed or in-flight dynamic import degrades gracefully
 * instead of rendering nothing. Retrying recreates the lazy components
 * (see the `attempt` state below) so a previously-rejected import()
 * promise doesn't keep re-throwing its cached error forever.
 *
 * Each chart's own file stays a thin wrapper that supplies its two
 * `loadPlotly`/`loadSvg` thunks and its own prop type, e.g.:
 *
 *   export function EntropyChart(props: EntropyChartProps) {
 *     return (
 *       <ChartDispatcher<EntropyChartProps>
 *         loadPlotly={() => import("./plotly/EntropyChart")}
 *         loadSvg={() => import("./svg/EntropyChart")}
 *         {...props}
 *       />
 *     );
 *   }
 */
import { lazy, Suspense, useCallback, useMemo, useState } from "react";
import type { ComponentType } from "react";
import { useSettingsStore } from "@/stores/settings-store";
import { ChartErrorBoundary } from "@/components/charts/ChartErrorBoundary";
import { ChartSkeleton } from "@/components/charts/ChartSkeleton";

interface ChartModule<P extends object> {
  default: ComponentType<P>;
}

export type ChartDispatcherProps<P extends object> = P & {
  /** Dynamically imports the Plotly-backed implementation. */
  loadPlotly: () => Promise<ChartModule<P>>;
  /** Dynamically imports the SVG-backed implementation. */
  loadSvg: () => Promise<ChartModule<P>>;
};

/**
 * Renders whichever of `loadPlotly`/`loadSvg` matches the user's selected
 * `chartBackend`, spreading the remaining (chart-specific) props through
 * to the resolved implementation.
 */
export function ChartDispatcher<P extends object = Record<string, never>>({
  loadPlotly,
  loadSvg,
  ...chartProps
}: ChartDispatcherProps<P>) {
  const backend = useSettingsStore((s) => s.display.chartBackend);
  // Bumping `attempt` forces useMemo to call `lazy()` again, which creates
  // a brand-new import() promise — required because a `lazy()` component
  // whose dynamic import already rejected once will keep re-throwing that
  // same cached error forever on every subsequent render, even after the
  // surrounding ErrorBoundary clears its own state. Recreating the lazy
  // component is what makes "Retry" a genuine second attempt rather than
  // an immediate repeat of the same failure.
  const [attempt, setAttempt] = useState(0);
  // `attempt` is an intentional cache-buster: it isn't read inside the
  // callback, but bumping it is what forces useMemo to call `lazy()` again
  // on retry.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const PlotlyImpl = useMemo(() => lazy(loadPlotly), [attempt]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const SvgImpl = useMemo(() => lazy(loadSvg), [attempt]);
  const Impl = backend === "svg" ? SvgImpl : PlotlyImpl;
  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  return (
    <ChartErrorBoundary onRetry={retry}>
      <Suspense fallback={<ChartSkeleton />}>
        {/* Impl is memoized above and only gets a new identity when the
            user clicks Retry (bumping `attempt`); this is the escape hatch
            for retrying a lazy() import whose promise already rejected
            once. */}
        {/* The rest-destructured `chartProps` is exactly `P` by construction
            of `ChartDispatcherProps<P>` above (P & { loadPlotly, loadSvg }
            minus those two named keys); TS's generic object-rest inference
            can't prove that structurally, hence the cast. */}
        <Impl {...(chartProps as P)} />
      </Suspense>
    </ChartErrorBoundary>
  );
}
