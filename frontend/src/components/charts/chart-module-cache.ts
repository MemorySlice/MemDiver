/**
 * Remembers chart implementations whose dynamic import has already resolved,
 * keyed by the (module-level, stable) loader function that imported them.
 *
 * Why: `React.lazy` always suspends on its first render, even when the
 * import promise it is handed has long resolved, and React 19 throttles the
 * reveal of a suspended boundary (~300 ms). For a chart whose code was
 * preloaded (see `entropy-chart-loaders.ts`), that throttle was the single
 * largest cost between "data arrived" and "chart visible". With a cache hit
 * the dispatcher renders the component directly and never suspends.
 *
 * Loaders passed as inline arrows simply never hit (a new function per
 * render), which keeps their behaviour exactly as before.
 */
import type { ComponentType } from "react";

export interface ChartModule<P extends object> {
  default: ComponentType<P>;
}

export type ChartLoader<P extends object> = () => Promise<ChartModule<P>>;

const resolvedModules = new WeakMap<ChartLoader<object>, ComponentType<object>>();

/** Run *load* and remember its component once it resolves. */
export function loadChartModule<P extends object>(
  load: ChartLoader<P>,
): Promise<ChartModule<P>> {
  return load().then((module) => {
    resolvedModules.set(
      load as unknown as ChartLoader<object>,
      module.default as unknown as ComponentType<object>,
    );
    return module;
  });
}

/** The component *load* resolved to, if it already has. */
export function resolvedChartModule<P extends object>(
  load: ChartLoader<P>,
): ComponentType<P> | undefined {
  return resolvedModules.get(load as unknown as ChartLoader<object>) as
    | ComponentType<P>
    | undefined;
}
