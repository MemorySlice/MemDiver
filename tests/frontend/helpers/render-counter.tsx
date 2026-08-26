/**
 * Render-count harness for the `useShallow` selector sweep (B3).
 *
 * A component that destructures a whole Zustand store re-renders on every
 * `set()` of that store, however unrelated the mutated field is. These helpers
 * make that observable in a test: mount a component, drive N store mutations
 * that touch fields the component does NOT read, then assert the render count
 * did not move.
 */
import { render, type RenderResult } from "@testing-library/react";
import { Profiler, useState, type ReactElement, type ReactNode } from "react";

/**
 * Counts how many times the calling component has rendered.
 *
 * Bumping the tally must not itself schedule a render, which rules out
 * `useState`'s setter; and a `useRef` bumped during render trips
 * react-hooks' no-ref-access-during-render rule (right for product code, in
 * the way for a render-counting probe). So the count lives in a module-level
 * WeakMap keyed by a stable per-instance identity object.
 *
 * The first render returns 1.
 */
const renderTallies = new WeakMap<object, number>();

export function useRenderCount(): number {
  // `identity` is a stable per-instance key that is never itself mutated; the
  // tally lives beside it in a module-level WeakMap. Keeping the count out of
  // React's own storage is what lets a probe read it during render without
  // scheduling one.
  const [identity] = useState(() => ({}));
  const next = (renderTallies.get(identity) ?? 0) + 1;
  renderTallies.set(identity, next);
  return next;
}

/** Live view of how many times the subtree under test has rendered. */
export interface RenderCounter {
  readonly count: number;
}

export interface RenderWithCountResult extends RenderResult {
  counter: RenderCounter;
}

/**
 * Renders `element` under a React `Profiler` and tallies its commits.
 *
 * A plain wrapper component cannot do this job: when the child re-renders from
 * its own store subscription, the wrapper does not re-render, so a counter in
 * the wrapper would always read 0. `Profiler.onRender` fires for every commit
 * in which the subtree actually rendered, which is precisely the signal a
 * selector sweep is meant to reduce.
 */
export function renderWithCount(element: ReactElement): RenderWithCountResult {
  const box = { count: 0 };
  const result = render(
    <Profiler id="render-counter" onRender={() => { box.count += 1; }}>
      {element}
    </Profiler>,
  );
  return Object.assign(result, {
    counter: {
      get count() {
        return box.count;
      },
    },
  });
}

/**
 * Builds a probe component that renders `children` and reports each of its own
 * renders to `onRender`. Use it when you want the render count of a specific
 * inner component rather than of a whole subtree.
 */
export function createRenderProbe(onRender: (count: number) => void) {
  return function RenderProbe({ children }: { children: ReactNode }) {
    const count = useRenderCount();
    onRender(count);
    return <>{children}</>;
  };
}
