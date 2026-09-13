/**
 * Tests for `@/hooks/useInfiniteScrollSentinel`.
 *
 * The only `IntersectionObserver` in this tree, shared by the dataset run list
 * and the variance-region browser. The two properties worth pinning are the
 * ones a scroll can break: no observer while a page is already in flight, and
 * no observer once the list is exhausted.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";

import { useInfiniteScrollSentinel } from "@/hooks/useInfiniteScrollSentinel";

let observed: Element[] = [];
let disconnects = 0;
let fire: (entries: { isIntersecting: boolean }[]) => void = () => {};

class FakeObserver {
  constructor(cb: (entries: { isIntersecting: boolean }[]) => void) {
    fire = cb;
  }
  observe(node: Element) {
    observed.push(node);
  }
  disconnect() {
    disconnects += 1;
  }
  unobserve() {}
  takeRecords() {
    return [];
  }
}

function Harness({
  hasMore,
  loading,
  loadMore,
}: {
  hasMore: boolean;
  loading: boolean;
  loadMore: () => void;
}) {
  const ref = useInfiniteScrollSentinel(hasMore, loading, loadMore);
  return <div ref={ref} data-testid="sentinel" />;
}

beforeEach(() => {
  observed = [];
  disconnects = 0;
  vi.stubGlobal("IntersectionObserver", FakeObserver);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("useInfiniteScrollSentinel", () => {
  it("observes the sentinel while there is more to load", () => {
    render(<Harness hasMore loading={false} loadMore={() => {}} />);

    expect(observed).toHaveLength(1);
  });

  it("loads the next page when the sentinel comes into view", () => {
    const loadMore = vi.fn();
    render(<Harness hasMore loading={false} loadMore={loadMore} />);

    fire([{ isIntersecting: true }]);

    expect(loadMore).toHaveBeenCalledTimes(1);
  });

  it("ignores an entry that is not intersecting", () => {
    const loadMore = vi.fn();
    render(<Harness hasMore loading={false} loadMore={loadMore} />);

    fire([{ isIntersecting: false }]);

    expect(loadMore).not.toHaveBeenCalled();
  });

  /** A page already in flight must not be requested a second time by a tick. */
  it("does not observe while a page is loading", () => {
    render(<Harness hasMore loading loadMore={() => {}} />);

    expect(observed).toHaveLength(0);
  });

  it("stops observing once the list is exhausted", () => {
    render(<Harness hasMore={false} loading={false} loadMore={() => {}} />);

    expect(observed).toHaveLength(0);
  });

  it("disconnects on unmount", () => {
    const { unmount } = render(<Harness hasMore loading={false} loadMore={() => {}} />);

    unmount();

    expect(disconnects).toBe(1);
  });
});
