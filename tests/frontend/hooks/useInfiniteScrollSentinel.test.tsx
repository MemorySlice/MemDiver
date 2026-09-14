/**
 * Tests for `@/hooks/useInfiniteScrollSentinel`.
 *
 * The only `IntersectionObserver` in this tree, shared by the dataset run list
 * and the variance-region browser. The two properties worth pinning are the
 * ones a scroll can break: no observer while a page is already in flight, and
 * no observer once the list is exhausted.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { act, fireEvent, render } from "@testing-library/react";
import { useCallback, useState } from "react";
import "@testing-library/jest-dom/vitest";

import {
  MAX_SENTINEL_AUTOLOADS,
  useInfiniteScrollSentinel,
} from "@/hooks/useInfiniteScrollSentinel";

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

// ---------------------------------------------------------------------------
// THE POST STORM
// ---------------------------------------------------------------------------

/** Whether the fake observer reports the sentinel as on screen. */
let intersecting = true;

/**
 * An observer that delivers the initial callback `observe()` really does.
 *
 * That callback is the engine of the storm, and the reason the plain
 * `FakeObserver` above cannot show it: a rejected page leaves `hasMore` true
 * (`variance-regions-store` never touches `nextAfter` on failure), `loading`
 * flips back to false, the effect builds a NEW observer, and `observe()`
 * reports the still-intersecting sentinel immediately — fetch, fail,
 * re-observe, fetch, with no backoff and no end.
 */
class InitialCallbackObserver {
  private cb: (entries: { isIntersecting: boolean }[]) => void;
  constructor(cb: (entries: { isIntersecting: boolean }[]) => void) {
    this.cb = cb;
    fire = cb;
  }
  observe(node: Element) {
    observed.push(node);
    this.cb([{ isIntersecting: intersecting }]);
  }
  disconnect() {
    disconnects += 1;
  }
  unobserve() {}
  takeRecords() {
    return [];
  }
}

/**
 * A list whose next page always fails, exactly as the two real ones behave:
 * `loading` goes true then false, and `hasMore` never changes.
 *
 * The button is the "Load more" fallback both real lists keep. It runs the same
 * failing page WITHOUT going through the hook, which is what makes it a human
 * gesture rather than a retry.
 */
function FailingListHarness({ onLoad }: { onLoad: () => void }) {
  const [loading, setLoading] = useState(false);
  const runFailingPage = useCallback(() => {
    setLoading(true);
    setTimeout(() => setLoading(false), 0);
  }, []);
  const loadMore = useCallback(() => {
    onLoad();
    runFailingPage();
  }, [onLoad, runFailingPage]);
  const ref = useInfiniteScrollSentinel(true, loading, loadMore);
  return (
    <div>
      <div ref={ref} data-testid="sentinel" />
      <button data-testid="load-more" onClick={runFailingPage} />
    </div>
  );
}

/** Lets each pending 0ms timer and the re-render behind it settle, `rounds` times. */
async function settleRounds(rounds: number): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
  }
}

describe("useInfiniteScrollSentinel: a page that keeps failing", () => {
  beforeEach(() => {
    intersecting = true;
    vi.stubGlobal("IntersectionObserver", InitialCallbackObserver);
  });

  it("issues a BOUNDED number of requests, not an unbounded stream", async () => {
    const onLoad = vi.fn();
    render(<FailingListHarness onLoad={onLoad} />);

    // Far more rounds than the budget: an unlatched hook fetches on every one.
    await settleRounds(12);

    expect(onLoad).toHaveBeenCalledTimes(MAX_SENTINEL_AUTOLOADS);
  });

  it("resumes on a human gesture, the way retryChunkAt does", async () => {
    const onLoad = vi.fn();
    const { getByTestId } = render(<FailingListHarness onLoad={onLoad} />);
    await settleRounds(12);
    expect(onLoad).toHaveBeenCalledTimes(MAX_SENTINEL_AUTOLOADS);

    // A load this hook did not start: a person asked again, so the budget
    // starts over — and is bounded again after it.
    await act(async () => {
      fireEvent.click(getByTestId("load-more"));
    });
    await settleRounds(12);

    expect(onLoad).toHaveBeenCalledTimes(MAX_SENTINEL_AUTOLOADS * 2);
  });

  /**
   * Scrolling away is what a page that actually loaded looks like from here —
   * the list grew and pushed the sentinel off screen — so it refills the
   * budget, and healthy pagination never reaches the latch at all.
   */
  it("refills the budget when the sentinel leaves the viewport", async () => {
    const onLoad = vi.fn();
    render(<FailingListHarness onLoad={onLoad} />);
    await settleRounds(1);
    const spent = onLoad.mock.calls.length;
    expect(spent).toBeGreaterThan(0);
    expect(spent).toBeLessThan(MAX_SENTINEL_AUTOLOADS);

    intersecting = false;
    await settleRounds(4);
    expect(onLoad).toHaveBeenCalledTimes(spent);

    // Back into view against a refilled budget.
    intersecting = true;
    await act(async () => {
      fire([{ isIntersecting: true }]);
    });
    await settleRounds(12);

    expect(onLoad).toHaveBeenCalledTimes(spent + MAX_SENTINEL_AUTOLOADS);
  });
});
