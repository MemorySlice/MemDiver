import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render } from "@testing-library/react";

import { useConsensusStore } from "@/stores/consensus-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import {
  liveRequestKey,
  useVarianceRegionsStore,
} from "@/stores/variance-regions-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const { useVarianceRegionsLoader } = await import("@/hooks/useVarianceRegions");

/**
 * The ONE mounted effect that keeps the region list describing the query the
 * app is actually in — and the place the length filter can go wrong SILENTLY.
 *
 * The effect early-returns when `store.requestKey === liveRequestKey(...)`, so
 * the filter has to be spelled out in THREE places that must agree:
 *
 *   (a) `requestKeyFor`, so the key changes at all;
 *   (b) the exported `liveRequestKey` signature this hook compares against;
 *   (c) this hook's subscriptions and dependency array, so the effect re-runs.
 *
 * Miss (c) and the list never reloads under a new filter. Miss (a) or (b) and
 * something worse happens: the guard finds the stale key EQUAL to the live one,
 * early-returns, and leaves the previous filter's rows on screen beneath the
 * new controls — plausible rows at sizes the analyst did not ask for, which no
 * type checker and no screenshot catches. One case below pins each.
 */

const CONSENSUS_ID = "cns-1";
const DUMP_A = "/dumps/a.msl";
const DUMP_B = "/dumps/b.msl";

function Harness() {
  useVarianceRegionsLoader();
  return null;
}

/** A `loadMore` that lands a page, the way a real one eventually does. */
function landingLoadMore() {
  return vi.fn(async () => {
    const { category, minLength, maxLength, sort } = useVarianceRegionsStore.getState();
    if (category === null) return;
    useVarianceRegionsStore.setState({
      requestKey: liveRequestKey(category, minLength, maxLength, sort),
    });
  });
}

beforeEach(() => {
  act(() => {
    useVarianceRegionsStore.getState().reset();
    useMultiHexStore.getState().reset();
    useConsensusStore.setState({ consensusId: CONSENSUS_ID, builtFrom: [DUMP_A, DUMP_B] });
    useHexStore.setState({ dumpPath: DUMP_A, viewMode: "va" });
  });
});

afterEach(() => {
  act(() => {
    useVarianceRegionsStore.getState().reset();
    useHexStore.getState().reset();
  });
});

describe("useVarianceRegionsLoader and the length filter", () => {
  it("reloads when the ceiling changes — the filter is in the dependency array", async () => {
    const loadMore = landingLoadMore();
    act(() => {
      useVarianceRegionsStore.setState({ loadMore });
    });
    render(<Harness />);
    await act(async () => {});
    const afterFirstLoad = loadMore.mock.calls.length;
    expect(afterFirstLoad).toBeGreaterThan(0);

    await act(async () => {
      useVarianceRegionsStore.getState().setMaxLength(32);
    });

    // Without `maxLength` among the subscriptions, nothing the effect watches
    // moved and the list would stay empty under the new filter forever.
    expect(loadMore.mock.calls.length).toBeGreaterThan(afterFirstLoad);
  });

  it("reloads when the sort changes", async () => {
    const loadMore = landingLoadMore();
    act(() => {
      useVarianceRegionsStore.setState({ loadMore });
    });
    render(<Harness />);
    await act(async () => {});
    const afterFirstLoad = loadMore.mock.calls.length;

    await act(async () => {
      useVarianceRegionsStore.getState().setSort("length_desc");
    });

    expect(loadMore.mock.calls.length).toBeGreaterThan(afterFirstLoad);
  });

  it("REFUSES a page loaded under a different ceiling, key for key", async () => {
    const loadMore = landingLoadMore();
    act(() => {
      useVarianceRegionsStore.setState({ loadMore });
    });
    render(<Harness />);
    await act(async () => {});
    loadMore.mockClear();

    // The filter moves WITHOUT the action that drops the page — exactly the
    // state the store would be left in if `clearedPage` ever stopped clearing
    // `requestKey`. The key comparison is then the only thing standing between
    // the analyst and the previous filter's rows.
    await act(async () => {
      useVarianceRegionsStore.setState({ maxLength: 32 });
    });

    expect(loadMore).toHaveBeenCalled();
  });

  it("REFUSES a page loaded under a different sort, key for key", async () => {
    const loadMore = landingLoadMore();
    act(() => {
      useVarianceRegionsStore.setState({ loadMore });
    });
    render(<Harness />);
    await act(async () => {});
    loadMore.mockClear();

    await act(async () => {
      useVarianceRegionsStore.setState({ sort: "length_asc" });
    });

    expect(loadMore).toHaveBeenCalled();
  });

  it("still early-returns when nothing about the query moved", async () => {
    const loadMore = landingLoadMore();
    act(() => {
      useVarianceRegionsStore.setState({ loadMore });
    });
    render(<Harness />);
    await act(async () => {});
    loadMore.mockClear();

    // Re-applying the filter it already has is not a new query, and a loader
    // that re-fetched on every unrelated `set()` would page-two a list nobody
    // scrolled.
    await act(async () => {
      useVarianceRegionsStore.getState().setMaxLength(0);
      useVarianceRegionsStore.getState().setSort("offset");
    });

    expect(loadMore).not.toHaveBeenCalled();
  });
});
