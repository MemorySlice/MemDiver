/**
 * Unmount teardown for the multi-dump byte cache (`@/hooks/useAlignedPanes`).
 *
 * `multi-hex-store` is module-global and outlives every viewer, and its
 * `reset()` had NO production caller. Two things leaked as a result:
 *
 *  1. A retry scheduled up to 4 s earlier still fired after the viewer was
 *     gone, still passed every one of `scheduleRetry`'s guards — nothing had
 *     been reset, so the identity, the request and the failure all still
 *     matched — and issued a real POST for a viewer that no longer exists,
 *     repopulating `byPath` and all three side maps behind it.
 *  2. The cache itself was never released for the rest of the tab's life.
 *
 * Both are pinned here. The counted-mount half matters too: the three viewers
 * are mutually exclusive branches of one `if` ladder in `Workspace`, and the
 * teardown must not start depending on that — the LAST loader out resets, not
 * the first.
 */

import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { act, render } from "@testing-library/react";

import { useMultiHexStore } from "@/stores/multi-hex-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

// Partial: `fetchAlignedWindow` must still go through the REAL `request`, so
// the failure this test schedules a retry from is a real rejected fetch.
vi.mock("@/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/client")>()),
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { useAlignedWindowLoader } = await import("@/hooks/useAlignedPanes");

const A = "/dumps/a.raw";
const B = "/dumps/b.raw";

/** A `raw` anchor, so `useMslViewSizes` resolves without a probe round trip. */
const ANCHOR: DumpEntry = {
  id: "a",
  path: A,
  name: "a.raw",
  size: 1 << 20,
  format: "raw",
  sameProcess: true,
};

const fetchMock = vi.fn();

/** Only the aligned-window POST is of interest; everything else is noise. */
function windowCalls(): number {
  return fetchMock.mock.calls.filter((call) =>
    String(call[0]).includes("aligned-window"),
  ).length;
}

function Loader() {
  useAlignedWindowLoader({ anchor: ANCHOR, paths: [A, B], firstRow: 0, lastRow: 0 });
  return null;
}

/** Advance fake time, then let the promise chain behind `fetch` settle. */
async function settle(ms = 0): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
    await vi.advanceTimersByTimeAsync(0);
  });
}

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockRejectedValue(new Error("boom"));
  vi.stubGlobal("fetch", fetchMock);
  vi.useFakeTimers();
  useMultiHexStore.getState().reset();
  useDumpStore.getState().clearAll();
  useHexStore.setState({ viewMode: "raw", dumpPath: A, fileSize: ANCHOR.size });
  // The loader fetches nothing without a consensus that covers this selection.
  useConsensusStore.setState({ consensusId: "c1", builtFrom: [A, B] });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  useMultiHexStore.getState().reset();
  useConsensusStore.getState().reset();
});

describe("useAlignedWindowLoader unmount teardown", () => {
  it("cancels a pending retry so no request outlives the viewer", async () => {
    const { unmount } = render(<Loader />);
    await settle();
    // The visible row plus its prefetch margin: several chunks, each of which
    // failed and each of which now has a nudge scheduled 1s out.
    const beforeUnmount = windowCalls();
    expect(beforeUnmount).toBeGreaterThan(0);
    expect(useMultiHexStore.getState().getChunkFailure(0)?.message).toBe("boom");

    act(() => unmount());

    // Well past both backoff steps (1s, then 4s). Nothing may wake up.
    await settle(10_000);
    expect(windowCalls()).toBe(beforeUnmount);
  });

  it("releases the cache rather than holding it for the tab's lifetime", async () => {
    fetchMock.mockReset();
    fetchMock.mockRejectedValue(new Error("boom"));
    const { unmount } = render(<Loader />);
    await settle();
    expect(useMultiHexStore.getState().chunkErrors.size).toBeGreaterThan(0);

    act(() => unmount());

    const state = useMultiHexStore.getState();
    expect(state.byPath.size).toBe(0);
    expect(state.chunkErrors.size).toBe(0);
    expect(state.identity).toBeNull();
    expect(state.lastRequest).toBeNull();
  });

  /**
   * The three viewers are mutually exclusive branches of one `return` today,
   * but that is a property of an `if` ladder, not of the store. Counting the
   * mounts means a future split layout cannot wipe a live viewer's bytes.
   */
  it("does not tear down while another loader is still mounted", async () => {
    const first = render(<Loader />);
    const second = render(<Loader />);
    await settle();

    act(() => first.unmount());

    expect(useMultiHexStore.getState().lastRequest).not.toBeNull();

    act(() => second.unmount());

    expect(useMultiHexStore.getState().lastRequest).toBeNull();
  });
});
