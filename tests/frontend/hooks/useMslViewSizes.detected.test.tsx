import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

import { parseDistinctViews, useMslViewSizes } from "@/hooks/useMslViewSizes";
import { useHexStore } from "@/stores/hex-store";

vi.mock("@/api/client", () => ({
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

/**
 * A non-`.msl` dump is probed once for what the backend detected; a gcore
 * core answers `distinct_views: ["raw", "vas"]`, so the store learns both
 * views and both sizes. A flat dump answers `["raw"]` and nothing else is
 * fetched.
 */

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200 });
}

function viewOf(url: string): string | null {
  return new URL(url, "http://x").searchParams.get("view");
}

beforeEach(() => {
  useHexStore.getState().reset();
  useHexStore.setState({ viewMode: "raw" });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("parseDistinctViews", () => {
  it("keeps known views and falls back otherwise", () => {
    expect(parseDistinctViews(["raw", "vas"], ["raw"])).toEqual(["raw", "vas"]);
    expect(parseDistinctViews(["raw", "bogus"], ["raw"])).toEqual(["raw"]);
    expect(parseDistinctViews(undefined, ["raw"])).toEqual(["raw"]);
    expect(parseDistinctViews([], ["raw", "vas"])).toEqual(["raw", "vas"]);
  });
});

describe("useMslViewSizes on a non-.msl dump", () => {
  it("learns a gcore core's views and sizes from the backend", async () => {
    const fetchMock = vi.fn((url: string) => {
      const view = viewOf(url);
      return Promise.resolve(json({
        format: "gcore",
        file_size: view === "vas" ? 8192 : 8320,
        distinct_views: ["raw", "vas"],
      }));
    });
    vi.stubGlobal("fetch", fetchMock);
    useHexStore.getState().setDumpPath("/dumps/planted.core", 8320, "raw");

    renderHook(() => useMslViewSizes("/dumps/planted.core", "raw"));

    await waitFor(() => expect(useHexStore.getState().availableViews).toEqual(["raw", "vas"]));
    const s = useHexStore.getState();
    expect(s.detectedFormat).toBe("gcore");
    expect(s.rawSize).toBe(8320);
    expect(s.vasSize).toBe(8192);
    expect(fetchMock.mock.calls.map(([u]) => viewOf(u as string)).sort()).toEqual(["raw", "vas"]);
  });

  it("asks once and changes nothing for a flat dump", async () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve(json({ format: "raw", file_size: 64, distinct_views: ["raw"] })));
    vi.stubGlobal("fetch", fetchMock);
    useHexStore.getState().setDumpPath("/dumps/flat.dump", 64, "raw");

    renderHook(() => useMslViewSizes("/dumps/flat.dump", "raw"));

    await waitFor(() => expect(useHexStore.getState().availableViews).toEqual(["raw"]));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(useHexStore.getState().fileSize).toBe(64);
  });
});
