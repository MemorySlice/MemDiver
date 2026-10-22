import { describe, it, expect, beforeEach, vi } from "vitest";

import { useHexStore } from "@/stores/hex-store";

/**
 * Backend-detected views: a gcore core / gdb_raw .bin is "raw" by extension
 * but has distinct raw and vas views. The store learns them from the
 * `/hex-raw` probe (`setAvailableViews`), clamps a view the dump lacks, and
 * switches to the view analysis hits were computed in (`showView`) WITHOUT
 * overwriting the user's persisted preference.
 */

vi.mock("@/api/client", () => ({
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const VIEW_MODE_KEY = "memdiver:hex:viewMode";

beforeEach(() => {
  localStorage.clear();
  useHexStore.getState().reset();
  useHexStore.setState({ viewMode: "raw" });
  useHexStore.getState().setDumpPath("/dumps/planted.core", 8320, "raw");
});

describe("hex-store available views", () => {
  it("starts unknown and resets on a dump change", () => {
    const s = useHexStore.getState();
    expect(s.availableViews).toEqual([]);
    s.setAvailableViews(["raw", "vas"], "gcore");
    expect(useHexStore.getState().detectedFormat).toBe("gcore");
    useHexStore.getState().setDumpPath("/dumps/other.dump", 10, "raw");
    expect(useHexStore.getState().availableViews).toEqual([]);
    expect(useHexStore.getState().detectedFormat).toBe("");
  });

  it("clamps a persisted view the dump cannot serve, without persisting", () => {
    localStorage.setItem(VIEW_MODE_KEY, "va");
    useHexStore.setState({ viewMode: "va" });
    useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    expect(useHexStore.getState().viewMode).toBe("raw");
    expect(localStorage.getItem(VIEW_MODE_KEY)).toBe("va");
  });

  it("leaves a single-view (flat) dump's view alone", () => {
    useHexStore.setState({ viewMode: "vas" });
    useHexStore.getState().setAvailableViews(["raw"], "raw");
    expect(useHexStore.getState().viewMode).toBe("vas");
  });

  it("showView switches a multi-view dump without persisting the choice", () => {
    useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    useHexStore.getState().showView("vas");
    expect(useHexStore.getState().viewMode).toBe("vas");
    expect(localStorage.getItem(VIEW_MODE_KEY)).toBeNull();
  });

  it("showView is a no-op on a single-view dump", () => {
    useHexStore.getState().setAvailableViews(["raw"], "raw");
    useHexStore.getState().showView("vas");
    expect(useHexStore.getState().viewMode).toBe("raw");
  });

  it("showView before the probe is applied once the views are known", () => {
    useHexStore.getState().showView("vas");
    expect(useHexStore.getState().viewMode).toBe("raw");
    useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    expect(useHexStore.getState().viewMode).toBe("vas");
    expect(useHexStore.getState().requestedView).toBeNull();
  });

  it("setViewMode still persists the user's choice", () => {
    useHexStore.getState().setViewMode("vas");
    expect(localStorage.getItem(VIEW_MODE_KEY)).toBe("vas");
  });
});
