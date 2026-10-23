import { describe, it, expect, beforeEach, vi } from "vitest";
import { renderHook } from "@testing-library/react";

import { useHeapModeLayer } from "@/hooks/useHeapModeLayer";
import { useAppStore } from "@/stores/app-store";
import { useHeapStore, selectHeapLayerEnabled } from "@/stores/heap-store";
import { useHexStore } from "@/stores/hex-store";

/**
 * Entering heap mode enables the heap layer on the active dump and, on an
 * .msl shown in its container ("raw") view, moves the hex viewer to the flat
 * memory ("vas") view: the backend maps no heap chunk into an .msl's raw view.
 */

vi.mock("@/api/client", () => ({
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const MSL = "/dumps/heap.msl";
const CORE = "/dumps/heap.core";

function openDump(path: string, format: string, detected: string): void {
  useHexStore.getState().reset();
  useHexStore.setState({ viewMode: "raw" });
  useHexStore.getState().setDumpPath(path, 8192, format);
  useHexStore.getState().setAvailableViews(["raw", "vas"], detected);
}

beforeEach(() => {
  localStorage.clear();
  useAppStore.setState({ mode: "exploration" });
});

describe("useHeapModeLayer", () => {
  it("switches an .msl from raw to vas on entering heap mode, without persisting it", () => {
    openDump(MSL, "msl", "msl");
    useAppStore.setState({ mode: "heap" });
    renderHook(() => useHeapModeLayer(MSL));
    expect(useHexStore.getState().viewMode).toBe("vas");
    expect(localStorage.getItem("memdiver:hex:viewMode")).not.toBe("vas");
    expect(selectHeapLayerEnabled(MSL)(useHeapStore.getState())).toBe(true);
  });

  it("leaves a non-.msl raw view alone (its raw view carries the heap)", () => {
    openDump(CORE, "raw", "gcore");
    useAppStore.setState({ mode: "heap" });
    renderHook(() => useHeapModeLayer(CORE));
    expect(useHexStore.getState().viewMode).toBe("raw");
  });

  it("does nothing outside heap mode", () => {
    openDump(MSL, "msl", "msl");
    renderHook(() => useHeapModeLayer(MSL));
    expect(useHexStore.getState().viewMode).toBe("raw");
    expect(selectHeapLayerEnabled(MSL)(useHeapStore.getState())).toBe(false);
  });

  it("turns the layer off again when heap mode is left", () => {
    openDump(MSL, "msl", "msl");
    useAppStore.setState({ mode: "heap" });
    const { unmount } = renderHook(() => useHeapModeLayer(MSL));
    unmount();
    expect(selectHeapLayerEnabled(MSL)(useHeapStore.getState())).toBe(false);
  });
});
