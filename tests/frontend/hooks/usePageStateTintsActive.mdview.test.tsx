import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook } from "@testing-library/react";

import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { useAlignedPageStateTintsActive } = await import("@/hooks/usePageStateTintsActive");
const { useMslPaneCoordinate } = await import("@/hooks/useAlignedPanes");

/** An `.mdview` is `format: "raw"` by extension; only the backend's detection says image view. */
function dump(path: string, format: DumpEntry["format"]): DumpEntry {
  return { id: "d0", path, name: path, size: 4096, format, sameProcess: true };
}

function select(entry: DumpEntry) {
  useDumpStore.setState({
    dumps: [entry],
    selectedDumpIds: [entry.id],
    activeDumpId: entry.id,
    mainView: "sideBySide",
  });
}

const MDVIEW = "/images/sshd.mdview";

beforeEach(() => {
  useHexStore.getState().reset();
  useDumpStore.setState({ dumps: [], selectedDumpIds: [], activeDumpId: null });
});

describe("useAlignedPageStateTintsActive", () => {
  it("is on for an .msl anchor in va", () => {
    select(dump("/d/a.msl", "msl"));
    useHexStore.setState({ viewMode: "va" });
    expect(renderHook(() => useAlignedPageStateTintsActive()).result.current).toBe(true);
  });

  it("is on for an .mdview anchor the backend detected as an image view", () => {
    select(dump(MDVIEW, "raw"));
    useHexStore.setState({ dumpPath: MDVIEW, detectedFormat: "image_view", viewMode: "va" });
    expect(renderHook(() => useAlignedPageStateTintsActive()).result.current).toBe(true);
  });

  it("is off for an .mdview in vas, for a plain raw dump, and for another path's detection", () => {
    select(dump(MDVIEW, "raw"));
    useHexStore.setState({ dumpPath: MDVIEW, detectedFormat: "image_view", viewMode: "vas" });
    expect(renderHook(() => useAlignedPageStateTintsActive()).result.current).toBe(false);

    useHexStore.setState({ detectedFormat: "gcore", viewMode: "va" });
    expect(renderHook(() => useAlignedPageStateTintsActive()).result.current).toBe(false);

    useHexStore.setState({ dumpPath: "/other.bin", detectedFormat: "image_view" });
    expect(renderHook(() => useAlignedPageStateTintsActive()).result.current).toBe(false);
  });
});

describe("useMslPaneCoordinate for an image view", () => {
  it("moves a raw .mdview to vas when the view offers it", () => {
    const entry = dump(MDVIEW, "raw");
    select(entry);
    useHexStore.setState({
      dumpPath: MDVIEW,
      detectedFormat: "image_view",
      availableViews: ["vas", "va", "raw"],
      viewMode: "raw",
    });
    renderHook(() => useMslPaneCoordinate(entry));
    expect(useHexStore.getState().viewMode).toBe("vas");
  });

  it("leaves a raw-only image view and a plain raw dump alone", () => {
    const entry = dump(MDVIEW, "raw");
    select(entry);
    useHexStore.setState({
      dumpPath: MDVIEW,
      detectedFormat: "image_view",
      availableViews: ["raw"],
      viewMode: "raw",
    });
    renderHook(() => useMslPaneCoordinate(entry));
    expect(useHexStore.getState().viewMode).toBe("raw");
  });
});
