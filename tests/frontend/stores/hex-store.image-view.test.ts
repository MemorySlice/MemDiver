import { describe, it, expect, beforeEach, vi } from "vitest";

import { servesPageStates, useHexStore } from "@/stores/hex-store";

/**
 * An `.mdview` image view is "raw" by extension, so the workspace knows it only
 * from the backend's `format_name` (`detectedFormat`). That is what must move it
 * off its multi-GB raw file, and what must let it ask for page states.
 */

const getPageStates = vi.fn();
vi.mock("@/api/client", () => ({
  getPageStates: (...args: unknown[]) => getPageStates(...args),
}));

const VIEW_MODE_KEY = "memdiver:hex:viewMode";
const IMAGE_VIEWS = ["vas", "va", "raw"] as const;
const BASE = 0x56056590c000;

beforeEach(() => {
  localStorage.clear();
  getPageStates.mockReset();
  getPageStates.mockReturnValue(new Promise(() => {}));
  useHexStore.getState().reset();
  useHexStore.setState({ viewMode: "raw" });
  useHexStore.getState().setDumpPath("/images/sshd.mdview", 4096, "raw");
});

describe("servesPageStates", () => {
  it("is true for an .msl and for a detected image view only", () => {
    expect(servesPageStates("msl", "")).toBe(true);
    expect(servesPageStates("raw", "image_view")).toBe(true);
    expect(servesPageStates("raw", "gcore")).toBe(false);
    expect(servesPageStates("raw", "")).toBe(false);
  });
});

describe("image view default view", () => {
  it("opens on vas instead of raw, without persisting", () => {
    useHexStore.getState().setAvailableViews([...IMAGE_VIEWS], "image_view");
    expect(useHexStore.getState().viewMode).toBe("vas");
    expect(localStorage.getItem(VIEW_MODE_KEY)).toBeNull();
  });

  it("keeps the view an earlier session left on va", () => {
    useHexStore.setState({ viewMode: "va" });
    useHexStore.getState().setAvailableViews([...IMAGE_VIEWS], "image_view");
    expect(useHexStore.getState().viewMode).toBe("va");
  });

  it("leaves every other multi-view format on raw", () => {
    useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    expect(useHexStore.getState().viewMode).toBe("raw");
  });

  it("lets a view the analysis asked for win over the default", () => {
    useHexStore.getState().showView("va");
    useHexStore.getState().setAvailableViews([...IMAGE_VIEWS], "image_view");
    expect(useHexStore.getState().viewMode).toBe("va");
  });

  it("falls back to the first offered view when va was dropped for a kernel view", () => {
    useHexStore.setState({ viewMode: "va" });
    useHexStore.getState().setAvailableViews(["vas", "raw"], "image_view");
    expect(useHexStore.getState().viewMode).toBe("vas");
  });
});

describe("image view page states", () => {
  const response = {
    regions: [
      { base_addr: BASE, region_size: 8192, page_size: 4096, intervals: [
        { va: BASE, length: 8192, state: "CAPTURED", page_count: 2 }] },
      { base_addr: BASE + 3 * 4096, region_size: 4096, page_size: 4096, intervals: [
        { va: BASE + 3 * 4096, length: 4096, state: "NOT_RESIDENT", page_count: 1 }] },
    ],
  };

  it("fetches for a detected image view and exposes the absolute VA span start", async () => {
    getPageStates.mockResolvedValue(response);
    useHexStore.getState().setAvailableViews([...IMAGE_VIEWS], "image_view");
    useHexStore.getState().fetchPageStates();
    await vi.waitFor(() => expect(useHexStore.getState().pageStatesLoaded).toBe(true));
    const s = useHexStore.getState();
    expect(s.vaSpanStart).toBe(BASE);
    expect(s.getPageStateAt(0)).toBe("CAPTURED");
    expect(s.getPageStateAt(2 * 4096)).toBe("UNMAPPED"); // the gap between runs
    expect(s.getPageStateAt(3 * 4096)).toBe("NOT_RESIDENT");
  });

  it("does not fetch for a dump that is neither an .msl nor an image view", () => {
    useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    useHexStore.getState().fetchPageStates();
    expect(getPageStates).not.toHaveBeenCalled();
  });

  it("entering va on an image view fetches the page states", () => {
    useHexStore.getState().setAvailableViews([...IMAGE_VIEWS], "image_view");
    useHexStore.getState().setViewMode("va");
    expect(getPageStates).toHaveBeenCalledWith("/images/sshd.mdview", undefined);
  });
});
