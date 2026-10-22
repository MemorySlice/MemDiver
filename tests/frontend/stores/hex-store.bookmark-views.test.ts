import { describe, it, expect, beforeEach, vi } from "vitest";

import { useHexStore } from "@/stores/hex-store";

/**
 * Bookmarks record the view their offset addresses, so jumping back on a
 * multi-view dump (gcore raw/vas, .msl raw/vas/va) lands on the same byte.
 * Bookmarks saved before the view was recorded keep the historical
 * "whatever view is on screen" behaviour.
 */

vi.mock("@/api/client", () => ({
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const DUMP = "/dumps/planted.core";
const BOOKMARKS_KEY = `memdiver:hex:bookmarks:${DUMP}`;

/** Re-open DUMP so its bookmarks reload from localStorage. */
function rehydrate(): void {
  useHexStore.getState().setDumpPath("/dumps/other.core", 10, "raw");
  useHexStore.getState().setDumpPath(DUMP, 8320, "raw");
}

beforeEach(() => {
  localStorage.clear();
  useHexStore.getState().reset();
  useHexStore.setState({ viewMode: "raw" });
  useHexStore.getState().setDumpPath(DUMP, 8320, "raw");
  useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
});

describe("hex-store bookmark views", () => {
  it("stamps the current (effective) view on a new bookmark", () => {
    useHexStore.getState().showView("vas"); // data-driven, not persisted
    useHexStore.getState().addBookmark({ offset: 0x1100, length: 1, label: "secret" });
    expect(useHexStore.getState().bookmarks).toEqual([
      { offset: 0x1100, length: 1, label: "secret", view: "vas" },
    ]);
    expect(JSON.parse(localStorage.getItem(BOOKMARKS_KEY)!)[0].view).toBe("vas");
  });

  it("keeps a caller-given view", () => {
    useHexStore.getState().addBookmark({ offset: 4, length: 1, label: "x", view: "vas" });
    expect(useHexStore.getState().bookmarks[0].view).toBe("vas");
  });

  it("treats the same offset in two views as two bookmarks", () => {
    const s = useHexStore.getState();
    s.addBookmark({ offset: 0x1b0, length: 1, label: "raw" });
    s.showView("vas");
    useHexStore.getState().addBookmark({ offset: 0x1b0, length: 1, label: "vas" });
    expect(useHexStore.getState().bookmarks.map((b) => b.view)).toEqual(["raw", "vas"]);
  });

  it("jumpToBookmark switches to the bookmark's view, then moves the cursor", () => {
    useHexStore.getState().addBookmark({ offset: 0x1100, length: 1, label: "s", view: "vas" });
    const [b] = useHexStore.getState().bookmarks;
    useHexStore.getState().jumpToBookmark(b);
    const s = useHexStore.getState();
    expect(s.viewMode).toBe("vas");
    expect(s.cursorOffset).toBe(0x1100);
    expect(s.scrollTarget).toBe(0x1100 / 16);
  });

  it("jumpToBookmark leaves the view alone for a legacy (view-less) bookmark", () => {
    localStorage.setItem(BOOKMARKS_KEY, JSON.stringify([{ offset: 0x20, length: 1, label: "old" }]));
    rehydrate();
    useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    useHexStore.getState().showView("vas");
    const [b] = useHexStore.getState().bookmarks;
    expect(b.view).toBeUndefined();
    useHexStore.getState().jumpToBookmark(b);
    expect(useHexStore.getState().viewMode).toBe("vas");
    expect(useHexStore.getState().cursorOffset).toBe(0x20);
  });

  it("drops a persisted bookmark with an unknown view", () => {
    localStorage.setItem(
      BOOKMARKS_KEY,
      JSON.stringify([
        { offset: 1, length: 1, label: "ok", view: "va" },
        { offset: 2, length: 1, label: "bad", view: "vsa" },
      ]),
    );
    rehydrate();
    expect(useHexStore.getState().bookmarks.map((b) => b.label)).toEqual(["ok"]);
  });

  it("removeBookmarkEntry removes only the exact (offset, length, view) entry", () => {
    const s = useHexStore.getState();
    s.addBookmark({ offset: 0x1b0, length: 1, label: "raw", view: "raw" });
    s.addBookmark({ offset: 0x1b0, length: 1, label: "vas", view: "vas" });
    useHexStore.getState().removeBookmarkEntry(useHexStore.getState().bookmarks[1]);
    expect(useHexStore.getState().bookmarks.map((b) => b.label)).toEqual(["raw"]);
  });

  it("removeBookmark keeps its (offset, length) contract across views", () => {
    const s = useHexStore.getState();
    s.addBookmark({ offset: 8, length: 2, label: "a", view: "raw" });
    s.addBookmark({ offset: 8, length: 2, label: "b", view: "vas" });
    useHexStore.getState().removeBookmark(8, 2);
    expect(useHexStore.getState().bookmarks).toEqual([]);
  });

  it("structure overlay highlights carry the overlay's view", () => {
    useHexStore.getState().setActiveStructureOverlay({
      structureName: "s",
      baseOffset: 0x10,
      totalSize: 4,
      view: "vas",
      fields: [{ name: "f", offset: 0x10, length: 4, display: "1", valid: true }],
    });
    const regions = useHexStore.getState().highlightedRegions.filter((r) => r.type === "structure");
    expect(regions).toHaveLength(1);
    expect(regions[0].view).toBe("vas");
  });
});
