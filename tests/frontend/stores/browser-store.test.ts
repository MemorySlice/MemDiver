import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { FavouriteDir } from "@/api/settings";

/**
 * The favourites store, after it stopped being `localStorage`.
 *
 * It looked persisted before and mostly behaved that way, but `localStorage` is
 * keyed by origin: a different `--port`, a cleared cache or a second browser
 * each produced a silently empty list. These tests pin the replacement — the
 * server is the source of truth, every mutation adopts the list the server
 * returns, and the one-shot import of the old local list loses nothing.
 */

const api = vi.hoisted(() => ({
  getFavourites: vi.fn(),
  getLastDir: vi.fn(),
  addFavourite: vi.fn(),
  removeFavourite: vi.fn(),
  setLastDir: vi.fn(),
}));

vi.mock("@/api/settings", () => api);

const { useBrowserStore, normalizePath, defaultLabel } = await import(
  "@/stores/browser-store"
);

function fav(path: string, label = path.split("/").pop() ?? path): FavouriteDir {
  return { path, label, added_at: 1 };
}

const PRISTINE = {
  favourites: [] as FavouriteDir[],
  lastDir: null as string | null,
  loaded: false,
  loading: false,
  error: null as string | null,
};

beforeEach(() => {
  useBrowserStore.setState(PRISTINE);
  api.getFavourites.mockResolvedValue([]);
  api.getLastDir.mockResolvedValue(null);
  api.addFavourite.mockResolvedValue([]);
  api.removeFavourite.mockResolvedValue([]);
  api.setLastDir.mockResolvedValue(null);
  localStorage.clear();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("path helpers", () => {
  it("treats a trailing slash as the same directory", () => {
    expect(normalizePath("/data/dumps/")).toBe("/data/dumps");
    expect(normalizePath("/")).toBe("/");
    expect(normalizePath("")).toBe("");
  });

  it("labels a directory by its own name", () => {
    expect(defaultLabel("/data/dumps")).toBe("dumps");
    expect(defaultLabel("/data/dumps/")).toBe("dumps");
    expect(defaultLabel("/")).toBe("/");
  });
});

describe("browser-store load", () => {
  it("adopts what the server holds", async () => {
    api.getFavourites.mockResolvedValue([fav("/data/dumps")]);
    api.getLastDir.mockResolvedValue("/data/dumps");

    await useBrowserStore.getState().load();

    const state = useBrowserStore.getState();
    expect(state.favourites).toEqual([fav("/data/dumps")]);
    expect(state.lastDir).toBe("/data/dumps");
    expect(state.loaded).toBe(true);
    expect(state.error).toBeNull();
  });

  /**
   * A backend that cannot answer must cost the user their favourites, never
   * the dialog: browsing works perfectly well without a saved list, and
   * throwing here would take the whole file browser down with it.
   */
  it("still opens the browser when the server fails", async () => {
    api.getFavourites.mockRejectedValue(new Error("backend down"));

    await useBrowserStore.getState().load();

    const state = useBrowserStore.getState();
    expect(state.loaded).toBe(true);
    expect(state.favourites).toEqual([]);
    expect(state.error).toMatch(/backend down/);
  });

  it("does not stampede when called twice", async () => {
    const first = useBrowserStore.getState().load();
    const second = useBrowserStore.getState().load();
    await Promise.all([first, second]);

    expect(api.getFavourites).toHaveBeenCalledTimes(1);
  });
});

describe("browser-store legacy localStorage import", () => {
  /** Exactly the envelope zustand's `persist` middleware used to write. */
  function seedLegacy(bookmarks: unknown) {
    localStorage.setItem(
      "memdiver-browser",
      JSON.stringify({ state: { bookmarks }, version: 1 }),
    );
  }

  it("moves a curated list up to the server exactly once", async () => {
    seedLegacy([
      { id: "a", path: "/data/dumps", label: "corpus", addedAt: 1 },
      { id: "b", path: "/data/pcaps", label: "captures", addedAt: 2 },
    ]);
    api.addFavourite.mockResolvedValue([fav("/data/dumps"), fav("/data/pcaps")]);

    await useBrowserStore.getState().load();

    expect(api.addFavourite).toHaveBeenCalledWith("/data/dumps", "corpus");
    expect(api.addFavourite).toHaveBeenCalledWith("/data/pcaps", "captures");
    // The key is cleared, so a second load imports nothing.
    expect(localStorage.getItem("memdiver-browser")).toBeNull();
    expect(useBrowserStore.getState().favourites).toHaveLength(2);
  });

  /**
   * The server list is the newer truth. Re-importing over it would resurrect
   * entries the user has since deleted — a delete that undoes itself is worse
   * than no import at all.
   */
  it("leaves a non-empty server list alone", async () => {
    seedLegacy([{ id: "a", path: "/old", label: "old", addedAt: 1 }]);
    api.getFavourites.mockResolvedValue([fav("/data/dumps")]);

    await useBrowserStore.getState().load();

    expect(api.addFavourite).not.toHaveBeenCalled();
    expect(useBrowserStore.getState().favourites).toEqual([fav("/data/dumps")]);
  });

  it("keeps importing after one entry is refused", async () => {
    seedLegacy([
      { id: "a", path: "/gone", label: "gone", addedAt: 1 },
      { id: "b", path: "/data/dumps", label: "corpus", addedAt: 2 },
    ]);
    api.addFavourite
      .mockRejectedValueOnce(new Error("/gone does not exist"))
      .mockResolvedValueOnce([fav("/data/dumps")]);

    await useBrowserStore.getState().load();

    expect(api.addFavourite).toHaveBeenCalledTimes(2);
    expect(useBrowserStore.getState().favourites).toEqual([fav("/data/dumps")]);
  });

  it.each([
    ["not json at all", "{{{"],
    ["a missing state key", JSON.stringify({ version: 1 })],
    ["bookmarks that are not a list", JSON.stringify({ state: { bookmarks: 7 } })],
  ])("survives %s", async (_name, raw) => {
    localStorage.setItem("memdiver-browser", raw);

    await useBrowserStore.getState().load();

    expect(api.addFavourite).not.toHaveBeenCalled();
    expect(useBrowserStore.getState().loaded).toBe(true);
  });
});

describe("browser-store mutations", () => {
  it("adopts the list the server answers with rather than patching locally", async () => {
    api.addFavourite.mockResolvedValue([fav("/data/dumps")]);

    await useBrowserStore.getState().addFavourite("/data/dumps/");

    // Normalised on the way out — the server keys on the path.
    expect(api.addFavourite).toHaveBeenCalledWith("/data/dumps", undefined);
    expect(useBrowserStore.getState().favourites).toEqual([fav("/data/dumps")]);
  });

  it("ignores an empty path", async () => {
    await useBrowserStore.getState().addFavourite("");

    expect(api.addFavourite).not.toHaveBeenCalled();
  });

  it("reports a rejected save without losing the current list", async () => {
    useBrowserStore.setState({ favourites: [fav("/data/dumps")] });
    api.addFavourite.mockRejectedValue(new Error("/nope does not exist"));

    await useBrowserStore.getState().addFavourite("/nope");

    const state = useBrowserStore.getState();
    expect(state.error).toMatch(/does not exist/);
    expect(state.favourites).toEqual([fav("/data/dumps")]);
  });

  it("removes through the server", async () => {
    useBrowserStore.setState({ favourites: [fav("/data/dumps")] });

    await useBrowserStore.getState().removeFavourite("/data/dumps");

    expect(api.removeFavourite).toHaveBeenCalledWith("/data/dumps");
    expect(useBrowserStore.getState().favourites).toEqual([]);
  });

  /** Rename rides the upsert-by-path POST; there is no second endpoint. */
  it("renames through the same upsert", async () => {
    api.addFavourite.mockResolvedValue([fav("/data/dumps", "TLS corpus")]);

    await useBrowserStore.getState().renameFavourite("/data/dumps", "  TLS corpus  ");

    expect(api.addFavourite).toHaveBeenCalledWith("/data/dumps", "TLS corpus");
  });

  it("refuses to rename to nothing", async () => {
    await useBrowserStore.getState().renameFavourite("/data/dumps", "   ");

    expect(api.addFavourite).not.toHaveBeenCalled();
  });

  it("knows whether the current directory is saved", () => {
    useBrowserStore.setState({ favourites: [fav("/data/dumps")] });

    expect(useBrowserStore.getState().isFavourite("/data/dumps")).toBe(true);
    expect(useBrowserStore.getState().isFavourite("/data/dumps/")).toBe(true);
    expect(useBrowserStore.getState().isFavourite("/data")).toBe(false);
  });
});

describe("browser-store last directory", () => {
  it("remembers locally and tells the server", () => {
    useBrowserStore.getState().rememberLastDir("/data/dumps/");

    expect(useBrowserStore.getState().lastDir).toBe("/data/dumps");
    expect(api.setLastDir).toHaveBeenCalledWith("/data/dumps");
  });

  it("does not re-write the directory it is already on", () => {
    useBrowserStore.setState({ lastDir: "/data/dumps" });

    useBrowserStore.getState().rememberLastDir("/data/dumps");

    expect(api.setLastDir).not.toHaveBeenCalled();
  });

  /** Failing to remember where you were is not worth interrupting anything. */
  it("swallows a failed write", () => {
    api.setLastDir.mockRejectedValue(new Error("backend down"));

    expect(() => useBrowserStore.getState().rememberLastDir("/data/dumps")).not.toThrow();
    expect(useBrowserStore.getState().lastDir).toBe("/data/dumps");
  });
});
