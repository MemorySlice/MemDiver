import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { BrowseResult } from "@/api/types";
import type { FavouriteDir } from "@/api/settings";

/**
 * The browse dialog's favourites, end to end through the component.
 *
 * The feature was already built and already persisted when a user reported it
 * missing — because the only way to find it was a bare `☆` glyph, and the list
 * that would have explained it stayed hidden until you had already used it.
 * So the assertions here are mostly about DISCOVERABILITY: that the section is
 * on screen before there is anything in it, and that the toggle says what it
 * does.
 */

const api = vi.hoisted(() => ({
  getFavourites: vi.fn(),
  getLastDir: vi.fn(),
  addFavourite: vi.fn(),
  removeFavourite: vi.fn(),
  setLastDir: vi.fn(),
}));
vi.mock("@/api/settings", () => api);

const client = vi.hoisted(() => ({ browsePath: vi.fn() }));
// PARTIAL: the browse call is the only thing under test; `client.ts` also
// exports `request`/`ApiError`, which the modules below import for real.
vi.mock("@/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/client")>()),
  browsePath: client.browsePath,
}));

const { FileBrowser } = await import("@/components/wizard/FileBrowser");
const { useBrowserStore } = await import("@/stores/browser-store");

const HOME = "/Users/analyst";
const DUMPS = "/data/dumps";

function listing(current: string, entries: BrowseResult["entries"] = []): BrowseResult {
  return { current, parent: "/", entries } as BrowseResult;
}

function fav(path: string, label = path.split("/").pop() ?? path): FavouriteDir {
  return { path, label, added_at: 1 };
}

function open(onSelect = vi.fn()) {
  render(<FileBrowser onSelect={onSelect} onClose={vi.fn()} />);
  return onSelect;
}

beforeEach(() => {
  useBrowserStore.setState({
    favourites: [],
    lastDir: null,
    loaded: false,
    loading: false,
    error: null,
  });
  api.getFavourites.mockResolvedValue([]);
  api.getLastDir.mockResolvedValue(null);
  api.addFavourite.mockResolvedValue([]);
  api.removeFavourite.mockResolvedValue([]);
  api.setLastDir.mockResolvedValue(null);
  client.browsePath.mockImplementation(async (path?: string) => listing(path ?? HOME));
  localStorage.clear();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("FileBrowser favourites discoverability", () => {
  it("shows the Favourites section before anything is saved", async () => {
    open();

    const empty = await screen.findByTestId("file-browser-favourites-empty");
    expect(empty).toHaveTextContent(/No favourites yet/i);
    expect(screen.getByTestId("file-browser-favourites")).toBeInTheDocument();
  });

  it("labels the toggle in words, not just a glyph", async () => {
    open();

    const toggle = await screen.findByTestId("file-browser-favourite-toggle");
    await waitFor(() => expect(toggle).toBeEnabled());
    expect(toggle).toHaveTextContent("Favourite");
    expect(toggle).toHaveAttribute("aria-pressed", "false");
  });

  it("reflects a folder that is already saved", async () => {
    api.getFavourites.mockResolvedValue([fav(HOME, "home")]);
    open();

    const toggle = await screen.findByTestId("file-browser-favourite-toggle");
    await waitFor(() => expect(toggle).toHaveAttribute("aria-pressed", "true"));
    expect(toggle).toHaveTextContent("Favourited");
  });
});

describe("FileBrowser favourites actions", () => {
  it("saves the folder it is standing in", async () => {
    api.addFavourite.mockResolvedValue([fav(HOME, "analyst")]);
    open();

    const toggle = await screen.findByTestId("file-browser-favourite-toggle");
    await waitFor(() => expect(toggle).toBeEnabled());
    fireEvent.click(toggle);

    await waitFor(() => expect(api.addFavourite).toHaveBeenCalledWith(HOME, undefined));
    expect(await screen.findByTestId("file-browser-favourite")).toHaveTextContent(
      "analyst",
    );
  });

  it("un-saves it on a second press", async () => {
    api.getFavourites.mockResolvedValue([fav(HOME, "analyst")]);
    open();

    const toggle = await screen.findByTestId("file-browser-favourite-toggle");
    await waitFor(() => expect(toggle).toHaveAttribute("aria-pressed", "true"));
    fireEvent.click(toggle);

    await waitFor(() => expect(api.removeFavourite).toHaveBeenCalledWith(HOME));
  });

  it("navigates to a saved folder when it is clicked", async () => {
    api.getFavourites.mockResolvedValue([fav(DUMPS, "corpus")]);
    open();

    const row = await screen.findByTestId("file-browser-favourite");
    fireEvent.click(screen.getByTestId("file-browser-favourite-open"));

    await waitFor(() => expect(client.browsePath).toHaveBeenCalledWith(DUMPS));
    expect(row).toHaveTextContent(DUMPS);
  });

  it("removes a saved folder from the list", async () => {
    api.getFavourites.mockResolvedValue([fav(DUMPS, "corpus")]);
    open();

    await screen.findByTestId("file-browser-favourite");
    fireEvent.click(screen.getByTestId("file-browser-favourite-remove"));

    await waitFor(() => expect(api.removeFavourite).toHaveBeenCalledWith(DUMPS));
  });
});

describe("FileBrowser reopens where it was", () => {
  it("opens on the remembered directory instead of home", async () => {
    api.getLastDir.mockResolvedValue(DUMPS);
    open();

    await waitFor(() => expect(client.browsePath).toHaveBeenCalledWith(DUMPS));
    // Not the server default: that is the whole point.
    expect(client.browsePath).not.toHaveBeenCalledWith(undefined);
  });

  /**
   * The remembered directory can have been deleted or unmounted since. Without
   * the fallback the dialog would open empty, showing an error and offering no
   * way onwards.
   */
  it("falls back to home when the remembered directory is gone", async () => {
    api.getLastDir.mockResolvedValue("/gone");
    client.browsePath.mockImplementation(async (path?: string) =>
      path === "/gone"
        ? ({ error: "Path does not exist", entries: [] } as unknown as BrowseResult)
        : listing(HOME),
    );
    open();

    await waitFor(() => expect(client.browsePath).toHaveBeenCalledWith(undefined));
    await waitFor(() =>
      expect(screen.getByTestId("file-browser-path")).toHaveValue(HOME),
    );
  });

  it("remembers the directory that was selected", async () => {
    const onSelect = open();

    await waitFor(() => expect(client.browsePath).toHaveBeenCalled());
    fireEvent.click(await screen.findByRole("button", { name: "Select This Directory" }));

    expect(onSelect).toHaveBeenCalledWith(HOME);
    expect(api.setLastDir).toHaveBeenCalledWith(HOME);
  });

  /**
   * A backend that cannot answer must cost the favourites, never the dialog.
   */
  it("still browses when the favourites call fails", async () => {
    api.getFavourites.mockRejectedValue(new Error("backend down"));
    open();

    await waitFor(() => expect(client.browsePath).toHaveBeenCalled());
    expect(await screen.findByTestId("file-browser")).toBeInTheDocument();
  });
});
