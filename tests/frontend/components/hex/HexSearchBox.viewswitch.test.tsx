import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useHexStore } from "@/stores/hex-store";

const active = vi.hoisted(() => ({ path: "/a.mdview" }));
vi.mock("@/hooks/useActiveDump", () => ({ useActiveDump: () => ({ path: active.path, name: "v" }) }));

const { HexSearchBox } = await import("@/components/hex/HexSearchBox");

beforeEach(() => {
  active.path = "/a.mdview";
  useHexStore.setState({
    dumpPath: "/a.mdview", searchOffsets: [], highlightedRegions: [],
  });
});

describe("HexSearchBox view switch", () => {
  it("clears hits and search highlights when the active view changes", () => {
    const { rerender } = render(<HexSearchBox />);
    act(() => useHexStore.setState({
      searchOffsets: [4, 8],
      highlightedRegions: [
        { offset: 4, length: 1, type: "search", label: "hit" },
        { offset: 0, length: 1, type: "key_hit", label: "k" },
      ] as never,
    }));
    active.path = "/b.mdview";
    rerender(<HexSearchBox />);
    expect(useHexStore.getState().searchOffsets).toEqual([]);
    expect(useHexStore.getState().highlightedRegions.map((r) => r.type)).toEqual(["key_hit"]);
  });

  it("re-runs the search in the new view mode and drops the old-mode hits", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (u: string) => {
      urls.push(u);
      const mode = /view=(\w+)/.exec(u)![1];
      return { ok: true, json: async () => ({ offsets: mode === "raw" ? [4] : [100], pattern_len: 2, truncated: false }) };
    }));
    useHexStore.setState({ viewMode: "raw" } as never);
    render(<HexSearchBox />);
    fireEvent.change(screen.getByTestId("hex-search-pattern"), { target: { value: "dead" } });
    fireEvent.change(screen.getByTestId("hex-search-format"), { target: { value: "hex" } });
    fireEvent.click(screen.getByTestId("hex-search-find"));
    await waitFor(() => expect(useHexStore.getState().searchOffsets).toEqual([4]));
    act(() => useHexStore.setState({ viewMode: "vas" } as never));
    await waitFor(() => expect(useHexStore.getState().searchOffsets).toEqual([100]));
    expect(urls).toHaveLength(2);
    expect(urls[1]).toContain("view=vas");
    expect(useHexStore.getState().highlightedRegions.filter((r) => r.type === "search").map((r) => r.offset)).toEqual([100]);
    vi.unstubAllGlobals();
  });

  it("does not search on a mode change when nothing was searched", () => {
    const f = vi.fn();
    vi.stubGlobal("fetch", f);
    render(<HexSearchBox />);
    act(() => useHexStore.setState({ viewMode: "vas" } as never));
    expect(f).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
