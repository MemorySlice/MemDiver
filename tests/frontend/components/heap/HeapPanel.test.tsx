import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { stubVirtualizerLayout } from "@tests/helpers/virtualizer";

vi.mock("@/api/heap", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/heap")>();
  return {
    ...actual,
    fetchHeapDetect: vi.fn(() => new Promise(() => {})),
    fetchHeapSummary: vi.fn(() => new Promise(() => {})),
    fetchHeapChunks: vi.fn(),
    fetchHeapFreeLists: vi.fn(),
    fetchHeapChunkAt: vi.fn(),
  };
});
// The chart backends are lazy Plotly/SVG modules; the panel's job is to hand
// them the summary's buckets.
vi.mock("@/components/heap/HeapSizeHistogram", () => ({
  HeapSizeHistogram: ({ buckets }: { buckets: unknown[] }) => (
    <p data-testid="heap-histogram-stub">{buckets.length}</p>
  ),
}));

import { fetchHeapChunkAt, fetchHeapChunks, fetchHeapFreeLists } from "@/api/heap";
import { HeapPanel } from "@/components/heap/HeapPanel";
import { __resetHeapStoreBookkeeping, useHeapStore } from "@/stores/heap-store";
import { useHexStore } from "@/stores/hex-store";
import { DETECTION, DUMP, FREE_LISTS, SUMMARY, chunk, chunksPage, seedDump } from "./heap-fixtures";

const A = chunk({ va: 0x1000, view_offset: 0x40, size: 32 });
const B = chunk({
  va: 0x2000, view_offset: 0x80, size: 64, state: "free", flags: 5, bin: "tcache[3]",
  extra: { prev_size: 32, fd: 0x3000, custom: "x" },
});

beforeEach(() => {
  __resetHeapStoreBookkeeping();
  stubVirtualizerLayout();
  vi.mocked(fetchHeapChunks).mockReset().mockResolvedValue(chunksPage([A, B]));
  vi.mocked(fetchHeapFreeLists).mockReset().mockResolvedValue(FREE_LISTS);
  vi.mocked(fetchHeapChunkAt).mockReset();
  useHexStore.setState({ viewMode: "vas", cursorOffset: null, scrollTarget: null });
  seedDump({
    allocator: "ptmalloc2",
    detection: { ...DETECTION, best: "ptmalloc2" },
    detectionStatus: "ready",
    summary: { ...SUMMARY, allocator: "ptmalloc2" },
    summaryStatus: "ready",
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function renderPanel() {
  await act(async () => {
    render(<HeapPanel dumpPath={DUMP} />);
  });
}

describe("HeapPanel chunk table", () => {
  it("loads the first page in the hex viewer's view and lists the chunks", async () => {
    await renderPanel();
    expect(fetchHeapChunks).toHaveBeenCalledWith(expect.objectContaining({ dumpPath: DUMP, view: "vas", page: 0 }));
    const rows = screen.getAllByTestId("heap-chunk-row");
    expect(rows).toHaveLength(2);
    expect(rows[1]).toHaveTextContent("0x2000");
    expect(rows[1]).toHaveTextContent("Free");
    expect(screen.getByTestId("heap-chunk-page")).toHaveTextContent("Page 1 of 1");
    expect(screen.getByTestId("heap-legend")).toBeInTheDocument();
  });

  it("a row click selects the chunk, scrolls the hex viewer and fills the inspector", async () => {
    await renderPanel();
    expect(screen.getByTestId("heap-inspector-empty")).toBeInTheDocument();
    await act(async () => fireEvent.click(screen.getAllByTestId("heap-chunk-row")[1]));

    expect(useHeapStore.getState().dumps[DUMP].selectedChunk?.va).toBe(0x2000);
    expect(useHexStore.getState().cursorOffset).toBe(0x80);
    expect(useHexStore.getState().scrollTarget).toBe(Math.floor(0x80 / 16));

    const inspector = screen.getByTestId("heap-inspector");
    expect(within(inspector).getByTestId("heap-inspector-va")).toHaveTextContent("0x2000");
    // ptmalloc size-word bits 1|4 decode to names.
    expect(within(inspector).getByTestId("heap-inspector-flags")).toHaveTextContent("PREV_INUSE NON_MAIN_ARENA");
    const extra = within(inspector).getByTestId("heap-inspector-extra");
    const keys = Array.from(extra.querySelectorAll("[data-field]")).map((n) => n.getAttribute("data-field"));
    expect(keys).toEqual(["prev_size", "fd", "custom"]);
    expect(extra).toHaveTextContent("0x3000");
  });

  it("a state filter refetches with the filter", async () => {
    await renderPanel();
    await act(async () => {
      fireEvent.change(screen.getByTestId("heap-filter-state"), { target: { value: "free" } });
    });
    expect(fetchHeapChunks).toHaveBeenLastCalledWith(
      expect.objectContaining({ filters: expect.objectContaining({ state: "free" }), page: 0 }),
    );
  });

  it("min/max size apply on submit", async () => {
    await renderPanel();
    fireEvent.change(screen.getByTestId("heap-filter-min"), { target: { value: "48" } });
    fireEvent.change(screen.getByTestId("heap-filter-max"), { target: { value: "0x100" } });
    await act(async () => fireEvent.click(screen.getByText("Apply")));
    expect(useHeapStore.getState().dumps[DUMP].filters).toEqual(expect.objectContaining({ minSize: 48, maxSize: 256 }));
  });

  it("a failed page shows the error and does not retry by itself", async () => {
    vi.mocked(fetchHeapChunks).mockReset().mockRejectedValue(new Error("down"));
    await renderPanel();
    expect(screen.getByRole("alert")).toHaveTextContent("down");
    expect(fetchHeapChunks).toHaveBeenCalledTimes(1);
  });

  it("a view switch while a page is in flight loads the new view's page once it settles", async () => {
    let settleRaw: (value: ReturnType<typeof chunksPage>) => void = () => {};
    vi.mocked(fetchHeapChunks)
      .mockReset()
      .mockImplementationOnce(() => new Promise((resolve) => { settleRaw = resolve; }))
      .mockResolvedValue(chunksPage([A, B]));
    useHexStore.setState({ viewMode: "raw" });
    await renderPanel();
    expect(fetchHeapChunks).toHaveBeenCalledWith(expect.objectContaining({ view: "raw" }));

    await act(async () => useHexStore.setState({ viewMode: "vas" }));
    await act(async () => settleRaw(chunksPage([])));

    expect(fetchHeapChunks).toHaveBeenCalledTimes(2);
    expect(fetchHeapChunks).toHaveBeenLastCalledWith(expect.objectContaining({ view: "vas" }));
    expect(screen.getAllByTestId("heap-chunk-row")).toHaveLength(2);
  });
});

describe("HeapPanel other views", () => {
  it("the histogram view receives the summary buckets", async () => {
    await renderPanel();
    await act(async () => fireEvent.click(screen.getByTestId("heap-view-histogram")));
    expect(screen.getByTestId("heap-histogram-stub")).toHaveTextContent("2");
  });

  it("the free-list tree flags cycles and jumps on a chain click", async () => {
    vi.mocked(fetchHeapChunkAt).mockResolvedValue({
      allocator: "ptmalloc2", va: 0x2000, view: "vas", view_offset: 0x80,
      found: true, chunk: B, role: "chunk_header", offset_in_chunk: 0, offset_in_user: null, prev: null, next: null,
    });
    await renderPanel();
    await act(async () => fireEvent.click(screen.getByTestId("heap-view-freeLists")));
    expect(fetchHeapFreeLists).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("heap-free-list-cycle")).toBeInTheDocument();
    expect(screen.queryByTestId("heap-free-list-corrupt")).toBeNull();

    await act(async () => fireEvent.click(screen.getAllByTestId("heap-free-list-entry")[1]));
    expect(fetchHeapChunkAt).toHaveBeenCalledWith(expect.objectContaining({ va: 0x2000, view: "vas" }));
    expect(useHexStore.getState().cursorOffset).toBe(0x80);
  });

  it("asks for a dump when none is active", () => {
    render(<HeapPanel dumpPath="" />);
    expect(screen.getByText(/Load a dump/)).toBeInTheDocument();
  });
});
