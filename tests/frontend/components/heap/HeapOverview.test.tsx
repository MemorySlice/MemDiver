import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

vi.mock("@/api/heap", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/heap")>();
  return {
    ...actual,
    fetchHeapDetect: vi.fn(() => new Promise(() => {})),
    fetchHeapSummary: vi.fn(() => new Promise(() => {})),
    fetchHeapChunkAt: vi.fn(),
  };
});

import { fetchHeapChunkAt, fetchHeapDetect } from "@/api/heap";
import { HeapOverview } from "@/components/heap/HeapOverview";
import { __resetHeapStoreBookkeeping, useHeapStore } from "@/stores/heap-store";
import { useHexStore } from "@/stores/hex-store";
import { DETECTION, DUMP, SUMMARY, seedDump } from "./heap-fixtures";

beforeEach(() => {
  __resetHeapStoreBookkeeping();
  vi.mocked(fetchHeapDetect).mockClear();
  vi.mocked(fetchHeapChunkAt).mockReset();
});

describe("HeapOverview", () => {
  it("asks for detection and summary when nothing is loaded, and shows loading", () => {
    seedDump({});
    render(<HeapOverview dumpPath={DUMP} />);
    expect(fetchHeapDetect).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("status")).toHaveTextContent("Analysing heap");
  });

  it("renders allocator, confidence, partial badge, platform, regions, counts, evidence and diagnostics", () => {
    seedDump({ detection: DETECTION, detectionStatus: "ready", summary: SUMMARY, summaryStatus: "ready" });
    render(<HeapOverview dumpPath={DUMP} />);

    expect(screen.getByTestId("heap-allocator-badge")).toHaveTextContent("jemalloc");
    expect(screen.getByText("62% confidence")).toBeInTheDocument();
    expect(screen.getByTestId("heap-badge-partial")).toBeInTheDocument();
    expect(screen.queryByTestId("heap-badge-heuristic")).toBeNull();
    expect(screen.getByTestId("heap-platform")).toHaveTextContent("linux / x86_64, 64-bit, little");
    expect(screen.getByText("5.3.0")).toBeInTheDocument();
    expect(screen.getByTestId("heap-regions")).toHaveTextContent("[anon:jemalloc]");
    expect(screen.getByTestId("heap-state-counts")).toHaveTextContent("In use");
    expect(screen.getByTestId("heap-evidence")).toHaveTextContent("[anon:jemalloc] present");
    expect(screen.getByTestId("heap-diagnostics")).toHaveTextContent("stride guessed");
    expect(screen.getByTestId("heap-candidates")).toHaveTextContent("glibc ptmalloc2");
  });

  it("shows the heuristic badge for the generic allocator", () => {
    seedDump({ summary: { ...SUMMARY, allocator: "generic", partial: false, heuristic: true }, summaryStatus: "ready", detectionStatus: "ready" });
    render(<HeapOverview dumpPath={DUMP} />);
    expect(screen.getByTestId("heap-badge-heuristic")).toBeInTheDocument();
  });

  it("shows the error with a retry and the empty state", () => {
    seedDump({ detectionStatus: "error", detectionError: "Heap detection failed: boom", summaryStatus: "ready",
      summary: { ...SUMMARY, chunk_count: 0, regions: [] } });
    render(<HeapOverview dumpPath={DUMP} />);
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
    expect(screen.getByTestId("heap-overview-empty")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Retry"));
    expect(fetchHeapDetect).toHaveBeenCalledTimes(1);
  });

  it("changing the allocator resets the dump to that allocator", () => {
    seedDump({ detection: DETECTION, detectionStatus: "ready", summary: SUMMARY, summaryStatus: "ready" });
    render(<HeapOverview dumpPath={DUMP} />);
    act(() => {
      fireEvent.change(screen.getByTestId("heap-allocator-select"), { target: { value: "scudo" } });
    });
    expect(useHeapStore.getState().dumps[DUMP].allocator).toBe("scudo");
    // Six concrete parsers plus auto.
    expect(screen.getByTestId("heap-allocator-select").querySelectorAll("option")).toHaveLength(7);
  });

  it("a region click translates its VA and scrolls the hex viewer", async () => {
    seedDump({ detection: DETECTION, detectionStatus: "ready", summary: SUMMARY, summaryStatus: "ready" });
    vi.mocked(fetchHeapChunkAt).mockResolvedValue({
      allocator: "jemalloc", va: SUMMARY.regions[0].va, view: "vas", view_offset: 0x4000,
      found: false, chunk: null, role: null, offset_in_chunk: null, offset_in_user: null, prev: null, next: null,
    });
    render(<HeapOverview dumpPath={DUMP} />);
    await act(async () => {
      fireEvent.click(screen.getByTestId("heap-regions").querySelector("button")!);
    });
    expect(fetchHeapChunkAt).toHaveBeenCalledWith(expect.objectContaining({ va: SUMMARY.regions[0].va, dumpPath: DUMP }));
    expect(useHexStore.getState().cursorOffset).toBe(0x4000);
  });

  it("a region outside the current view says so", async () => {
    seedDump({ detection: DETECTION, detectionStatus: "ready", summary: SUMMARY, summaryStatus: "ready" });
    vi.mocked(fetchHeapChunkAt).mockResolvedValue({
      allocator: "jemalloc", va: 1, view: "vas", view_offset: null,
      found: false, chunk: null, role: null, offset_in_chunk: null, offset_in_user: null, prev: null, next: null,
    });
    render(<HeapOverview dumpPath={DUMP} />);
    await act(async () => {
      fireEvent.click(screen.getByTestId("heap-regions").querySelector("button")!);
    });
    expect(screen.getByText(/not mapped in the current hex view/)).toBeInTheDocument();
  });
});
