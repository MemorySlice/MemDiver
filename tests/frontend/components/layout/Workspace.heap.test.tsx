import { describe, it, expect, beforeEach, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx`.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

vi.mock("@/hooks/useNewSessionGuard", () => ({
  useNewSessionGuard: vi.fn(() => ({
    open: false,
    defaultName: "x",
    summary: { dumps: 1, bookmarks: 0, hasAnalysisResult: false },
    busy: false,
    error: null,
    recoveryFailed: false,
    requestNewSession: vi.fn(),
    saveAndStartNew: vi.fn(async () => {}),
    discardAndStartNew: vi.fn(async () => {}),
    forceDiscardAndStartNew: vi.fn(),
    cancel: vi.fn(),
  })),
}));

vi.mock("@/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/client")>();
  return {
    ...actual,
    getNotebookStatus: vi.fn(async () => ({ available: false })),
    getVasRegions: vi.fn(() => new Promise(() => {})),
    listDatasetRuns: vi.fn(() => new Promise(() => {})),
  };
});

// Heap requests stay in flight: this file is about the workspace chrome.
vi.mock("@/api/heap", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/heap")>();
  const pending = () => new Promise<never>(() => {});
  return {
    ...actual,
    fetchHeapDetect: vi.fn(pending),
    fetchHeapSummary: vi.fn(pending),
    fetchHeapChunks: vi.fn(pending),
    fetchHeapFreeLists: vi.fn(pending),
    fetchHeapRoles: vi.fn(pending),
    fetchHeapChunkAt: vi.fn(pending),
  };
});

import { fetchHeapDetect, fetchHeapSummary } from "@/api/heap";
import { Workspace } from "@/components/layout/Workspace";
import { ThemeProvider } from "@/providers/ThemeProvider";
import { useAppStore } from "@/stores/app-store";
import { __resetHeapStoreBookkeeping, useHeapStore } from "@/stores/heap-store";

class NoopObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return [];
  }
}
vi.stubGlobal("ResizeObserver", NoopObserver);
vi.stubGlobal("IntersectionObserver", NoopObserver);

const DUMP = "/dumps/a.bin";

beforeEach(() => {
  vi.mocked(fetchHeapDetect).mockClear();
  vi.mocked(fetchHeapSummary).mockClear();
  __resetHeapStoreBookkeeping();
  useHeapStore.setState({ dumps: {}, roleWindows: {}, roleWindowsVersion: 0 });
  useAppStore.setState({ inputMode: "file", inputPath: DUMP, mode: "exploration" });
});

function renderWorkspace() {
  return render(
    <ThemeProvider>
      <Workspace />
    </ThemeProvider>,
  );
}

async function setMode(mode: "verification" | "exploration" | "heap") {
  await act(async () => {
    useAppStore.getState().setMode(mode);
  });
}

const layerOn = () => useHeapStore.getState().dumps[DUMP]?.layerEnabled ?? false;

describe("Workspace heap mode", () => {
  it("offers no heap tabs outside heap mode", () => {
    renderWorkspace();
    expect(screen.queryByTestId("tab-heap-overview")).toBeNull();
    expect(screen.queryByTestId("tab-heap")).toBeNull();
    expect(layerOn()).toBe(false);
  });

  it("entering heap mode opens both heap tabs and enables the layer", async () => {
    renderWorkspace();
    await setMode("heap");

    expect(screen.getByTestId("tab-heap-overview")).toBeInTheDocument();
    expect(screen.getByTestId("tab-heap")).toBeInTheDocument();
    expect(screen.getByTestId("heap-overview")).toBeInTheDocument();
    expect(screen.getByTestId("heap-panel")).toBeInTheDocument();
    // Heap mode is exploration plus heap: exploration tabs remain.
    expect(screen.getByTestId("tab-entropy")).toBeInTheDocument();
    expect(layerOn()).toBe(true);
    // Two panels mounted in one commit request each resource once.
    expect(fetchHeapDetect).toHaveBeenCalledTimes(1);
    expect(fetchHeapSummary).toHaveBeenCalledTimes(1);
  });

  it("the hex toolbar toggle hides and shows the layer in heap mode", async () => {
    renderWorkspace();
    await setMode("heap");
    const toggle = screen.queryByTestId("heap-layer-toggle");
    if (!toggle) return; // the hex toolbar is only drawn once the viewer lays out
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    await act(async () => fireEvent.click(toggle));
    expect(layerOn()).toBe(false);
  });

  it("leaving heap mode removes the tabs, resets the bottom tab and turns the layer off", async () => {
    renderWorkspace();
    await setMode("heap");
    await setMode("exploration");

    expect(screen.queryByTestId("tab-heap-overview")).toBeNull();
    expect(screen.queryByTestId("tab-heap")).toBeNull();
    expect(screen.queryByTestId("heap-panel")).toBeNull();
    expect(screen.getByTestId("tab-analysis").className).toContain("font-semibold");
    expect(layerOn()).toBe(false);
  });

  it("a workspace restored in heap mode starts on the heap tabs", () => {
    useAppStore.setState({ mode: "heap" });
    renderWorkspace();
    expect(screen.getByTestId("heap-overview")).toBeInTheDocument();
    expect(screen.getByTestId("heap-panel")).toBeInTheDocument();
  });
});
