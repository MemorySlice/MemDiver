import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";
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

const ENTROPY = {
  overall_entropy: 3.5,
  high_entropy_regions: [],
  profile_sample: [{ offset: 0, entropy: 1 }, { offset: 64, entropy: 2 }],
  stats: { min: 1, max: 2, mean: 1.5 },
  step: 64,
  window: 32,
  view: "raw" as const,
};

vi.mock("@/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/client")>();
  return {
    ...actual,
    getNotebookStatus: vi.fn(async () => ({ available: false })),
    getEntropy: vi.fn(async () => ENTROPY),
    getVasRegions: vi.fn(() => new Promise(() => {})),
    listDatasetRuns: vi.fn(() => new Promise(() => {})),
  };
});

// The real chart pulls in Plotly; a stub that counts mounts is what matters.
const chartMounts = vi.hoisted(() => ({ count: 0 }));
vi.mock("@/components/charts/EntropyChart", async () => {
  const { useEffect } = await import("react");
  return {
    EntropyChart: ({ data }: { data: { overall_entropy: number } }) => {
      useEffect(() => {
        chartMounts.count += 1;
      }, []);
      return <p data-testid="entropy-chart-stub">{data.overall_entropy}</p>;
    },
  };
});
vi.mock("@/components/charts/entropy-chart-loaders", () => ({
  preloadEntropyChart: vi.fn(async () => undefined),
}));

import { ENTROPY_ENVELOPE_BUCKETS, getEntropy } from "@/api/client";
import { preloadEntropyChart } from "@/components/charts/entropy-chart-loaders";
import { Workspace } from "@/components/layout/Workspace";
import { ThemeProvider } from "@/providers/ThemeProvider";
import { useAppStore } from "@/stores/app-store";

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

beforeEach(() => {
  (getEntropy as unknown as Mock).mockClear();
  (preloadEntropyChart as unknown as Mock).mockClear();
  chartMounts.count = 0;
  useAppStore.setState({ inputMode: "file", inputPath: "/dumps/a.bin", mode: "exploration" });
});

async function openTab(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByTestId(`tab-${name}`));
  });
}

describe("Workspace entropy tab", () => {
  it("fetches once, preloads the chart code alongside, and keeps the chart mounted", async () => {
    render(
      <ThemeProvider>
        <Workspace />
      </ThemeProvider>,
    );
    expect(getEntropy).not.toHaveBeenCalled();

    await openTab("entropy");
    expect(getEntropy).toHaveBeenCalledTimes(1);
    expect(preloadEntropyChart).toHaveBeenCalledTimes(1);
    expect(await screen.findByTestId("entropy-chart-stub")).toHaveTextContent("3.5");
    expect(chartMounts.count).toBe(1);

    await openTab("results");
    expect(screen.getByTestId("entropy-panel")).not.toBeVisible();

    await openTab("entropy");
    expect(screen.getByTestId("entropy-panel")).toBeVisible();
    expect(getEntropy).toHaveBeenCalledTimes(1);
    expect(chartMounts.count).toBe(1);
  });

  it("shows the localized loading state while the request is in flight", async () => {
    (getEntropy as unknown as Mock).mockImplementationOnce(() => new Promise(() => {}));
    render(
      <ThemeProvider>
        <Workspace />
      </ThemeProvider>,
    );
    await openTab("entropy");
    expect(screen.getByText("Loading entropy data...")).toBeVisible();
  });
});

describe("Workspace entropy progressive loading", () => {
  const SAMPLED = {
    ...ENTROPY,
    overall_entropy: 1.25,
    resolution: "sampled" as const,
    full_resolution_available: true,
  };
  const FULL = { ...ENTROPY, overall_entropy: 9.75, resolution: "full" as const, step: 1 };

  function deferred<T>() {
    let resolve!: (v: T) => void;
    let reject!: (e: unknown) => void;
    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { promise, resolve, reject };
  }

  function renderWorkspace() {
    render(
      <ThemeProvider>
        <Workspace />
      </ThemeProvider>,
    );
  }

  it("asks for the envelope, renders the sampled profile, then replaces it at full resolution", async () => {
    const full = deferred<typeof FULL>();
    (getEntropy as unknown as Mock)
      .mockImplementationOnce(async () => SAMPLED)
      .mockImplementationOnce(() => full.promise);
    renderWorkspace();
    await openTab("entropy");

    const [first, second] = (getEntropy as unknown as Mock).mock.calls;
    expect(first[0]).toBe("/dumps/a.bin");
    expect(first[4]).toEqual({ buckets: ENTROPY_ENVELOPE_BUCKETS });
    expect(second[4]).toMatchObject({ resolution: "full", buckets: ENTROPY_ENVELOPE_BUCKETS });
    expect(second[4].signal).toBeInstanceOf(AbortSignal);

    expect(await screen.findByTestId("entropy-chart-stub")).toHaveTextContent("1.25");
    expect(screen.getByTestId("entropy-refining")).toHaveTextContent("Refining at full resolution…");

    await act(async () => full.resolve(FULL));
    expect(screen.getByTestId("entropy-chart-stub")).toHaveTextContent("9.75");
    expect(screen.queryByTestId("entropy-refining")).toBeNull();
    // Refinement swaps the data in place; the chart is not remounted.
    expect(chartMounts.count).toBe(1);
  });

  it("does not refine when the first response is already full resolution", async () => {
    (getEntropy as unknown as Mock).mockImplementationOnce(async () => ({
      ...FULL,
      full_resolution_available: false,
    }));
    renderWorkspace();
    await openTab("entropy");
    expect(await screen.findByTestId("entropy-chart-stub")).toHaveTextContent("9.75");
    expect(getEntropy).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId("entropy-refining")).toBeNull();
  });

  it("keeps the sampled chart and shows a note when refinement fails", async () => {
    (getEntropy as unknown as Mock)
      .mockImplementationOnce(async () => SAMPLED)
      .mockImplementationOnce(async () => {
        throw new Error("boom");
      });
    renderWorkspace();
    await openTab("entropy");
    expect(await screen.findByTestId("entropy-refine-failed")).toBeVisible();
    expect(screen.getByTestId("entropy-chart-stub")).toHaveTextContent("1.25");
    expect(screen.queryByTestId("entropy-refining")).toBeNull();
  });

  it("drops a late full-resolution response for a dump that is no longer active", async () => {
    const staleFull = deferred<typeof FULL>();
    (getEntropy as unknown as Mock)
      .mockImplementationOnce(async () => SAMPLED)
      .mockImplementationOnce(() => staleFull.promise)
      .mockImplementationOnce(async () => ({ ...ENTROPY, overall_entropy: 4.5 }));
    renderWorkspace();
    await openTab("entropy");
    expect(await screen.findByTestId("entropy-chart-stub")).toHaveTextContent("1.25");
    const staleSignal = (getEntropy as unknown as Mock).mock.calls[1][4].signal as AbortSignal;

    await act(async () => {
      useAppStore.setState({ inputPath: "/dumps/b.bin" });
    });
    expect(await screen.findByText("4.5")).toBeInTheDocument();
    expect((getEntropy as unknown as Mock).mock.calls[2][0]).toBe("/dumps/b.bin");
    expect(staleSignal.aborted).toBe(true);

    await act(async () => staleFull.resolve(FULL));
    expect(screen.getByTestId("entropy-chart-stub")).toHaveTextContent("4.5");
    expect(screen.queryByTestId("entropy-refining")).toBeNull();
  });
});
