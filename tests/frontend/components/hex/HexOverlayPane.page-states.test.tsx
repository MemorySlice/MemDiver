/**
 * Overlay page-state tints read from the ALIGNED WINDOW, so they survive a
 * re-anchor.
 *
 * The bug: the overlay used to tint from `hex-store.getPageStateAt`, whose
 * intervals `setDumpPath` clears on every anchor change — and nothing in the
 * N-pane layouts refetched them, so the tints were gone after the first
 * re-anchor. The aligned window delivers the new anchor's runs with every
 * chunk, so the tints now follow the anchor.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import type { AlignedWindowRequest } from "@/api/aligned-window";
import { ABSENCE_META } from "@/utils/absence-classes";
import { stubVirtualizerLayout } from "@tests/helpers/virtualizer";
import {
  mslEntry,
  pageStateWindow,
  stubViewSizeProbe,
} from "@tests/helpers/page-state-window";

vi.mock("@/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/client")>()),
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const fetchAlignedWindow = vi.fn(async (req: AlignedWindowRequest) => pageStateWindow(req));
vi.mock("@/api/aligned-window", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/aligned-window")>()),
  fetchAlignedWindow: (req: AlignedWindowRequest) => fetchAlignedWindow(req),
}));

const { HexOverlayPane } = await import("@/components/hex/HexOverlayPane");

const REAL_ENSURE_CHUNKS = useHexStore.getState().ensureChunksLoaded;

function seed() {
  const dumps = [mslEntry(0), mslEntry(1)];
  act(() => {
    useDumpStore.setState({
      dumps,
      selectedDumpIds: dumps.map((d) => d.id),
      activeDumpId: dumps[0].id,
      originDumpId: dumps[0].id,
      visibleDumps: new Set<string>(),
      mainView: "overlay",
    });
    useHexStore.getState().reset();
    useHexStore.setState({
      dumpPath: dumps[0].path,
      fileSize: dumps[0].size,
      format: "msl",
      viewMode: "va",
      windowStartRow: 0,
      ensureChunksLoaded: () => {},
    });
    useConsensusStore.setState({ consensusId: "c1", builtFrom: [] });
  });
  return dumps;
}

function hexCell(container: HTMLElement, offset: number): HTMLElement {
  const el = container.querySelector(`[data-col="hex"][data-offset="${offset}"]`);
  if (!el) throw new Error(`no hex cell at offset ${offset}`);
  return el as HTMLElement;
}

const FAILED = ABSENCE_META.failed.cellClass;
const UNMAPPED = ABSENCE_META.unmapped.cellClass;

beforeEach(() => {
  fetchAlignedWindow.mockClear();
  stubVirtualizerLayout();
  stubViewSizeProbe();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  act(() => {
    useDumpStore.getState().clearAll();
    useMultiHexStore.getState().reset();
    useConsensusStore.getState().reset();
    useHexStore.getState().reset();
    useHexStore.setState({ ensureChunksLoaded: REAL_ENSURE_CHUNKS });
  });
});

describe("HexOverlayPane page-state tints", () => {
  it("tints the anchor's non-captured pages from the aligned window", async () => {
    seed();
    const { container } = render(<HexOverlayPane />);

    await waitFor(() => expect(hexCell(container, 0)).toHaveClass(FAILED));
    expect(hexCell(container, 16)).toHaveClass(UNMAPPED);
    expect(screen.getByTestId("hex-absence-legend-absence-page-failed")).toBeInTheDocument();
  });

  it("keeps the tints after a re-anchor, for the NEW anchor", async () => {
    const [, peer] = seed();
    const { container } = render(<HexOverlayPane />);
    await waitFor(() => expect(hexCell(container, 0)).toHaveClass(FAILED));

    act(() => useDumpStore.getState().setActiveDump(peer.id));

    await waitFor(() => {
      const last = fetchAlignedWindow.mock.calls.at(-1)?.[0];
      expect(last?.anchor_path).toBe(peer.path);
    });
    await waitFor(() => expect(hexCell(container, 0)).toHaveClass(FAILED));
    expect(hexCell(container, 16)).toHaveClass(UNMAPPED);
    // The re-anchor cleared hex-store's own intervals — the tint above cannot
    // have come from there.
    expect(useHexStore.getState().pageStatesLoaded).toBe(false);
    expect(screen.getByTestId("hex-absence-legend-absence-page-failed")).toBeInTheDocument();
  });
});
