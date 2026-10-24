/**
 * Side-by-side page-state tints, end to end through the REAL store and the
 * REAL `HexRow`: the mocked aligned-window response carries the anchor's
 * `page_states`, and the anchor pane's cells must take the page-state classes
 * while the peer's cells stay `no-correspondence` — and the legend must
 * explain the three tints exactly while they can be on screen.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore, type HexViewMode } from "@/stores/hex-store";
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

const { MultiHexViewer } = await import("@/components/hex/MultiHexViewer");

const REAL_ENSURE_CHUNKS = useHexStore.getState().ensureChunksLoaded;

function seed(view: HexViewMode, format: DumpEntry["format"] = "msl") {
  const dumps = [mslEntry(0), mslEntry(1)].map((d) => ({ ...d, format }));
  act(() => {
    useDumpStore.setState({
      dumps,
      selectedDumpIds: dumps.map((d) => d.id),
      activeDumpId: dumps[0].id,
      originDumpId: dumps[0].id,
      visibleDumps: new Set<string>(),
      mainView: "sideBySide",
    });
    useHexStore.getState().reset();
    useHexStore.setState({
      dumpPath: dumps[0].path,
      fileSize: dumps[0].size,
      format,
      viewMode: view,
      windowStartRow: 0,
      // The anchor's own single-dump bytes are not this test's subject.
      ensureChunksLoaded: () => {},
    });
    useConsensusStore.setState({ consensusId: "c1", builtFrom: [] });
  });
  return dumps;
}

function hexCell(container: HTMLElement, paneId: string, offset: number): HTMLElement {
  const el = container.querySelector(
    `[data-pane-id="${paneId}"] [data-col="hex"][data-offset="${offset}"]`,
  );
  if (!el) throw new Error(`no hex cell for ${paneId} at ${offset}`);
  return el as HTMLElement;
}

const FAILED = ABSENCE_META.failed.cellClass;
const UNMAPPED = ABSENCE_META.unmapped.cellClass;
const NOT_RESIDENT = ABSENCE_META["not-resident"].cellClass;
const GAP = ABSENCE_META["no-correspondence"].cellClass;
const PAGE_CLASSES = [FAILED, UNMAPPED, NOT_RESIDENT];

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

describe("MultiHexViewer page-state tints", () => {
  it("tints the anchor pane's cells by its page_states and leaves the peer alone", async () => {
    const [anchor, peer] = seed("va");
    const { container } = render(<MultiHexViewer />);

    await waitFor(() => expect(hexCell(container, anchor.id, 0)).toHaveClass(FAILED));
    expect(hexCell(container, anchor.id, 15)).toHaveClass(FAILED);
    expect(hexCell(container, anchor.id, 16)).toHaveClass(UNMAPPED);
    expect(hexCell(container, anchor.id, 32)).toHaveClass(NOT_RESIDENT);
    // A captured, aligned byte is not tinted at all.
    for (const cls of [...PAGE_CLASSES, GAP]) {
      expect(hexCell(container, anchor.id, 48)).not.toHaveClass(cls);
    }

    // The peer has no runs: its gap cells keep the no-correspondence hatch.
    for (const offset of [0, 16, 32]) {
      const cell = hexCell(container, peer.id, offset);
      expect(cell).toHaveClass(GAP);
      for (const cls of PAGE_CLASSES) expect(cell).not.toHaveClass(cls);
    }
    expect(fetchAlignedWindow).toHaveBeenCalled();
    expect(fetchAlignedWindow.mock.calls[0][0].view).toBe("va");
  });

  it("lists the three page states in the legend for an .msl anchor in va", () => {
    seed("va");
    render(<MultiHexViewer />);

    const legend = screen.getByTestId("multi-hex-legend");
    expect(legend).toHaveTextContent("Failed");
    expect(legend).toHaveTextContent("Unmapped");
    expect(legend).toHaveTextContent("Not resident");
    for (const kind of ["failed", "unmapped", "not-resident"] as const) {
      expect(
        screen.getByTestId(`hex-absence-legend-${ABSENCE_META[kind].swatchClass}`),
      ).toBeInTheDocument();
    }
  });

  it.each([
    ["an .msl anchor in vas", "vas", "msl"],
    ["a non-.msl anchor", "raw", "raw"],
  ] as [string, HexViewMode, DumpEntry["format"]][])("shows no page-state entries for %s", (_label, view, format) => {
    seed(view, format);
    render(<MultiHexViewer />);

    const legend = screen.getByTestId("multi-hex-legend");
    expect(legend).toHaveTextContent(/no correspondence/i);
    for (const kind of ["failed", "unmapped", "not-resident"] as const) {
      expect(
        screen.queryByTestId(`hex-absence-legend-${ABSENCE_META[kind].swatchClass}`),
      ).not.toBeInTheDocument();
    }
  });
});
