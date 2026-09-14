/**
 * What the PANES do when a window fails — with the real `HexRow`.
 *
 * `MultiHexViewer.test.tsx` mocks the row away, because its subject is the
 * `rowOffset` every pane is handed. That mock is also why the failure below
 * went unnoticed: the banner it asserts is a sibling of the grid, and a banner
 * can appear over cells that never changed.
 *
 * The bug: `byteReaders` was memoized on `chunkVersionByPath`, which
 * `applyResponse` bumps and nothing else does. A failed fetch writes only
 * `chunkErrors` and `pending`, so the readers never rotated, `HexRow`'s memo
 * never re-ran, and the cells the store now describes as `"error"` kept
 * painting the `··` they had while the request was in flight — leaving
 * `.byte-error`, its high-contrast rule and the `Load failed` legend swatch
 * unreachable in the product.
 *
 * Which is why the failure is injected AFTER the first render: seeding it up
 * front would be answered by the initial paint and prove nothing.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import type { AlignedWindowAlignment } from "@/api/aligned-window";
import { stubVirtualizerLayout } from "@tests/helpers/virtualizer";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const { MultiHexViewer } = await import("@/components/hex/MultiHexViewer");

const ALIGNMENT: AlignedWindowAlignment = {
  method: "module_offset",
  bytes_compared: 8192,
  bytes_discarded: 0,
  sizes_differed: false,
  n_sources: 2,
  warnings: [],
};

function entry(i: number): DumpEntry {
  return {
    id: `d${i}`,
    path: `/dumps/d${i}.msl`,
    name: `d${i}.msl`,
    size: 64 * 1024,
    format: "msl",
    sameProcess: true,
  };
}

function seed() {
  const dumps = [entry(0), entry(1)];
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
      format: "msl",
      windowStartRow: 0,
    });
    useConsensusStore.setState({ consensusId: "c1", builtFrom: [] });
    useMultiHexStore.setState({
      alignment: ALIGNMENT,
      truncated: false,
      ensureLoaded: () => {},
      isPresentAt: () => true,
      getByteAt: (_path: string, offset: number) => offset % 256,
      absenceAt: () => null,
    });
  });
  return dumps;
}

/**
 * Exactly what `ensureLoaded`'s failure path writes: the chunk key recorded
 * under the live identity, and no version bump anywhere.
 */
function failVisibleChunk(message = "Internal Server Error") {
  act(() => {
    useMultiHexStore.setState({
      identity: "seeded",
      chunkErrors: new Map([["seeded|0", { message, attempts: 0, nextRetryAt: 0 }]]),
      isPresentAt: () => false,
      absenceAt: () => "error",
    });
  });
}

/** Every hex cell the grid rendered for `offset`, one per pane. */
function hexCells(container: HTMLElement, offset: number): HTMLElement[] {
  return [...container.querySelectorAll(`[data-col="hex"][data-offset="${offset}"]`)] as
    HTMLElement[];
}

beforeEach(() => {
  stubVirtualizerLayout();
});

afterEach(() => {
  vi.restoreAllMocks();
  act(() => {
    useDumpStore.getState().clearAll();
    useMultiHexStore.getState().reset();
    useConsensusStore.getState().reset();
    useHexStore.getState().reset();
  });
});

describe("MultiHexViewer chunk failure reaches the cells", () => {
  it("paints byte-error on every pane's cell once the chunk fails", () => {
    seed();
    const { container } = render(<MultiHexViewer />);

    const before = hexCells(container, 0);
    expect(before.length).toBe(2);
    for (const cell of before) expect(cell).not.toHaveClass("byte-error");

    failVisibleChunk();

    const after = hexCells(container, 0);
    expect(after.length).toBe(2);
    for (const cell of after) {
      expect(cell).toHaveClass("byte-error");
      // The glyph and the class have to agree: a cell that says `··` while its
      // class says "load failed" is the confusion this vocabulary removes.
      expect(cell).toHaveTextContent("!!");
      expect(cell).not.toHaveClass("hex-loading");
    }
  });

  it("raises the banner over the cells it describes, not instead of them", () => {
    seed();
    const { container } = render(<MultiHexViewer />);

    failVisibleChunk("boom");

    expect(screen.getByTestId("multi-hex-window-error")).toHaveTextContent("boom");
    expect(hexCells(container, 0)[0]).toHaveClass("byte-error");
  });

  it("takes the treatment back off when the chunk is retried and lands", () => {
    seed();
    const { container } = render(<MultiHexViewer />);
    failVisibleChunk();

    act(() => {
      useMultiHexStore.setState({
        chunkErrors: new Map(),
        isPresentAt: () => true,
        absenceAt: () => null,
      });
    });

    expect(hexCells(container, 0)[0]).not.toHaveClass("byte-error");
  });
});
