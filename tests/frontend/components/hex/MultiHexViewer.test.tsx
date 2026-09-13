import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import type { AlignedWindowAlignment } from "@/api/aligned-window";
import { CHUNK_SIZE } from "@/components/hex/multi-window-utils";
import { BYTES_PER_ROW } from "@/components/hex/window-utils";
import { stubVirtualizerLayout } from "@tests/helpers/virtualizer";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

/**
 * Every `HexRow` this render produced, in DOM order, with the props that decide
 * WHERE its bytes come from. Mocking the row is what makes the alignment
 * guarantee directly observable: the claim is about the `rowOffset` each pane
 * is handed, not about the glyphs it happens to paint.
 */
const rows: { rowOffset: number }[] = [];
vi.mock("@/components/hex/HexRow", () => ({
  HexRow: (props: { rowOffset: number }) => {
    rows.push({ rowOffset: props.rowOffset });
    return <div data-testid="hex-row" data-row-offset={props.rowOffset} />;
  },
}));

const { MultiHexViewer } = await import("@/components/hex/MultiHexViewer");

/**
 * The store's REAL range walk, captured before any test replaces it.
 *
 * `setState` on a zustand store overwrites its actions permanently — `reset()`
 * restores data, not methods — so a test that wants the real implementation
 * has to put it back, or it silently inherits whichever stub ran first.
 */
const realGetChunkErrorsInRange = useMultiHexStore.getState().getChunkErrorsInRange;

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

const MODULE_ALIGNMENT: AlignedWindowAlignment = {
  method: "module_offset",
  bytes_compared: 8192,
  bytes_discarded: 0,
  sizes_differed: false,
  n_sources: 2,
  warnings: [],
};

/**
 * Seeds `n` selected dumps and neutralises the network.
 *
 * `ensureLoaded` is replaced rather than mocked at the `fetch` boundary: these
 * are tests of the VIEWER, and the store's own fetch/dedupe/eviction behaviour
 * already has a 28-test suite of its own. Replacing the getters likewise lets a
 * test state what the panes hold without hand-rolling a base64 response.
 */
function seed(
  n: number,
  alignment: AlignedWindowAlignment = MODULE_ALIGNMENT,
  // The viewer now REFUSES to paint without a consensus that describes the
  // selection — with none, the store falls back to posting `dump_paths` and
  // the server rebuilds the whole consensus for every 8 KiB chunk. `builtFrom`
  // stays empty ("this build cannot name its dumps"), which is the permissive
  // case, so these tests keep asserting about panes rather than provenance.
  consensusId: string | null = "c1",
) {
  const dumps = Array.from({ length: n }, (_, i) => entry(i));
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
    useConsensusStore.setState({ consensusId, builtFrom: [] });
    useMultiHexStore.setState({
      alignment,
      truncated: false,
      ensureLoaded: () => {},
      isPresentAt: () => true,
      getByteAt: (_path: string, offset: number) => offset % 256,
    });
  });
  return dumps;
}

beforeEach(() => {
  rows.length = 0;
  stubVirtualizerLayout();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  act(() => {
    useDumpStore.getState().clearAll();
    useMultiHexStore.getState().reset();
    useConsensusStore.getState().reset();
  });
});

describe("MultiHexViewer pane membership", () => {
  it("renders one pane per selected dump", () => {
    const dumps = seed(3);
    render(<MultiHexViewer />);

    for (const d of dumps) {
      expect(screen.getByTestId(`hex-pane-header-${d.id}`)).toBeInTheDocument();
    }
  });

  it("caps the panes at MAX_PANES and points at Overlay", () => {
    seed(7);
    render(<MultiHexViewer />);

    expect(screen.getAllByTestId(/^hex-pane-header-/)).toHaveLength(6);
    expect(screen.queryByTestId("hex-pane-header-d6")).not.toBeInTheDocument();

    const note = screen.getByTestId("multi-hex-pane-cap");
    expect(note).toHaveTextContent("Showing 6 of 7 selected dumps.");
    expect(note).toHaveTextContent(/Overlay/);
  });

  it("shows no cap note while the selection fits", () => {
    seed(6);
    render(<MultiHexViewer />);

    expect(screen.queryByTestId("multi-hex-pane-cap")).not.toBeInTheDocument();
  });
});

/**
 * THE flagship assertion.
 *
 * One scroll container, one virtualizer, N columns per virtual row: byte
 * alignment is structural, so every pane on a given virtual row must receive
 * the IDENTICAL `rowOffset`. A mirrored-scroll implementation can satisfy this
 * on a still frame and violate it mid-scroll; this one cannot express the
 * violation at all, and that is exactly what is being pinned.
 */
describe("MultiHexViewer row alignment", () => {
  it("hands every pane the same rowOffset on each virtual row", () => {
    seed(4);
    const { container } = render(<MultiHexViewer />);

    const rowEls = container.querySelectorAll("[data-row-offset][data-index]");
    expect(rowEls.length).toBeGreaterThan(0);

    for (const rowEl of rowEls) {
      const expected = rowEl.getAttribute("data-row-offset");
      const cells = rowEl.querySelectorAll("[data-testid='hex-row']");
      expect(cells).toHaveLength(4);
      for (const cell of cells) {
        expect(cell.getAttribute("data-row-offset")).toBe(expected);
      }
    }
  });

  it("advances the shared rowOffset by exactly 16 bytes per row", () => {
    seed(2);
    const { container } = render(<MultiHexViewer />);

    const offsets = [...container.querySelectorAll("[data-row-offset][data-index]")].map(
      (el) => Number(el.getAttribute("data-row-offset")),
    );
    expect(offsets.length).toBeGreaterThan(1);
    for (let i = 1; i < offsets.length; i++) {
      expect(offsets[i] - offsets[i - 1]).toBe(16);
    }
  });

  it("gives every HexRow of one virtual row the same offset, pane count aside", () => {
    seed(3);
    render(<MultiHexViewer />);

    // Three panes => the recorded rowOffsets arrive in runs of three equal
    // values, one run per virtual row.
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.length % 3).toBe(0);
    for (let i = 0; i < rows.length; i += 3) {
      expect(rows[i + 1].rowOffset).toBe(rows[i].rowOffset);
      expect(rows[i + 2].rowOffset).toBe(rows[i].rowOffset);
    }
  });
});

describe("MultiHexViewer focus", () => {
  it("moves activeDumpId when a pane is clicked", () => {
    const dumps = seed(3);
    render(<MultiHexViewer />);

    expect(useDumpStore.getState().activeDumpId).toBe(dumps[0].id);

    fireEvent.click(screen.getByTestId(`hex-pane-focus-${dumps[1].id}`));

    expect(useDumpStore.getState().activeDumpId).toBe(dumps[1].id);
  });

  it("marks the focused pane with aria-current and a text pill, not colour alone", () => {
    const dumps = seed(2);
    render(<MultiHexViewer />);

    const focused = screen.getByTestId(`hex-pane-header-${dumps[0].id}`);
    expect(focused).toHaveAttribute("aria-current", "true");
    expect(screen.getByTestId(`hex-pane-focus-pill-${dumps[0].id}`)).toBeInTheDocument();

    const other = screen.getByTestId(`hex-pane-header-${dumps[1].id}`);
    expect(other).not.toHaveAttribute("aria-current");
    expect(screen.queryByTestId(`hex-pane-focus-pill-${dumps[1].id}`)).not.toBeInTheDocument();
  });

  it("labels the session origin", () => {
    const dumps = seed(2);
    render(<MultiHexViewer />);

    expect(screen.getByTestId(`hex-pane-origin-${dumps[0].id}`)).toBeInTheDocument();
    expect(screen.queryByTestId(`hex-pane-origin-${dumps[1].id}`)).not.toBeInTheDocument();
  });
});

describe("MultiHexViewer collapse", () => {
  /**
   * Collapse is a VIEW state. A dump folded away is still selected, still
   * analysed and still contributes to the consensus classes the other panes
   * are painted with — so a collapse that quietly narrowed the analysis would
   * change the answer, not just the picture.
   */
  it("hides the pane without touching the selection", () => {
    const dumps = seed(3);
    render(<MultiHexViewer />);

    fireEvent.click(screen.getByTestId(`hex-pane-collapse-${dumps[1].id}`));

    expect(screen.queryByTestId(`hex-pane-header-${dumps[1].id}`)).not.toBeInTheDocument();
    expect(useDumpStore.getState().selectedDumpIds).toEqual(dumps.map((d) => d.id));
  });

  it("offers the collapsed dump back", () => {
    const dumps = seed(3);
    render(<MultiHexViewer />);

    fireEvent.click(screen.getByTestId(`hex-pane-collapse-${dumps[2].id}`));
    expect(screen.getByTestId(`hex-pane-restore-${dumps[2].id}`)).toBeInTheDocument();

    fireEvent.click(screen.getByTestId(`hex-pane-restore-${dumps[2].id}`));
    expect(screen.getByTestId(`hex-pane-header-${dumps[2].id}`)).toBeInTheDocument();
  });

  it("does not collapse the pane when its name is clicked", () => {
    const dumps = seed(2);
    render(<MultiHexViewer />);

    fireEvent.click(screen.getByTestId(`hex-pane-focus-${dumps[1].id}`));

    expect(screen.getByTestId(`hex-pane-header-${dumps[1].id}`)).toBeInTheDocument();
  });
});

describe("MultiHexViewer alignment chip", () => {
  it("names the method in words on every window", () => {
    seed(2);
    render(<MultiHexViewer />);

    expect(screen.getByTestId("hex-alignment-method")).toHaveTextContent(
      "Aligned by module offset",
    );
  });

  /**
   * Silent misalignment is the worst failure this view can produce: the panes
   * still line up and the bytes still look plausible. `file_offset` over `.msl`
   * dumps therefore says so in words AND offers the fix.
   */
  it("warns on file_offset and offers to run a consensus", () => {
    seed(2, {
      method: "file_offset",
      bytes_compared: 4096,
      bytes_discarded: 128,
      sizes_differed: true,
      n_sources: 2,
      warnings: ["dump sizes differ"],
    });
    render(<MultiHexViewer />);

    expect(screen.getByTestId("hex-alignment-method")).toHaveTextContent(
      "Aligned by file offset",
    );
    expect(screen.getByTestId("hex-alignment-file-offset-warning")).toHaveTextContent(
      /may not be the same address/i,
    );
    expect(screen.getByTestId("hex-alignment-warning")).toHaveTextContent("dump sizes differ");
    expect(screen.getByTestId("hex-alignment-run-consensus")).toBeInTheDocument();
  });

  it("does not offer the consensus action for an already aligned window", () => {
    seed(2);
    render(<MultiHexViewer />);

    expect(screen.queryByTestId("hex-alignment-run-consensus")).not.toBeInTheDocument();
  });

  it("surfaces a truncated window", () => {
    seed(2);
    act(() => {
      useMultiHexStore.setState({ truncated: true });
    });
    render(<MultiHexViewer />);

    expect(screen.getByTestId("hex-alignment-truncated")).toBeInTheDocument();
  });
});

describe("MultiHexViewer absence vocabulary", () => {
  /**
   * Side-by-side had no legend at all, so the hatched cells it now paints
   * would have been a private notation.
   */
  it("names the three absences in a legend strip", () => {
    seed(2);
    render(<MultiHexViewer />);

    const legend = screen.getByTestId("multi-hex-legend");
    expect(legend).toHaveTextContent(/no correspondence/i);
    expect(legend).toHaveTextContent(/not in this dump/i);
    expect(legend).toHaveTextContent(/load failed/i);
    expect(screen.getByTestId("hex-absence-legend-absence-gap")).toBeInTheDocument();
    expect(screen.getByTestId("hex-absence-legend-absence-absent")).toBeInTheDocument();
    expect(screen.getByTestId("hex-absence-legend-absence-error")).toBeInTheDocument();
  });

  /**
   * Absence is the NORMAL case — the aligned slab holds only pages every dump
   * captured at the same ASLR-invariant key — so the viewer has to say so
   * where the analyst is already reading the alignment, not leave them to
   * conclude that something broke.
   */
  it("explains discarded bytes where the alignment is reported", () => {
    // 4096 compared across 2 sources + 8192 discarded = 16384 offered.
    seed(2, { ...MODULE_ALIGNMENT, bytes_compared: 4096, bytes_discarded: 8192 });
    render(<MultiHexViewer />);

    const note = screen.getByTestId("hex-alignment-discard-note");
    // Folded away by default: the chip has to stay a chip.
    expect((note as HTMLDetailsElement).open).toBe(false);
    expect(note).toHaveTextContent("50.0%");
    expect(note).toHaveTextContent(/anonymous/i);
    expect(note).toHaveTextContent(/never as a difference/i);
  });

  it("offers no such note when nothing was discarded", () => {
    seed(2);
    render(<MultiHexViewer />);

    expect(screen.queryByTestId("hex-alignment-discard-note")).toBeNull();
  });
});

describe("MultiHexViewer window-error banner", () => {
  it("renders a Retry control and asks the store to retry the visible chunk", () => {
    seed(2);
    const retryChunksInRange = vi.fn();
    act(() => {
      useMultiHexStore.setState({
        retryChunksInRange,
        getChunkErrorsInRange: () => [{ offset: 0, message: "Internal Server Error" }],
      });
    });

    render(<MultiHexViewer />);

    const banner = screen.getByTestId("multi-hex-window-error");
    expect(banner).toBeInTheDocument();
    // The message text resolves through i18n, never a hardcoded string.
    expect(banner).toHaveTextContent("Internal Server Error");

    const retry = screen.getByTestId("multi-hex-window-retry");
    fireEvent.click(retry);
    expect(retryChunksInRange).toHaveBeenCalled();
  });

  /**
   * The dead end this replaced: the banner used to inspect the FIRST and LAST
   * visible row's chunk only, so a chunk failing anywhere between them showed
   * nothing at all — a band of `--` in the middle of the grid, with the retry
   * control reachable from nowhere.
   */
  it("raises the banner for a chunk failing in the MIDDLE of the visible window", () => {
    seed(2);
    const retryChunksInRange = vi.fn();
    // Tall enough that four chunks are on screen, so chunk 2 is interior: it
    // is neither the first visible row's chunk nor the last's.
    stubVirtualizerLayout(1600, 32_000);
    act(() => {
      useMultiHexStore.setState({
        retryChunksInRange,
        getChunkErrorsInRange: realGetChunkErrorsInRange,
        // Seeded so the REAL `getChunkErrorsInRange` does the walk — this is a
        // test of that walk, not of a stub. The key shape is `cacheKeyFor`'s:
        // `identity|chunkOffset`.
        identity: "seeded",
        chunkErrors: new Map([
          [
            `seeded|${2 * CHUNK_SIZE}`,
            { message: "middle chunk failed", attempts: 0, nextRetryAt: 0 },
          ],
        ]),
      });
    });

    render(<MultiHexViewer />);

    // The window really does reach past the failing chunk on both sides.
    const lastRow = rows[rows.length - 1].rowOffset;
    expect(lastRow).toBeGreaterThan(2 * CHUNK_SIZE + CHUNK_SIZE);

    const banner = screen.getByTestId("multi-hex-window-error");
    expect(banner).toHaveTextContent("middle chunk failed");

    fireEvent.click(screen.getByTestId("multi-hex-window-retry"));
    const [start, end] = retryChunksInRange.mock.calls[0] as [number, number];
    expect(start).toBeLessThanOrEqual(2 * CHUNK_SIZE);
    expect(end).toBeGreaterThanOrEqual(2 * CHUNK_SIZE + BYTES_PER_ROW);
  });

  it("asks about every byte in the window, not just the two end rows", () => {
    seed(2);
    const getChunkErrorsInRange = vi.fn(() => []);
    stubVirtualizerLayout(1600, 32_000);
    act(() => {
      useMultiHexStore.setState({ getChunkErrorsInRange });
    });

    render(<MultiHexViewer />);

    const firstRow = rows[0].rowOffset;
    const lastRow = rows[rows.length - 1].rowOffset;
    const [start, end] = getChunkErrorsInRange.mock.calls[0] as unknown as [number, number];
    expect(start).toBe(firstRow);
    // Inclusive of the LAST byte of the last row, so that row's chunk counts.
    expect(end).toBe(lastRow + BYTES_PER_ROW - 1);
  });

  it("shows no banner when nothing failed", () => {
    seed(2);
    act(() => {
      useMultiHexStore.setState({ getChunkErrorsInRange: () => [] });
    });
    render(<MultiHexViewer />);
    expect(screen.queryByTestId("multi-hex-window-error")).toBeNull();
    expect(screen.queryByTestId("multi-hex-window-retry")).toBeNull();
  });
});

describe("MultiHexViewer consensus fence", () => {
  /**
   * Side-by-side had NO consensus guard at all: with none in the store the
   * aligned-window request falls back to `dump_paths`, and because `classify`
   * defaults to true the server re-derives the entire consensus for every
   * 8 KiB chunk the analyst scrolls past. Sending `classify: false` instead is
   * not the fix — that takes the raw-file-offset path, where an `.msl` peer
   * read lands on a block header and returns plausible bytes from the wrong
   * address, which is the exact failure the endpoint exists to prevent.
   */
  it("offers to run a consensus instead of rendering panes without one", () => {
    seed(3, MODULE_ALIGNMENT, null);
    render(<MultiHexViewer />);

    expect(screen.getByTestId("hex-overlay-no-consensus")).toBeInTheDocument();
    expect(screen.getByTestId("hex-overlay-run-consensus")).toBeInTheDocument();
    expect(screen.queryByTestId("multi-hex-viewer")).not.toBeInTheDocument();
    expect(rows).toHaveLength(0);
  });

  it("issues no aligned-window request while there is no consensus", () => {
    seed(3, MODULE_ALIGNMENT, null);
    const ensureLoaded = vi.fn();
    act(() => {
      useMultiHexStore.setState({ ensureLoaded });
    });

    render(<MultiHexViewer />);

    expect(ensureLoaded).not.toHaveBeenCalled();
  });

  it("names the cause when the consensus covers other dumps", () => {
    seed(3);
    act(() => {
      useConsensusStore.setState({
        consensusId: "c1",
        builtFrom: ["/dumps/somewhere-else.msl", "/dumps/other.msl"],
      });
    });

    render(<MultiHexViewer />);

    const prompt = screen.getByTestId("hex-overlay-no-consensus");
    expect(prompt).toHaveAttribute("data-variant", "stale");
    expect(prompt).toHaveTextContent(/different set of dumps/i);
  });

  it("renders the panes once the consensus describes the selection", () => {
    const dumps = seed(3);
    act(() => {
      useConsensusStore.setState({
        consensusId: "c1",
        builtFrom: dumps.map((d) => d.path),
      });
    });

    render(<MultiHexViewer />);

    expect(screen.getByTestId("multi-hex-viewer")).toBeInTheDocument();
    expect(screen.queryByTestId("hex-overlay-no-consensus")).not.toBeInTheDocument();
  });
});
