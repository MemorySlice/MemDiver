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

const { HexOverlayPane } = await import("@/components/hex/HexOverlayPane");

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

const ALIGNED: AlignedWindowAlignment = {
  method: "virtual_address",
  bytes_compared: 8192,
  bytes_discarded: 0,
  sizes_differed: false,
  n_sources: 2,
  warnings: [],
};

interface Overrides {
  consensusId?: string | null;
  alignment?: AlignedWindowAlignment;
  classAt?: (offset: number) => number | undefined;
  differsAt?: (offset: number) => boolean;
  presentAt?: (path: string, offset: number) => boolean;
}

function seed({
  consensusId = "c1",
  alignment = ALIGNED,
  classAt = () => undefined,
  differsAt = () => false,
  presentAt = () => true,
}: Overrides = {}) {
  const dumps = [entry(0), entry(1), entry(2)];
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
      windowStartRow: 0,
    });
    useConsensusStore.setState({ consensusId });
    useMultiHexStore.setState({
      alignment,
      truncated: false,
      ensureLoaded: () => {},
      isPresentAt: presentAt,
      getByteAt: (_path: string, offset: number) => offset % 256,
      getClassAt: classAt,
      differsAt,
    });
  });
  return dumps;
}

/** The hex cell for an absolute offset anywhere in the rendered window. */
function hexCell(container: HTMLElement, offset: number): HTMLElement {
  const el = container.querySelector(`[data-col="hex"][data-offset="${offset}"]`);
  if (!el) throw new Error(`no hex cell at offset ${offset}`);
  return el as HTMLElement;
}

beforeEach(() => {
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

describe("HexOverlayPane cross-dump ring", () => {
  it("applies cross-dump-differs exactly where differsAt is true", () => {
    seed({ differsAt: (offset) => offset % 16 === 5 });
    const { container } = render(<HexOverlayPane />);

    for (let offset = 0; offset < 32; offset++) {
      expect(hexCell(container, offset).classList.contains("cross-dump-differs")).toBe(
        offset % 16 === 5,
      );
    }
  });

  it("leaves every byte unmarked when nothing differs", () => {
    seed({ differsAt: () => false });
    const { container } = render(<HexOverlayPane />);

    // Scoped to the byte grid: the legend swatch carries the same class on
    // purpose, so an unscoped query would never be able to fail.
    expect(
      container.querySelectorAll("[data-col] .cross-dump-differs, [data-col].cross-dump-differs"),
    ).toHaveLength(0);
  });
});

describe("HexOverlayPane consensus classes", () => {
  /**
   * The SAME `consensus-*` classes the single view uses. A second palette for
   * the same four meanings would make the legend a per-view detail the analyst
   * has to re-learn every time the layout changes.
   */
  it("paints the four classes from the aligned window", () => {
    seed({ classAt: (offset) => offset % 4 });
    const { container } = render(<HexOverlayPane />);

    expect(hexCell(container, 0)).toHaveClass("consensus-invariant");
    expect(hexCell(container, 1)).toHaveClass("consensus-structural");
    expect(hexCell(container, 2)).toHaveClass("consensus-pointer");
    expect(hexCell(container, 3)).toHaveClass("consensus-key-candidate");
  });

  it("leaves an unclassified byte unstyled rather than guessing invariant", () => {
    seed({ classAt: () => undefined });
    const { container } = render(<HexOverlayPane />);

    expect(hexCell(container, 0)).not.toHaveClass("consensus-invariant");
  });

  it("composes the class and the ring on the same byte", () => {
    seed({ classAt: () => 3, differsAt: (offset) => offset === 7 });
    const { container } = render(<HexOverlayPane />);

    const cell = hexCell(container, 7);
    expect(cell).toHaveClass("consensus-key-candidate");
    expect(cell).toHaveClass("cross-dump-differs");
  });
});

describe("HexOverlayPane presence", () => {
  /**
   * `getByteAt` returns the stored `0` for a byte no dump holds, so a pane that
   * skipped `isPresentAt` would confidently render `00` over a hole in the
   * address space.
   */
  it("renders an absent byte as a placeholder, not as 00", () => {
    seed({ presentAt: (_path, offset) => offset !== 4 });
    const { container } = render(<HexOverlayPane />);

    expect(hexCell(container, 4)).toHaveTextContent("--");
    expect(hexCell(container, 5)).not.toHaveTextContent("--");
  });
});

describe("HexOverlayPane empty states", () => {
  /**
   * Without a consensus every byte is unclassified, so a plain hex dump would
   * silently read as "nothing varies here" — the most misleading thing this
   * pane could show. An empty state carrying the action is the alternative.
   */
  it("offers to run a consensus instead of rendering a blank pane", () => {
    seed({ consensusId: null });
    const { container } = render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-no-consensus")).toBeInTheDocument();
    expect(screen.getByTestId("hex-overlay-run-consensus")).toBeInTheDocument();
    expect(container.querySelectorAll("[data-col='hex']")).toHaveLength(0);
  });

  it("runs the consensus over the selected dumps when asked", () => {
    const dumps = seed({ consensusId: null });
    const runConsensus = vi.fn(() => Promise.resolve());
    act(() => {
      useConsensusStore.setState({ runConsensus });
    });
    render(<HexOverlayPane />);

    screen.getByTestId("hex-overlay-run-consensus").click();

    expect(runConsensus).toHaveBeenCalledWith(
      dumps.map((d) => d.path),
      false,
    );
  });

  it("names the ASLR fix when the consensus is in raw file offsets", () => {
    seed({
      alignment: {
        method: "file_offset",
        bytes_compared: 1024,
        bytes_discarded: 0,
        sizes_differed: false,
        n_sources: 3,
        warnings: [],
      },
    });
    render(<HexOverlayPane />);

    const banner = screen.getByTestId("hex-overlay-raw-offset");
    expect(banner).toHaveTextContent(/ASLR normalization/i);
    expect(screen.getByTestId("hex-overlay-enable-aslr")).toBeInTheDocument();
  });

  it("keeps the bytes visible under the raw-offset banner", () => {
    seed({
      alignment: {
        method: "file_offset",
        bytes_compared: 1024,
        bytes_discarded: 0,
        sizes_differed: false,
        n_sources: 3,
        warnings: [],
      },
    });
    const { container } = render(<HexOverlayPane />);

    expect(container.querySelectorAll("[data-col='hex']").length).toBeGreaterThan(0);
  });

  it("re-runs with normalization on when the ASLR action is used", () => {
    const dumps = seed({
      alignment: {
        method: "file_offset",
        bytes_compared: 1024,
        bytes_discarded: 0,
        sizes_differed: false,
        n_sources: 3,
        warnings: [],
      },
    });
    const runConsensus = vi.fn(() => Promise.resolve());
    act(() => {
      useConsensusStore.setState({ runConsensus });
    });
    render(<HexOverlayPane />);

    screen.getByTestId("hex-overlay-enable-aslr").click();

    expect(runConsensus).toHaveBeenCalledWith(
      dumps.map((d) => d.path),
      true,
    );
    expect(useDumpStore.getState().aslrNormalize).toBe(true);
  });
});

describe("HexOverlayPane legend", () => {
  it("reuses the N-dump overlay's existing strings", () => {
    seed();
    render(<HexOverlayPane />);

    const legend = screen.getByTestId("hex-overlay-legend");
    for (const label of ["Invariant", "Structural", "Pointer", "Key Candidate", "Differs"]) {
      expect(legend).toHaveTextContent(label);
    }
  });

  it("names the anchor so one byte stream is never mistaken for all of them", () => {
    const dumps = seed();
    render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-legend")).toHaveTextContent(dumps[0].name);
  });
});
