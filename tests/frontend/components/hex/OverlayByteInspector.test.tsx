import { afterEach, describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const { OverlayByteInspector } = await import("@/components/hex/OverlayByteInspector");

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

const CURSOR = 0x4a118;

interface Seed {
  n?: number;
  cursorOffset?: number | null;
  /** Per-path byte at the cursor; `undefined` means the dump lacks it. */
  bytes?: Record<string, number | undefined>;
  classAt?: number | undefined;
}

function seed({ n = 4, cursorOffset = CURSOR, bytes = {}, classAt }: Seed = {}) {
  const dumps = Array.from({ length: n }, (_, i) => entry(i));
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
    useHexStore.setState({ cursorOffset });
    useMultiHexStore.setState({
      ensureLoaded: () => {},
      // An absent byte still READS as 0 from the store, exactly as the backend
      // sends it — so a component that trusted `getByteAt` alone would print
      // "00" for it. The presence mask is the only thing separating the two.
      isPresentAt: (path: string) => bytes[path] !== undefined,
      getByteAt: (path: string) => bytes[path] ?? 0,
      getClassAt: () => classAt,
    });
  });
  return dumps;
}

afterEach(() => {
  act(() => {
    useDumpStore.getState().clearAll();
    useMultiHexStore.getState().reset();
    useHexStore.getState().reset();
  });
});

describe("OverlayByteInspector rows", () => {
  it("renders one row per selected dump", () => {
    const dumps = seed({
      n: 4,
      bytes: {
        "/dumps/d0.msl": 0x7f,
        "/dumps/d1.msl": 0xa3,
        "/dumps/d2.msl": 0xa3,
      },
    });
    render(<OverlayByteInspector />);

    for (const d of dumps) {
      expect(screen.getByTestId(`overlay-inspector-row-${d.id}`)).toBeInTheDocument();
    }
    expect(screen.getAllByTestId(/^overlay-inspector-row-/)).toHaveLength(4);
  });

  it("marks the anchor and only the anchor", () => {
    const dumps = seed({ bytes: { "/dumps/d0.msl": 0x7f } });
    render(<OverlayByteInspector />);

    expect(screen.getByTestId(`overlay-inspector-anchor-${dumps[0].id}`)).toBeInTheDocument();
    expect(
      screen.queryByTestId(`overlay-inspector-anchor-${dumps[1].id}`),
    ).not.toBeInTheDocument();
  });

  it("follows the focused dump when the anchor moves", () => {
    const dumps = seed({ bytes: { "/dumps/d1.msl": 0x11 } });
    act(() => {
      useDumpStore.getState().setActiveDump(dumps[2].id);
    });
    render(<OverlayByteInspector />);

    expect(screen.getByTestId(`overlay-inspector-anchor-${dumps[2].id}`)).toBeInTheDocument();
  });
});

describe("OverlayByteInspector absence", () => {
  /**
   * The load-bearing distinction of this whole panel: a dump that does not hold
   * the byte says so, instead of reporting the `0` the store hands back for it.
   * "00" is a claim about memory contents; absence is the opposite of one.
   */
  it("renders an absent byte as absent, never as 00", () => {
    const dumps = seed({
      bytes: {
        "/dumps/d0.msl": 0x7f,
        "/dumps/d1.msl": 0xa3,
        "/dumps/d2.msl": 0xa3,
        // d3 is absent.
      },
    });
    render(<OverlayByteInspector />);

    const absent = screen.getByTestId(`overlay-inspector-byte-${dumps[3].id}`);
    expect(absent).toHaveTextContent("--");
    expect(absent).not.toHaveTextContent("00");
    expect(screen.getByTestId(`overlay-inspector-absent-${dumps[3].id}`)).toBeInTheDocument();
    expect(screen.getByTestId(`overlay-inspector-row-${dumps[3].id}`)).toHaveAttribute(
      "data-present",
      "false",
    );
  });

  it("still shows a real 0x00 as a byte", () => {
    const dumps = seed({
      bytes: { "/dumps/d0.msl": 0x7f, "/dumps/d1.msl": 0x00 },
    });
    render(<OverlayByteInspector />);

    expect(screen.getByTestId(`overlay-inspector-byte-${dumps[1].id}`)).toHaveTextContent("00");
    expect(
      screen.queryByTestId(`overlay-inspector-absent-${dumps[1].id}`),
    ).not.toBeInTheDocument();
  });
});

describe("OverlayByteInspector summary", () => {
  it("shows the offset, the class and how many dumps disagree", () => {
    seed({
      bytes: {
        "/dumps/d0.msl": 0x7f,
        "/dumps/d1.msl": 0xa3,
        "/dumps/d2.msl": 0xa3,
      },
      classAt: 3,
    });
    render(<OverlayByteInspector />);

    const summary = screen.getByTestId("overlay-inspector-summary");
    expect(summary).toHaveTextContent("0x0004_A118");
    // Reuses NDumpOverlay's own legend string, casing included.
    expect(summary).toHaveTextContent("class: Key Candidate");
    // d1 and d2 hold a different byte; d3 holds none. All three are "not what
    // the anchor holds", which is the question the analyst asked.
    expect(screen.getByTestId("overlay-inspector-differ-count")).toHaveTextContent(
      "3 of 4 dumps differ",
    );
  });

  it("says so when every dump agrees", () => {
    seed({
      n: 3,
      bytes: {
        "/dumps/d0.msl": 0x42,
        "/dumps/d1.msl": 0x42,
        "/dumps/d2.msl": 0x42,
      },
    });
    render(<OverlayByteInspector />);

    expect(screen.getByTestId("overlay-inspector-differ-count")).toHaveTextContent(
      "all 3 dumps agree",
    );
  });

  it("marks each disagreeing row, and no agreeing one", () => {
    const dumps = seed({
      n: 3,
      bytes: {
        "/dumps/d0.msl": 0x42,
        "/dumps/d1.msl": 0x42,
        "/dumps/d2.msl": 0x99,
      },
    });
    render(<OverlayByteInspector />);

    expect(screen.getByTestId(`overlay-inspector-row-${dumps[0].id}`)).toHaveAttribute(
      "data-differs",
      "false",
    );
    expect(screen.getByTestId(`overlay-inspector-row-${dumps[1].id}`)).toHaveAttribute(
      "data-differs",
      "false",
    );
    expect(screen.getByTestId(`overlay-inspector-row-${dumps[2].id}`)).toHaveAttribute(
      "data-differs",
      "true",
    );
  });

  it("reports an unclassified byte rather than inventing a class", () => {
    seed({ bytes: { "/dumps/d0.msl": 0x01 }, classAt: undefined });
    render(<OverlayByteInspector />);

    expect(screen.getByTestId("overlay-inspector-class")).toHaveTextContent("unclassified");
  });
});

describe("OverlayByteInspector without a cursor", () => {
  it("asks for a byte instead of rendering an empty table", () => {
    seed({ cursorOffset: null });
    render(<OverlayByteInspector />);

    expect(screen.getByTestId("overlay-byte-inspector")).toHaveTextContent(/Click a byte/i);
    expect(screen.queryAllByTestId(/^overlay-inspector-row-/)).toHaveLength(0);
  });
});
