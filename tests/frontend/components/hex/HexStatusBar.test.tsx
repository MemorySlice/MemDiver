import { afterEach, describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useDumpRailStore } from "@/stores/dump-rail-store";
import { useDumpStore, type DumpEntry, type MainView } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const { HexStatusBar } = await import("@/components/hex/HexStatusBar");

/**
 * Since the overlay stopped painting the anchor's bytes, this bar is the only
 * thing on screen that says WHOSE bytes are being read. A grid showing a
 * computed plurality and one showing a single dump's real bytes look
 * identical — same hex, same classes, same ring — so a missing or wrong layer
 * line is a forensics failure, not a cosmetic one.
 */

const CURSOR = 0x40;

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

interface Seed {
  mainView?: MainView;
  cursorOffset?: number | null;
  /** Per-path byte at the cursor; `undefined` means the dump lacks it. */
  bytes?: Record<string, number | undefined>;
}

function seed({ mainView = "overlay", cursorOffset = CURSOR, bytes = {} }: Seed = {}) {
  const dumps = [entry(0), entry(1), entry(2)];
  act(() => {
    useDumpStore.setState({
      dumps,
      selectedDumpIds: dumps.map((d) => d.id),
      activeDumpId: dumps[0].id,
      originDumpId: dumps[0].id,
      visibleDumps: new Set<string>(),
      mainView,
    });
    useHexStore.getState().reset();
    useHexStore.setState({
      cursorOffset,
      fileSize: 64 * 1024,
      format: "msl",
      viewMode: "va",
    });
    useMultiHexStore.setState({
      ensureLoaded: () => {},
      isPresentAt: (path: string) => bytes[path] !== undefined,
      getByteAt: (path: string) => bytes[path] ?? 0,
    });
  });
  return dumps;
}

afterEach(() => {
  act(() => {
    useDumpStore.getState().clearAll();
    useDumpRailStore.getState().reset();
    useMultiHexStore.getState().reset();
    useHexStore.getState().reset();
  });
});

describe("HexStatusBar layer line", () => {
  it("names the overlay layer and how many dumps it reduces", () => {
    seed({ bytes: { "/dumps/d0.msl": 1, "/dumps/d1.msl": 1, "/dumps/d2.msl": 1 } });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-layer")).toHaveTextContent(
      /Viewing: Overlay · weighted plurality of 3/,
    );
  });

  it("drops an excluded dump from the count it names", () => {
    const dumps = seed({ bytes: { "/dumps/d0.msl": 1 } });
    act(() => {
      useDumpRailStore.getState().toggleIncluded(dumps[1].path);
    });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-layer")).toHaveTextContent(
      /weighted plurality of 2/,
    );
  });

  it("names the dump by name in solo", () => {
    const dumps = seed({ bytes: { "/dumps/d1.msl": 0xaa } });
    act(() => {
      useDumpRailStore.getState().setSolo(dumps[1].path);
    });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-layer")).toHaveTextContent(
      /Viewing: d1\.msl · solo/,
    );
  });

  /**
   * A solo left over from a previous selection names a dump that is no longer
   * on screen. It reads as no solo at all — the same way `HexOverlayPane`
   * resolves it, so the caption cannot claim a stream the grid is not painting.
   */
  it("falls back to the overlay when the soloed dump left the selection", () => {
    seed({ bytes: { "/dumps/d0.msl": 1 } });
    act(() => {
      useDumpRailStore.getState().setSolo("/dumps/gone.msl");
    });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-layer")).toHaveTextContent(/Overlay/);
  });

  /**
   * The single-dump and side-by-side viewers mount this same bar and have no
   * layer to name: every pane there is one dump's own bytes, said by the pane
   * header. A layer line there would invent a reading nobody is looking at.
   */
  it("says nothing about layers outside the aligned overlay", () => {
    seed({ mainView: "single" });
    render(<HexStatusBar />);

    expect(screen.queryByTestId("hex-status-layer")).not.toBeInTheDocument();
    expect(screen.queryByTestId("hex-status-agreement")).not.toBeInTheDocument();
  });

  it("names the layer even with no cursor anywhere", () => {
    seed({ cursorOffset: null });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-layer")).toBeInTheDocument();
    expect(screen.queryByTestId("hex-status-agreement")).not.toBeInTheDocument();
  });
});

describe("HexStatusBar agreement", () => {
  it("reports full agreement when every dump holds the same byte", () => {
    seed({
      bytes: { "/dumps/d0.msl": 0xa3, "/dumps/d1.msl": 0xa3, "/dumps/d2.msl": 0xa3 },
    });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-agreement")).toHaveTextContent("Agreement: 3/3");
  });

  it("reports the majority share when the dumps disagree", () => {
    seed({
      bytes: { "/dumps/d0.msl": 0xaa, "/dumps/d1.msl": 0xbb, "/dumps/d2.msl": 0xbb },
    });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-agreement")).toHaveTextContent("Agreement: 2/3");
  });

  /**
   * `N` counts the dumps PRESENT at the cursor, not the ones included: an
   * absent dump agrees with nothing and disagrees with nothing, so counting it
   * in the denominator would report permanent disagreement over every hole.
   */
  it("counts only the dumps actually present at the cursor", () => {
    seed({ bytes: { "/dumps/d0.msl": 0xa3, "/dumps/d1.msl": 0xa3 } });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-agreement")).toHaveTextContent("Agreement: 2/2");
  });

  it("says n/a rather than 0/0 where nothing is present", () => {
    seed({ bytes: {} });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-agreement")).toHaveTextContent(
      "Agreement: n/a (void)",
    );
  });

  /**
   * The agreement describes the SET, so it is still the answer in solo: "this
   * is what dump 1 holds, and 2 of the 3 dumps agree with it" is exactly the
   * reading the solo view exists to support.
   */
  it("still reports the set's agreement while one dump is soloed", () => {
    const dumps = seed({
      bytes: { "/dumps/d0.msl": 0xaa, "/dumps/d1.msl": 0xbb, "/dumps/d2.msl": 0xbb },
    });
    act(() => {
      useDumpRailStore.getState().setSolo(dumps[0].path);
    });
    render(<HexStatusBar />);

    expect(screen.getByTestId("hex-status-agreement")).toHaveTextContent("Agreement: 2/3");
  });
});

describe("HexStatusBar existing fields", () => {
  /**
   * The layer and agreement fields are ADDITIVE. Losing the cursor, the byte or
   * the file summary to make room for them would trade one fact for another.
   */
  it("keeps the cursor, byte and file fields it always had", () => {
    seed({ bytes: { "/dumps/d0.msl": 0xa3 } });
    render(<HexStatusBar />);

    expect(screen.getByText(/0x00000040/)).toBeInTheDocument();
    expect(screen.getByText(/Byte:/)).toBeInTheDocument();
    expect(screen.getByText(/rows/)).toBeInTheDocument();
  });
});
