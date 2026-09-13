import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { useDumpRailStore } from "@/stores/dump-rail-store";
import { useOverlayRenderStore } from "@/stores/overlay-render-store";
import type { AlignedWindowAlignment } from "@/api/aligned-window";
import { stubVirtualizerLayout } from "@tests/helpers/virtualizer";
import { CHUNK_SIZE } from "@/components/hex/multi-window-utils";
import { BYTES_PER_ROW } from "@/components/hex/window-utils";

// PARTIAL: only the network calls are stubbed. `@/api/client` also exports
// `readableFailure`, which the stores under this tree import for real, and a
// whole-module factory would leave it undefined the moment a fetch rejects.
vi.mock("@/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/client")>()),
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
  /** The dumps the consensus was built over; `[]` means "cannot say". */
  builtFrom?: string[];
  alignment?: AlignedWindowAlignment;
  classAt?: (offset: number) => number | undefined;
  differsAt?: (offset: number) => boolean;
  presentAt?: (path: string, offset: number) => boolean;
  variantsAt?: (offset: number) => number | undefined;
  /**
   * Per-dump bytes. The default hands EVERY dump the same value, so the
   * weighted plurality over them is that value and every test written before
   * the rail existed still describes the same grid.
   */
  byteAt?: (path: string, offset: number) => number;
}

function seed({
  consensusId = "c1",
  builtFrom = [],
  alignment = ALIGNED,
  classAt = () => undefined,
  differsAt = () => false,
  presentAt = () => true,
  variantsAt = () => undefined,
  byteAt = (_path: string, offset: number) => offset % 256,
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
    useConsensusStore.setState({ consensusId, builtFrom });
    useMultiHexStore.setState({
      alignment,
      truncated: false,
      ensureLoaded: () => {},
      isPresentAt: presentAt,
      getByteAt: byteAt,
      // `absenceAt` is derived from the same predicate as `isPresentAt` so the
      // pane cannot be seeded into the one state the real store never
      // produces: a cell with no byte and no reason for it.
      absenceAt: (path: string, offset: number) =>
        presentAt(path, offset) ? null : "not-in-dump",
      getClassAt: classAt,
      differsAt,
      variantsAt,
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
    useDumpRailStore.getState().reset();
    useMultiHexStore.getState().reset();
    useConsensusStore.getState().reset();
    useOverlayRenderStore.getState().reset();
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

  /**
   * "--" is now the start of the answer, not all of it: the cell also says
   * WHICH absence this is, so a byte this dump never held cannot be read as a
   * window that simply has not loaded.
   */
  it("names the cause of the absence on the cell itself", () => {
    seed({ presentAt: (_path, offset) => offset !== 4 });
    const { container } = render(<HexOverlayPane />);

    const cell = hexCell(container, 4);
    expect(cell).toHaveClass("byte-absent");
    expect(cell).toHaveAttribute("title", expect.stringMatching(/not in this dump/i));
    expect(hexCell(container, 5)).not.toHaveClass("byte-absent");
  });
});

describe("HexOverlayPane window-error banner", () => {
  /**
   * The overlay carried a verbatim copy of the side-by-side banner, and both
   * copies asked the store about the FIRST and LAST visible row's chunk only.
   * A chunk failing between them raised nothing at all: a band of `--` with no
   * way to retry it. Both now go through `useVisibleWindowError`, which asks
   * about the whole window — which is what this pins, because a range that
   * covers every visible byte cannot miss a middle chunk.
   */
  it("asks about every byte in the window, not just the two end rows", () => {
    const getChunkErrorsInRange = vi.fn(() => []);
    seed();
    act(() => {
      useMultiHexStore.setState({ getChunkErrorsInRange });
    });

    const { container } = render(<HexOverlayPane />);

    const offsets = [...container.querySelectorAll("[data-col='hex']")].map((el) =>
      Number(el.getAttribute("data-offset")),
    );
    const firstByte = Math.min(...offsets);
    const lastByte = Math.max(...offsets);
    const [start, end] = getChunkErrorsInRange.mock.calls[0] as unknown as [number, number];
    expect(start).toBeLessThanOrEqual(firstByte);
    expect(end).toBeGreaterThanOrEqual(lastByte);
    // Inclusive of the last row's last byte, so that row's chunk is covered.
    expect(end % BYTES_PER_ROW).toBe(BYTES_PER_ROW - 1);
  });

  it("names a failed chunk and retries the whole visible range", () => {
    const retryChunksInRange = vi.fn();
    seed();
    act(() => {
      useMultiHexStore.setState({
        retryChunksInRange,
        getChunkErrorsInRange: () => [
          { offset: CHUNK_SIZE, message: "Internal Server Error" },
        ],
      });
    });

    render(<HexOverlayPane />);

    const banner = screen.getByTestId("hex-overlay-window-error");
    // The sentence resolves through i18n; only the cause is verbatim.
    expect(banner).toHaveTextContent("Internal Server Error");

    fireEvent.click(screen.getByTestId("hex-overlay-window-retry"));
    expect(retryChunksInRange).toHaveBeenCalled();
  });

  it("shows no banner when nothing in view failed", () => {
    seed();
    act(() => {
      useMultiHexStore.setState({ getChunkErrorsInRange: () => [] });
    });

    render(<HexOverlayPane />);

    expect(screen.queryByTestId("hex-overlay-window-error")).toBeNull();
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

  /**
   * A consensus built over ANOTHER set of dumps is not a weaker answer to this
   * question, it is an answer to a different one: the classes were computed
   * over other bytes, the gaps mark other holes, and the "Differs" rings report
   * differences between dumps nobody is looking at. So it is fenced off exactly
   * like "no consensus" — but with copy that names the cause, because "run a
   * consensus" is confusing advice for someone who already ran one.
   */
  it("refuses a consensus built over a different set of dumps", () => {
    seed({ consensusId: "c1", builtFrom: ["/dumps/x.msl", "/dumps/y.msl"] });
    const { container } = render(<HexOverlayPane />);

    const prompt = screen.getByTestId("hex-overlay-no-consensus");
    expect(prompt).toHaveAttribute("data-variant", "stale");
    expect(prompt).toHaveTextContent(/different set of dumps/i);
    expect(container.querySelectorAll("[data-col='hex']")).toHaveLength(0);
  });

  it("keeps the missing-consensus copy when nothing was ever built", () => {
    seed({ consensusId: null });
    render(<HexOverlayPane />);

    const prompt = screen.getByTestId("hex-overlay-no-consensus");
    expect(prompt).toHaveAttribute("data-variant", "missing");
    expect(prompt).toHaveTextContent(/No consensus for this selection/i);
  });

  it("re-runs a stale consensus over the CURRENT selection", () => {
    const dumps = seed({
      consensusId: "c1",
      builtFrom: ["/dumps/x.msl", "/dumps/y.msl"],
    });
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

  it("renders the bytes when the consensus does describe the selection", () => {
    const dumps = [entry(0), entry(1), entry(2)];
    seed({ consensusId: "c1", builtFrom: dumps.map((d) => d.path) });
    const { container } = render(<HexOverlayPane />);

    expect(screen.queryByTestId("hex-overlay-no-consensus")).not.toBeInTheDocument();
    expect(container.querySelectorAll("[data-col='hex']").length).toBeGreaterThan(0);
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
  /**
   * Asserting five labels EXIST is what let a compound-selector bug through
   * unnoticed: a legend swatch whose class the stylesheet does not target is
   * text on a blank square, and `toHaveTextContent` is perfectly happy with
   * that. So each entry is checked as the thing it now is — a real `<button>`
   * carrying a `.md-variance-swatch` with the exact modifier `hex.css` styles.
   */
  it("reuses the N-dump overlay's strings, on buttons the stylesheet paints", () => {
    seed();
    render(<HexOverlayPane />);

    const legend = screen.getByTestId("hex-overlay-legend");
    const expected: [string, string, string][] = [
      ["invariant", "Invariant", "variance-invariant"],
      ["structural", "Structural", "variance-structural"],
      ["pointer", "Pointer", "variance-pointer"],
      ["key_candidate", "Key Candidate", "variance-key-candidate"],
      ["differs", "Differs", "variance-differs"],
      // The sixth chip: the NON-INVARIANT UNION, which is the only query that
      // finds a class-mixed secret whole.
      ["non_invariant", "Changing", "variance-non-invariant"],
    ];
    for (const [category, label, swatchClass] of expected) {
      const chip = screen.getByTestId(`hex-overlay-class-chip-${category}`);
      expect(legend).toContainElement(chip);
      expect(chip.tagName).toBe("BUTTON");
      expect(chip).toHaveTextContent(label);
      // `aria-pressed`, not `aria-selected`: six independent toggles, not a
      // roving-tabindex toolbar.
      expect(chip).toHaveAttribute("aria-pressed");

      const swatch = screen.getByTestId(`hex-overlay-class-swatch-${category}`);
      expect(chip).toContainElement(swatch);
      expect(swatch).toHaveClass("md-variance-swatch");
      expect(swatch).toHaveClass(swatchClass);
    }
  });

  it("explains the colours without needing JavaScript to open it", () => {
    seed();
    render(<HexOverlayPane />);

    const explainer = screen.getByTestId("hex-overlay-colour-legend");
    expect(explainer.tagName).toBe("DETAILS");
    expect(explainer).toHaveTextContent(/deliberately dimmed/i);
  });

  it("names the anchor so one byte stream is never mistaken for all of them", () => {
    const dumps = seed();
    render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-legend")).toHaveTextContent(dumps[0].name);
  });
});

describe("HexOverlayPane render-mode switch", () => {
  /** The switch, as a screen reader meets it. */
  function modeTab(mode: "class" | "variants" | "glyph"): HTMLElement {
    return screen.getByTestId(`hex-overlay-render-mode-${mode}`);
  }

  it("offers the three modes with Class selected", () => {
    seed();
    render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-render-mode")).toBeInTheDocument();
    expect(modeTab("class")).toHaveAttribute("aria-selected", "true");
    expect(modeTab("variants")).toHaveAttribute("aria-selected", "false");
    expect(modeTab("glyph")).toHaveAttribute("aria-selected", "false");
  });

  it("repaints the grid in the distinct-value ramp when Variants is chosen", () => {
    seed({ classAt: () => 3, variantsAt: () => 4 });
    const { container } = render(<HexOverlayPane />);

    // Class mode first: the consensus band, no ramp.
    expect(hexCell(container, 0)).toHaveClass("consensus-key-candidate");
    expect(hexCell(container, 0)).not.toHaveClass("variant-3");

    fireEvent.click(modeTab("variants"));

    expect(modeTab("variants")).toHaveAttribute("aria-selected", "true");
    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("variant-3");
    expect(cell).not.toHaveClass("consensus-key-candidate");
  });

  it("prints colour-free marks when Glyph is chosen", () => {
    seed({ variantsAt: (offset) => (offset === 2 ? 3 : 1) });
    const { container } = render(<HexOverlayPane />);

    fireEvent.click(modeTab("glyph"));

    expect(hexCell(container, 0)).toHaveTextContent("■");
    expect(hexCell(container, 2)).toHaveTextContent("3");
  });

  /**
   * All three modes describe a relationship BETWEEN dumps, so with one source
   * left they are the same picture — but the control stays in the DOM. A
   * control that vanishes takes its discoverability with it AND shifts every
   * neighbour in the toolbar sideways the moment a selection changes.
   */
  it("dims but keeps the switch when the alignment compared one source", () => {
    seed({ alignment: { ...ALIGNED, n_sources: 1 } });
    render(<HexOverlayPane />);

    const group = screen.getByTestId("hex-overlay-render-mode");
    expect(group).toBeInTheDocument();
    expect(group).toHaveAttribute("data-enabled", "false");
    for (const mode of ["class", "variants", "glyph"] as const) {
      expect(modeTab(mode)).toBeDisabled();
      expect(modeTab(mode)).toHaveAttribute("aria-disabled", "true");
    }
  });

  it("leaves the switch usable when the alignment compared two or more", () => {
    seed({ alignment: { ...ALIGNED, n_sources: 2 } });
    render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-render-mode")).toHaveAttribute(
      "data-enabled",
      "true",
    );
    expect(modeTab("variants")).not.toBeDisabled();
  });
});

describe("HexOverlayPane legend follows the mode", () => {
  /**
   * The legend is the contract for what is CURRENTLY on screen. Showing all
   * three vocabularies at once would be the same mistake the switch exists to
   * avoid: three readings competing for one grid.
   */
  it("shows the class bands in Class mode and nothing else", () => {
    seed();
    render(<HexOverlayPane />);

    const legend = screen.getByTestId("hex-overlay-legend");
    expect(legend).toHaveTextContent("Key Candidate");
    expect(screen.queryByTestId("hex-overlay-legend-ramp")).toBeNull();
    expect(screen.queryByTestId("hex-overlay-legend-glyphs")).toBeNull();
  });

  it("swaps in the ramp with its end labels in Variants mode", () => {
    seed();
    render(<HexOverlayPane />);

    fireEvent.click(screen.getByTestId("hex-overlay-render-mode-variants"));

    const legend = screen.getByTestId("hex-overlay-legend");
    expect(legend).toHaveTextContent("identical");
    expect(legend).toHaveTextContent("6 variants");
    expect(legend).toHaveTextContent("void");
    expect(legend).not.toHaveTextContent("Key Candidate");
    // Five steps, so the strip cannot silently lose one.
    for (const step of [1, 2, 3, 4, 5]) {
      expect(screen.getByTestId(`hex-overlay-legend-variant-${step}`)).toBeInTheDocument();
    }
    expect(screen.getByTestId("hex-overlay-legend-void")).toBeInTheDocument();
  });

  it("swaps in the three marks in Glyph mode", () => {
    seed();
    render(<HexOverlayPane />);

    fireEvent.click(screen.getByTestId("hex-overlay-render-mode-glyph"));

    const glyphs = screen.getByTestId("hex-overlay-legend-glyphs");
    expect(glyphs).toHaveTextContent("■");
    expect(glyphs).toHaveTextContent("2–6");
    expect(glyphs).toHaveTextContent("░");
    expect(screen.queryByTestId("hex-overlay-legend-ramp")).toBeNull();
  });

  it("keeps naming the anchor whatever the mode", () => {
    const dumps = seed();
    render(<HexOverlayPane />);

    fireEvent.click(screen.getByTestId("hex-overlay-render-mode-glyph"));

    expect(screen.getByTestId("hex-overlay-legend")).toHaveTextContent(dumps[0].name);
  });
});

/**
 * The byte the analyst reads, which is the substantive thing the rail changed.
 *
 * The overlay used to paint the ANCHOR's stream — a fact about which pane had
 * focus rather than about the set. It now paints a weighted plurality of the
 * included dumps, so these tests pin the three ways that can silently go wrong:
 * the majority not winning, a weight failing to move it, and an excluded dump
 * still voting.
 */
function BYTES(perDump: Record<string, number | undefined>) {
  return {
    presentAt: (path: string) => perDump[path] !== undefined,
    byteAt: (path: string) => perDump[path] ?? 0,
  };
}

describe("HexOverlayPane weighted plurality", () => {
  /**
   * The compatibility promise: untouched weights, every dump included, and
   * wherever the dumps agree the painted byte is the byte this pane always
   * painted.
   */
  it("paints the agreed byte unchanged where the dumps agree", () => {
    seed(
      BYTES({
        "/dumps/d0.msl": 0xa3,
        "/dumps/d1.msl": 0xa3,
        "/dumps/d2.msl": 0xa3,
      }),
    );
    const { container } = render(<HexOverlayPane />);

    expect(hexCell(container, 0)).toHaveTextContent("a3");
  });

  /** A 2/1 split goes to the majority, even when the ANCHOR is the minority. */
  it("paints the majority byte rather than the anchor's", () => {
    seed(
      BYTES({
        "/dumps/d0.msl": 0xaa,
        "/dumps/d1.msl": 0xbb,
        "/dumps/d2.msl": 0xbb,
      }),
    );
    const { container } = render(<HexOverlayPane />);

    expect(hexCell(container, 0)).toHaveTextContent("bb");
  });

  it("lets a heavier weight move the painted byte, live", () => {
    const dumps = seed(
      BYTES({
        "/dumps/d0.msl": 0xbb,
        "/dumps/d1.msl": 0xaa,
      }),
    );
    const { container } = render(<HexOverlayPane />);

    // Equal weights tie, and the tie-break takes the lower value.
    expect(hexCell(container, 0)).toHaveTextContent("aa");

    act(() => {
      useDumpRailStore.getState().setWeight(dumps[0].path, 1.5);
    });

    expect(hexCell(container, 0)).toHaveTextContent("bb");
  });

  it("stops counting a dump the rail has excluded", () => {
    const dumps = seed(
      BYTES({
        "/dumps/d0.msl": 0xaa,
        "/dumps/d1.msl": 0xbb,
        "/dumps/d2.msl": 0xbb,
      }),
    );
    const { container } = render(<HexOverlayPane />);
    expect(hexCell(container, 0)).toHaveTextContent("bb");

    act(() => {
      useDumpRailStore.getState().toggleIncluded(dumps[2].path);
    });

    // 0xAA and 0xBB now tie at 1.0 each, so the lower value takes it.
    expect(hexCell(container, 0)).toHaveTextContent("aa");
  });

  /**
   * The overlay reads the whole included SET, so a byte the other dumps hold
   * and the anchor does not is real data — painted, not voided.
   */
  it("paints a byte the anchor does not hold", () => {
    seed(
      BYTES({
        "/dumps/d1.msl": 0xcc,
        "/dumps/d2.msl": 0xcc,
      }),
    );
    const { container } = render(<HexOverlayPane />);

    expect(hexCell(container, 0)).toHaveTextContent("cc");
    expect(hexCell(container, 0)).not.toHaveClass("byte-absent");
  });

  it("voids a byte no included dump holds", () => {
    seed(BYTES({}));
    const { container } = render(<HexOverlayPane />);

    expect(hexCell(container, 0)).toHaveTextContent("--");
    expect(hexCell(container, 0)).toHaveClass("byte-absent");
  });
});

describe("HexOverlayPane solo", () => {
  it("paints the soloed dump's own bytes, not the plurality", () => {
    const dumps = seed(
      BYTES({
        "/dumps/d0.msl": 0xaa,
        "/dumps/d1.msl": 0xbb,
        "/dumps/d2.msl": 0xbb,
      }),
    );
    const { container } = render(<HexOverlayPane />);
    expect(hexCell(container, 0)).toHaveTextContent("bb");

    act(() => {
      useDumpRailStore.getState().setSolo(dumps[0].path);
    });

    expect(hexCell(container, 0)).toHaveTextContent("aa");
  });

  it("voids a byte the soloed dump does not hold, whoever else does", () => {
    const dumps = seed(
      BYTES({
        "/dumps/d1.msl": 0xbb,
        "/dumps/d2.msl": 0xbb,
      }),
    );
    const { container } = render(<HexOverlayPane />);

    act(() => {
      useDumpRailStore.getState().setSolo(dumps[0].path);
    });

    expect(hexCell(container, 0)).toHaveTextContent("--");
  });

  /**
   * The switch dims rather than disappears, for the same reason it does below
   * two dumps: a control that vanishes takes its discoverability with it and
   * shifts every neighbour in the row sideways.
   */
  it("dims the render-mode switch in solo without removing it", () => {
    const dumps = seed();
    render(<HexOverlayPane />);
    expect(screen.getByTestId("hex-overlay-render-mode")).toHaveAttribute(
      "data-enabled",
      "true",
    );

    act(() => {
      useDumpRailStore.getState().setSolo(dumps[1].path);
    });

    expect(screen.getByTestId("hex-overlay-render-mode")).toHaveAttribute(
      "data-enabled",
      "false",
    );
  });

  /**
   * A solo left over from a previous selection names a dump nothing on screen
   * describes, so it reads as no solo at all.
   */
  it("ignores a solo naming a dump that is no longer selected", () => {
    seed(
      BYTES({
        "/dumps/d0.msl": 0xaa,
        "/dumps/d1.msl": 0xbb,
        "/dumps/d2.msl": 0xbb,
      }),
    );
    const { container } = render(<HexOverlayPane />);

    act(() => {
      useDumpRailStore.getState().setSolo("/dumps/gone.msl");
    });

    expect(hexCell(container, 0)).toHaveTextContent("bb");
  });
});

describe("HexOverlayPane rail", () => {
  it("renders the rail beside the grid", () => {
    seed();
    const { container } = render(<HexOverlayPane />);

    expect(screen.getByTestId("dump-rail")).toBeInTheDocument();
    expect(screen.getAllByTestId(/^dump-rail-chip-/)).toHaveLength(3);
    expect(container.querySelectorAll("[data-col='hex']").length).toBeGreaterThan(0);
  });

  it("gives the grid the rail's width back when it is collapsed", () => {
    seed();
    render(<HexOverlayPane />);

    fireEvent.click(screen.getByTestId("dump-rail-collapse"));

    expect(screen.queryByTestId("dump-rail")).not.toBeInTheDocument();
    expect(screen.getByTestId("dump-rail-restore")).toBeInTheDocument();
  });
});

/**
 * `Align: delta-fit │ raw offsets` — the coordinate the overlay is built in.
 *
 * The failure this suite is really guarding is a switch that tracks
 * `dump-store.aslrNormalize` (an INTENT for the next build) instead of
 * `multi-hex-store.alignment.method` (the coordinate the bytes on screen are
 * actually in). The two disagree for the whole duration of a rebuild, and a
 * switch wired to the intent would claim the grid had already moved.
 */
describe("HexOverlayPane align switch", () => {
  /** A `file_offset` (flat) build, the raw-offsets half of the switch. */
  const FLAT: AlignedWindowAlignment = {
    method: "file_offset",
    bytes_compared: 1024,
    bytes_discarded: 0,
    sizes_differed: false,
    n_sources: 3,
    warnings: [],
  };

  /** Swaps `runConsensus` for a spy that never settles unless told to. */
  function spyConsensus(impl: () => Promise<void> = () => Promise.resolve()) {
    const runConsensus = vi.fn(impl);
    act(() => {
      useConsensusStore.setState({ runConsensus });
    });
    return runConsensus;
  }

  it("renders both options under an Align label", () => {
    seed();
    render(<HexOverlayPane />);

    const group = screen.getByTestId("hex-overlay-align-switch");
    expect(group).toHaveAttribute("role", "tablist");
    expect(screen.getByTestId("hex-overlay-align-delta-fit")).toHaveTextContent("delta-fit");
    expect(screen.getByTestId("hex-overlay-align-raw-offsets")).toHaveTextContent("raw offsets");
    // The visible label the group is named by, not a second copy of the string.
    const label = document.getElementById(group.getAttribute("aria-labelledby")!);
    expect(label).toHaveTextContent("Align");
  });

  it("selects delta-fit for a normalized build", () => {
    seed();
    render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-align-delta-fit")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByTestId("hex-overlay-align-raw-offsets")).toHaveAttribute(
      "aria-selected",
      "false",
    );
  });

  it("selects raw offsets for a flat build", () => {
    seed({ alignment: FLAT });
    render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-align-raw-offsets")).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByTestId("hex-overlay-align-delta-fit")).toHaveAttribute(
      "aria-selected",
      "false",
    );
  });

  /**
   * THE test of this control. `aslrNormalize` is on, the live window is flat:
   * the user has ASKED for a normalized build and has not got one yet. The
   * switch must report the build, not the request.
   */
  it("reflects the live build, not the aslrNormalize intent", () => {
    seed({ alignment: FLAT });
    act(() => {
      useDumpStore.setState({ aslrNormalize: true });
    });
    render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-align-raw-offsets")).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });

  it("selects neither option before the first aligned window", () => {
    seed();
    act(() => {
      useMultiHexStore.setState({ alignment: null });
    });
    render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-align-switch")).toHaveAttribute(
      "data-method",
      "pending",
    );
    for (const id of ["delta-fit", "raw-offsets"]) {
      expect(screen.getByTestId(`hex-overlay-align-${id}`)).toHaveAttribute(
        "aria-selected",
        "false",
      );
    }
  });

  it("flipping to raw offsets re-runs the consensus with normalize false", () => {
    const dumps = seed();
    const runConsensus = spyConsensus();
    render(<HexOverlayPane />);

    fireEvent.click(screen.getByTestId("hex-overlay-align-raw-offsets"));

    expect(runConsensus).toHaveBeenCalledTimes(1);
    expect(runConsensus).toHaveBeenCalledWith(
      dumps.map((d) => d.path),
      false,
    );
    // The shared intent the dump list and `HexAlignmentChip` also read.
    expect(useDumpStore.getState().aslrNormalize).toBe(false);
  });

  it("flipping to delta-fit re-runs the consensus with normalize true", () => {
    const dumps = seed({ alignment: FLAT });
    const runConsensus = spyConsensus();
    render(<HexOverlayPane />);

    fireEvent.click(screen.getByTestId("hex-overlay-align-delta-fit"));

    expect(runConsensus).toHaveBeenCalledTimes(1);
    expect(runConsensus).toHaveBeenCalledWith(
      dumps.map((d) => d.path),
      true,
    );
    expect(useDumpStore.getState().aslrNormalize).toBe(true);
  });

  it("clicking the option that is already live rebuilds nothing", () => {
    seed();
    const runConsensus = spyConsensus();
    render(<HexOverlayPane />);

    fireEvent.click(screen.getByTestId("hex-overlay-align-delta-fit"));

    expect(runConsensus).not.toHaveBeenCalled();
  });

  it("shows a running state and refuses a second build over the first", () => {
    seed();
    // Never settles: `running` stays true for the whole assertion.
    const runConsensus = spyConsensus(() => new Promise<void>(() => {}));
    render(<HexOverlayPane />);

    const raw = screen.getByTestId("hex-overlay-align-raw-offsets");
    fireEvent.click(raw);

    expect(screen.getByTestId("hex-overlay-align-running")).toBeInTheDocument();
    expect(raw).toBeDisabled();
    expect(screen.getByTestId("hex-overlay-align-delta-fit")).toBeDisabled();

    fireEvent.click(raw);
    fireEvent.click(screen.getByTestId("hex-overlay-align-delta-fit"));

    expect(runConsensus).toHaveBeenCalledTimes(1);
  });

  /**
   * The design's caution, in the UI rather than in a code comment: a flat build
   * floods the grid with variance BY CONSTRUCTION, and that flood is the
   * control condition, not a finding.
   */
  it("carries the control-condition caution only while the build is flat", () => {
    seed({ alignment: FLAT });
    const { unmount } = render(<HexOverlayPane />);

    expect(screen.getByTestId("hex-overlay-align-raw-caution")).toHaveTextContent(
      /control condition/i,
    );
    expect(screen.getByTestId("hex-overlay-align-raw-caution")).toHaveTextContent(
      /expected/i,
    );
    unmount();

    seed();
    render(<HexOverlayPane />);
    expect(screen.queryByTestId("hex-overlay-align-raw-caution")).not.toBeInTheDocument();
  });

  it("leaves the raw-offset banner and its ASLR action in place", () => {
    seed({ alignment: FLAT });
    render(<HexOverlayPane />);

    // The switch names the CONSEQUENCE; the banner names the FIX. Both.
    expect(screen.getByTestId("hex-overlay-raw-offset")).toBeInTheDocument();
    expect(screen.getByTestId("hex-overlay-enable-aslr")).toBeInTheDocument();
    expect(screen.getByTestId("hex-overlay-align-switch")).toBeInTheDocument();
  });
});
