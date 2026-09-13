import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

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
function seed(n: number, alignment: AlignedWindowAlignment = MODULE_ALIGNMENT) {
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
