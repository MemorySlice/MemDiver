import { beforeEach, describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useAppStore } from "@/stores/app-store";

// Only the network edge is stubbed; the store and its invariants stay real, so
// these tests fail if `reconcileSelection` ever stops enforcing I2/I3.
vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { DumpList } = await import("@/components/dumps/DumpList");

function entry(id: string, over: Partial<DumpEntry> = {}): DumpEntry {
  return {
    id,
    path: `/dumps/${id}.msl`,
    name: `${id}.msl`,
    size: 4096,
    format: "msl",
    sameProcess: true,
    ...over,
  };
}

/** `n` dumps loaded, all selected, the first one both ORIGIN and focused. */
function seed(n: number, over: Partial<ReturnType<typeof useDumpStore.getState>> = {}) {
  const dumps = Array.from({ length: n }, (_, i) => entry(`d${i}`));
  useDumpStore.setState({
    dumps,
    selectedDumpIds: dumps.map((d) => d.id),
    activeDumpId: dumps[0]?.id ?? null,
    originDumpId: dumps[0]?.id ?? null,
    visibleDumps: new Set<string>(),
    mainView: "single",
    aslrNormalize: false,
    ...over,
  });
}

beforeEach(() => {
  useDumpStore.getState().clearAll();
  useConsensusStore.setState({ available: false, loading: false, error: null, counts: null });
  useAppStore.setState({ mode: "verification" });
});

describe("DumpList participation vs focus", () => {
  it("changes the selection and NOT the focus when the checkbox is ticked", () => {
    seed(3);
    render(<DumpList />);

    fireEvent.click(screen.getByTestId("dump-select-d1"));

    expect(useDumpStore.getState().selectedDumpIds).toEqual(["d0", "d2"]);
    // The whole point of splitting the affordances: participation is not a
    // disguised focus change.
    expect(useDumpStore.getState().activeDumpId).toBe("d0");
  });

  it("moves focus when the row body is clicked", () => {
    seed(3);
    render(<DumpList />);

    fireEvent.click(screen.getByText("d2.msl"));

    expect(useDumpStore.getState().activeDumpId).toBe("d2");
  });

  it("selects an unselected dump when it is focused (the store's one-way exception)", () => {
    seed(3, { selectedDumpIds: ["d0"], activeDumpId: "d0" });
    render(<DumpList />);

    fireEvent.click(screen.getByText("d2.msl"));

    const state = useDumpStore.getState();
    expect(state.activeDumpId).toBe("d2");
    expect(state.selectedDumpIds).toContain("d2");
  });

  it("marks the focused row with aria-current and a text pill, not colour alone", () => {
    seed(2);
    render(<DumpList />);

    const rows = screen.getAllByTestId("dump-row");
    expect(rows[0]).toHaveAttribute("aria-current", "true");
    expect(rows[1]).not.toHaveAttribute("aria-current");
    expect(screen.getByTestId("dump-focus-badge-d0")).toBeInTheDocument();
    expect(screen.queryByTestId("dump-focus-badge-d1")).not.toBeInTheDocument();
  });
});

describe("DumpList ORIGIN badge", () => {
  it("marks only the session's first dump", () => {
    seed(3);
    render(<DumpList />);

    expect(screen.getByTestId("dump-origin-d0")).toBeInTheDocument();
    expect(screen.queryByTestId("dump-origin-d1")).not.toBeInTheDocument();
    expect(screen.queryByTestId("dump-origin-d2")).not.toBeInTheDocument();
    expect(screen.getAllByText("ORIGIN")).toHaveLength(1);
  });

  it("does not follow the focus", () => {
    seed(3);
    render(<DumpList />);

    fireEvent.click(screen.getByText("d2.msl"));

    expect(screen.getByTestId("dump-origin-d0")).toBeInTheDocument();
    expect(screen.queryByTestId("dump-origin-d2")).not.toBeInTheDocument();
  });
});

describe("DumpList select all / only focused", () => {
  it("restores every dump to the analysis", () => {
    seed(3, { selectedDumpIds: ["d1"], activeDumpId: "d1" });
    render(<DumpList />);

    fireEvent.click(screen.getByTestId("dump-select-all"));

    expect(useDumpStore.getState().selectedDumpIds).toEqual(["d0", "d1", "d2"]);
    expect(screen.getByTestId("dump-selection-count")).toHaveTextContent("3 of 3 selected");
  });

  /**
   * The header used to offer "Select none", wired to `clearDumpSelection`. It
   * was a dead control: store invariant I2 reads an empty `selectedDumpIds`
   * over a non-empty dump list as "all of them", so the click round-tripped
   * straight back to everything selected. "Only focused" is the honest inverse
   * of "Select all" — the narrowest selection I2/I3 actually permit. The store
   * action itself is untouched and still exported.
   */
  it("narrows the selection to exactly the focused dump, leaving the focus alone", () => {
    seed(3, { selectedDumpIds: ["d0", "d1", "d2"], activeDumpId: "d1" });
    render(<DumpList />);

    fireEvent.click(screen.getByTestId("dump-select-only-focused"));

    const state = useDumpStore.getState();
    expect(state.selectedDumpIds).toEqual(["d1"]);
    expect(state.activeDumpId).toBe("d1");
    expect(screen.getByTestId("dump-selection-count")).toHaveTextContent("1 of 3 selected");
  });

  it("is disabled when the focused dump is already the only one selected", () => {
    seed(3, { selectedDumpIds: ["d1"], activeDumpId: "d1" });
    render(<DumpList />);

    const button = screen.getByTestId("dump-select-only-focused");
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", expect.stringMatching(/already the only one/i));
  });

  it("no longer renders the dead 'Select none' control", () => {
    seed(3);
    render(<DumpList />);

    expect(screen.queryByTestId("dump-select-none")).not.toBeInTheDocument();
    // Nothing was deleted from the store — only the button is gone.
    expect(typeof useDumpStore.getState().clearDumpSelection).toBe("function");
  });

  it("reports the selected count against the loaded total", () => {
    seed(4, { selectedDumpIds: ["d0", "d3"], activeDumpId: "d0" });
    render(<DumpList />);

    expect(screen.getByTestId("dump-selection-count")).toHaveTextContent("2 of 4 selected");
  });
});

describe("DumpList consensus scope", () => {
  beforeEach(() => {
    useAppStore.setState({ mode: "exploration" });
  });

  it("names the scope in the button label", () => {
    seed(5, { selectedDumpIds: ["d0", "d1", "d2"], activeDumpId: "d0" });
    render(<DumpList />);

    expect(screen.getByTestId("dump-run-consensus")).toHaveTextContent(
      "Run consensus on 3 dumps",
    );
  });

  it("singularises the label when only one dump would take part", () => {
    seed(3, { selectedDumpIds: ["d1"], activeDumpId: "d1" });
    render(<DumpList />);

    const button = screen.getByTestId("dump-run-consensus");
    expect(button).toHaveTextContent("Run consensus on 1 dump");
    // ...and it cannot be run: a consensus over one dump is meaningless.
    expect(button).toBeDisabled();
  });

  it("runs over the SELECTED dumps, not every loaded one", () => {
    const runConsensus = vi.fn();
    useConsensusStore.setState({ runConsensus });
    seed(4, { selectedDumpIds: ["d1", "d3"], activeDumpId: "d1" });
    render(<DumpList />);

    fireEvent.click(screen.getByTestId("dump-run-consensus"));

    expect(runConsensus).toHaveBeenCalledWith(["/dumps/d1.msl", "/dumps/d3.msl"], false);
  });
});

describe("DumpList view CTAs", () => {
  it("are disabled below two selected dumps and explain why", () => {
    seed(3, { selectedDumpIds: ["d0"], activeDumpId: "d0" });
    render(<DumpList />);

    const sideBySide = screen.getByTestId("dump-view-side-by-side");
    expect(sideBySide).toBeDisabled();
    expect(sideBySide).toHaveAttribute("title", expect.stringMatching(/at least 2 dumps/i));
  });

  it("set the main view once two dumps take part", () => {
    seed(3);
    render(<DumpList />);

    fireEvent.click(screen.getByTestId("dump-view-overlay"));
    expect(useDumpStore.getState().mainView).toBe("overlay");

    fireEvent.click(screen.getByTestId("dump-view-side-by-side"));
    expect(useDumpStore.getState().mainView).toBe("sideBySide");
  });
});

/**
 * The removed control wrote `DumpEntry.sameProcess`, which nothing in the app
 * ever read, and it sat exactly where the participation checkbox belongs. The
 * store field and `toggleSameProcess` are deliberately still there (both
 * `@deprecated`); only the control is gone.
 */
describe("DumpList no longer renders the dead 'Same' checkbox", () => {
  it("has no Same label and no same-process title anywhere in the list", () => {
    seed(3);
    render(<DumpList />);

    expect(screen.queryByText("Same")).not.toBeInTheDocument();
    expect(
      screen.queryByTitle("Mark as same process for consensus"),
    ).not.toBeInTheDocument();
  });

  it("still exposes the deprecated store action, so nothing was deleted", () => {
    expect(typeof useDumpStore.getState().toggleSameProcess).toBe("function");
  });
});
