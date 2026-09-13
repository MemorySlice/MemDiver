import { beforeEach, describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useDumpStore, type DumpEntry } from "@/stores/dump-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { DumpSelectionStrip } = await import("@/components/dumps/DumpSelectionStrip");

function entry(id: string): DumpEntry {
  return {
    id,
    path: `/dumps/long/path/${id}.msl`,
    name: `${id}.msl`,
    size: 4096,
    format: "msl",
    sameProcess: true,
  };
}

function seed(n: number, over: Partial<ReturnType<typeof useDumpStore.getState>> = {}) {
  const dumps = Array.from({ length: n }, (_, i) => entry(`d${i}`));
  useDumpStore.setState({
    dumps,
    selectedDumpIds: dumps.map((d) => d.id),
    activeDumpId: dumps[0]?.id ?? null,
    originDumpId: dumps[0]?.id ?? null,
    visibleDumps: new Set<string>(),
    mainView: "single",
    ...over,
  });
}

beforeEach(() => {
  useDumpStore.getState().clearAll();
});

describe("DumpSelectionStrip rendering", () => {
  it("renders one chip per loaded dump", () => {
    seed(4);
    render(<DumpSelectionStrip />);

    expect(screen.getAllByTestId("dump-chip")).toHaveLength(4);
  });

  it("renders nothing at all with no dumps loaded", () => {
    render(<DumpSelectionStrip />);
    expect(screen.queryByTestId("dump-selection-strip")).not.toBeInTheDocument();
  });

  it("keeps the full path reachable behind a truncated name", () => {
    seed(1);
    render(<DumpSelectionStrip />);

    expect(screen.getByText("d0.msl")).toHaveAttribute("title", "/dumps/long/path/d0.msl");
  });

  it("marks only the origin dump", () => {
    seed(3);
    render(<DumpSelectionStrip />);

    expect(screen.getByTestId("dump-chip-origin-d0")).toBeInTheDocument();
    expect(screen.queryByTestId("dump-chip-origin-d1")).not.toBeInTheDocument();
  });
});

describe("DumpSelectionStrip affordances are independent", () => {
  it("ticks participation without moving the focus", () => {
    seed(3);
    render(<DumpSelectionStrip />);

    fireEvent.click(screen.getByTestId("dump-chip-select-d2"));

    expect(useDumpStore.getState().selectedDumpIds).toEqual(["d0", "d1"]);
    expect(useDumpStore.getState().activeDumpId).toBe("d0");
  });

  it("moves the focus without changing an existing selection", () => {
    seed(3);
    render(<DumpSelectionStrip />);

    fireEvent.click(screen.getByTestId("dump-chip-focus-d1"));

    expect(useDumpStore.getState().activeDumpId).toBe("d1");
    expect(useDumpStore.getState().selectedDumpIds).toEqual(["d0", "d1", "d2"]);
  });

  it("reflects both states back: checked box, checked radio", () => {
    seed(2, { selectedDumpIds: ["d1"], activeDumpId: "d1" });
    render(<DumpSelectionStrip />);

    expect(screen.getByTestId("dump-chip-select-d0")).not.toBeChecked();
    expect(screen.getByTestId("dump-chip-select-d1")).toBeChecked();
    expect(screen.getByTestId("dump-chip-focus-d0")).not.toBeChecked();
    expect(screen.getByTestId("dump-chip-focus-d1")).toBeChecked();
  });

  it("focusing an unselected dump selects it", () => {
    seed(3, { selectedDumpIds: ["d0"], activeDumpId: "d0" });
    render(<DumpSelectionStrip />);

    fireEvent.click(screen.getByTestId("dump-chip-focus-d2"));

    const state = useDumpStore.getState();
    expect(state.activeDumpId).toBe("d2");
    expect(state.selectedDumpIds).toContain("d2");
  });
});
