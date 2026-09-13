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

const { MainViewSwitcher } = await import("@/components/hex/MainViewSwitcher");

function entry(id: string): DumpEntry {
  return { id, path: `/dumps/${id}.msl`, name: `${id}.msl`, size: 1024, format: "msl", sameProcess: true };
}

function seed(selectedCount: number) {
  const dumps = Array.from({ length: Math.max(1, selectedCount) }, (_, i) => entry(`d${i}`));
  useDumpStore.setState({
    dumps,
    selectedDumpIds: dumps.slice(0, selectedCount).map((d) => d.id),
    activeDumpId: dumps[0].id,
    originDumpId: dumps[0].id,
    visibleDumps: new Set<string>(),
    mainView: "single",
  });
}

beforeEach(() => {
  useDumpStore.getState().clearAll();
});

describe("MainViewSwitcher below two selected dumps", () => {
  beforeEach(() => seed(1));

  /**
   * DISABLED, never hidden. A control that vanishes is undiscoverable, which is
   * half of "I loaded a second dump and the UI did not change" — a greyed-out
   * segment at least states the precondition.
   */
  it("keeps the multi-dump modes in the DOM", () => {
    render(<MainViewSwitcher />);

    expect(screen.getByTestId("main-view-sideBySide")).toBeInTheDocument();
    expect(screen.getByTestId("main-view-overlay")).toBeInTheDocument();
  });

  it("disables them and says why", () => {
    render(<MainViewSwitcher />);

    for (const id of ["main-view-sideBySide", "main-view-overlay"]) {
      const button = screen.getByTestId(id);
      expect(button).toBeDisabled();
      expect(button).toHaveAttribute("aria-disabled", "true");
      expect(button).toHaveAttribute("title", expect.stringMatching(/at least 2 dumps/i));
    }
  });

  it("leaves Single enabled and selected", () => {
    render(<MainViewSwitcher />);

    const single = screen.getByTestId("main-view-single");
    expect(single).toBeEnabled();
    expect(single).toHaveAttribute("aria-selected", "true");
  });

  it("does not change the layout when a disabled segment is clicked", () => {
    render(<MainViewSwitcher />);

    fireEvent.click(screen.getByTestId("main-view-overlay"));

    expect(useDumpStore.getState().mainView).toBe("single");
  });
});

describe("MainViewSwitcher from two selected dumps", () => {
  beforeEach(() => seed(2));

  it("enables both multi-dump modes", () => {
    render(<MainViewSwitcher />);

    expect(screen.getByTestId("main-view-sideBySide")).toBeEnabled();
    expect(screen.getByTestId("main-view-sideBySide")).not.toHaveAttribute("aria-disabled");
    expect(screen.getByTestId("main-view-overlay")).toBeEnabled();
  });

  it("names the pane count so the label is not a guess", () => {
    render(<MainViewSwitcher />);

    expect(screen.getByTestId("main-view-sideBySide")).toHaveTextContent("Side by side (2)");
  });

  it("drives mainView, and keeps aria-selected on exactly one tab", () => {
    render(<MainViewSwitcher />);

    fireEvent.click(screen.getByTestId("main-view-sideBySide"));
    expect(useDumpStore.getState().mainView).toBe("sideBySide");
    expect(screen.getByTestId("main-view-sideBySide")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("main-view-single")).toHaveAttribute("aria-selected", "false");

    fireEvent.click(screen.getByTestId("main-view-overlay"));
    expect(useDumpStore.getState().mainView).toBe("overlay");
  });

  it("exposes tablist / tab semantics", () => {
    render(<MainViewSwitcher />);

    expect(screen.getByRole("tablist", { name: "Main view layout" })).toBeInTheDocument();
    expect(screen.getAllByRole("tab")).toHaveLength(3);
  });
});
