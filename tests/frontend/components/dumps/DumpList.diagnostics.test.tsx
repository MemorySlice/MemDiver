import { beforeEach, describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { CLASSIFICATION_BASIS_MIXED } from "@/api/diagnostics";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useAppStore } from "@/stores/app-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { DumpList } = await import("@/components/dumps/DumpList");

function entry(id: string): DumpEntry {
  return { id, path: `/dumps/${id}.msl`, name: `${id}.msl`, size: 4096, format: "msl", sameProcess: true };
}

beforeEach(() => {
  useDumpStore.getState().clearAll();
  const dumps = [entry("d0"), entry("d1")];
  useDumpStore.setState({
    dumps,
    selectedDumpIds: dumps.map((d) => d.id),
    activeDumpId: "d0",
    originDumpId: "d0",
    aslrNormalize: false,
  });
  useConsensusStore.setState({
    available: true,
    loading: false,
    runInFlight: false,
    error: null,
    counts: { invariant: 1 },
    diagnostics: [],
  });
  useAppStore.setState({ mode: "exploration" });
});

describe("DumpList consensus classification-basis warning", () => {
  it("shows the localized banner when the consensus reported mixed classification", () => {
    useConsensusStore.setState({
      diagnostics: [
        {
          code: CLASSIFICATION_BASIS_MIXED,
          message: "english",
          severity: "warning",
          details: { named_dumps: [0], stored_type_dumps: [1], total_dumps: 2, remedy: "" },
        },
      ],
    });
    render(<DumpList />);
    const banner = screen.getByTestId("classification-basis-warning");
    expect(banner).toHaveAttribute("data-scope", "consensus");
    expect(banner).toHaveTextContent("1 of 2 dumps are classified by mapping names");
  });

  it("shows nothing when the consensus reported no diagnostics", () => {
    render(<DumpList />);
    expect(screen.queryByTestId("classification-basis-warning")).not.toBeInTheDocument();
  });
});
