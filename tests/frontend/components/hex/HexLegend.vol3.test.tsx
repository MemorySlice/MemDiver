import { beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexLegend } from "@/components/hex/HexLegend";
import { useHexStore, type HighlightRegion } from "@/stores/hex-store";

const region = (kind: string): HighlightRegion => ({
  offset: 0, length: 4, type: "pattern", label: "x", kind,
});

beforeEach(() => useHexStore.setState({ dumpPath: "/d.msl", highlightedRegions: [] }));

describe("HexLegend vol3 kinds", () => {
  it("labels vol3 rows by plugin, not as Pattern Match", () => {
    useHexStore.setState({
      highlightedRegions: [region("vol3:linux.pslist.PsList"), region("vol3:linux.pslist.PsList"), region("vol3:query")],
    });
    render(<HexLegend />);
    expect(screen.getByText("Vol3 rows: linux.pslist.PsList")).toBeInTheDocument();
    expect(screen.getByText("Vol3 query rows")).toBeInTheDocument();
    expect(screen.queryByText("Pattern Match")).toBeNull();
    expect(screen.getAllByTestId("hex-legend-vol3")).toHaveLength(2);
  });

  it("still counts plain pattern regions as Pattern Match", () => {
    useHexStore.setState({ highlightedRegions: [{ offset: 0, length: 1, type: "pattern", label: "p" }] });
    render(<HexLegend />);
    expect(screen.getByText("Pattern Match")).toBeInTheDocument();
  });
});
