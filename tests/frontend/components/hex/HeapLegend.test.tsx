import { beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexLegend } from "@/components/hex/HexLegend";
import { useHexStore } from "@/stores/hex-store";
import { useHeapStore } from "@/stores/heap-store";

const DUMP = "/dumps/heap.msl";

beforeEach(() => {
  useHexStore.setState({ dumpPath: DUMP, highlightedRegions: [] });
  useHeapStore.setState({ dumps: {}, roleWindows: {}, roleWindowsVersion: 0 });
});

describe("HexLegend heap entries", () => {
  it("renders nothing while no highlight and no heap layer is active", () => {
    const { container } = render(<HexLegend />);
    expect(container).toBeEmptyDOMElement();
  });

  it("lists every localized heap role and the chunk-start tick when the layer is on", () => {
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    render(<HexLegend />);
    expect(screen.getByTestId("heap-legend")).toBeInTheDocument();
    for (const label of [
      "Chunk header",
      "User data",
      "Free-list link",
      "Freed data",
      "Allocator metadata",
      "Top chunk",
      "Slack",
      "Chunk start",
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it("hides the heap entries for a different dump", () => {
    useHeapStore.getState().setLayerEnabled("/other.msl", true);
    render(<HexLegend />);
    expect(screen.queryByTestId("heap-legend")).toBeNull();
  });

  it("flags a layer error", () => {
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    useHeapStore.setState((s) => ({
      dumps: { ...s.dumps, [DUMP]: { ...s.dumps[DUMP], layerError: "Loading heap roles failed: x" } },
    }));
    render(<HexLegend />);
    expect(screen.getByRole("status")).toHaveTextContent("Heap layer unavailable");
  });
});
