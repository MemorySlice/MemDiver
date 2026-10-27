import { describe, it, expect, beforeEach, vi } from "vitest";
import { render } from "@testing-library/react";
import "@/i18n";

const seenSelections: string[][] = [];
vi.mock("@/components/hex/HexOverlayPane", async () => {
  const { useDumpStore } = await import("@/stores/dump-store");
  return {
    HexOverlayPane: () => {
      seenSelections.push([...useDumpStore.getState().selectedDumpIds]);
      return <div data-testid="pane" />;
    },
  };
});

import { PairAlignedOverlay } from "@/components/layout/Workspace";
import { useDumpStore } from "@/stores/dump-store";

function dump(id: string) {
  return { id, path: `/d/${id}.msl`, format: "msl", fileSize: 10, name: id };
}

describe("PairAlignedOverlay", () => {
  beforeEach(() => {
    seenSelections.length = 0;
    useDumpStore.setState({
      dumps: ["a", "b", "c"].map(dump) as never,
      selectedDumpIds: ["a", "b", "c"],
      activeDumpId: "c",
      mainView: "sideBySide",
    });
  });

  it("applies the pair, never paints the pane with the old selection", () => {
    render(<PairAlignedOverlay ids={["a", "b"]} />);
    expect(seenSelections.length).toBeGreaterThan(0);
    for (const sel of seenSelections) expect(sel).toEqual(["a", "b"]);
    expect(useDumpStore.getState().mainView).toBe("overlay");
  });

  it("restores selection, active dump and mainView on unmount", () => {
    const { unmount } = render(<PairAlignedOverlay ids={["a", "b"]} />);
    unmount();
    const s = useDumpStore.getState();
    expect(s.selectedDumpIds).toEqual(["a", "b", "c"]);
    expect(s.activeDumpId).toBe("c");
    expect(s.mainView).toBe("sideBySide");
  });
});
