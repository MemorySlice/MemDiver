import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexRow } from "@/components/hex/HexRow";
import { buildRegionIndex, kindSlot, regionsForView } from "@/components/hex/highlight-utils";
import type { HighlightRegion } from "@/stores/hex-store";

function renderRow(list: HighlightRegion[]) {
  return render(
    <HexRow
      rowOffset={0}
      getByteAt={(o: number) => o % 256}
      cursorOffset={null}
      selectionStart={null}
      selectionEnd={null}
      regionIndex={buildRegionIndex(list)}
    />,
  );
}

function hexCell(container: HTMLElement, offset: number): HTMLElement {
  const el = container.querySelector(`[data-col="hex"][data-offset="${offset}"]`);
  if (!el) throw new Error(`no hex cell at offset ${offset}`);
  return el as HTMLElement;
}

describe("HexRow generic highlight kinds", () => {
  it("paints highlight-kind-<slot> inside the region only, with the label as title", () => {
    const { container } = renderRow([
      { offset: 2, length: 3, type: "pattern", label: "task_struct pid 4", kind: "vol3:task_struct" },
    ]);
    const cls = `highlight-kind-${kindSlot("vol3:task_struct")}`;
    expect(hexCell(container, 3)).toHaveClass(cls);
    expect(hexCell(container, 3)).toHaveAttribute("title", "task_struct pid 4");
    expect(hexCell(container, 3)).not.toHaveClass("highlight-pattern");
    expect(hexCell(container, 6)).not.toHaveClass(cls);
  });

  it("leaves a closed-type region on its own class", () => {
    const { container } = renderRow([{ offset: 0, length: 2, type: "search", label: "s" }]);
    expect(hexCell(container, 0)).toHaveClass("highlight-search");
  });

  it("does not paint a region that belongs to a different dump", () => {
    const regions: HighlightRegion[] = [
      { offset: 0, length: 4, type: "pattern", label: "k", kind: "key_hit", dumpPath: "/dump-a" },
    ];
    const paneB = renderRow(regionsForView(regions, "raw", ["raw"], "/dump-b"));
    expect(hexCell(paneB.container, 0).className).not.toMatch(/highlight-kind-/);
    const paneA = renderRow(regionsForView(regions, "raw", ["raw"], "/dump-a"));
    expect(hexCell(paneA.container, 0)).toHaveClass(`highlight-kind-${kindSlot("key_hit")}`);
  });
});
