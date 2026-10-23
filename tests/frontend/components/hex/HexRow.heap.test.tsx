import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexRow } from "@/components/hex/HexRow";
import { buildRegionIndex } from "@/components/hex/highlight-utils";
import { HEAP_CHUNK_START_BIT, HEAP_ROLE_CODE } from "@/utils/heap-roles";

/**
 * The heap role layer in `HexRow`: one packed primitive per byte, painted only
 * where no other highlight claimed the cell.
 */

const CURSOR = { cursorOffset: null, selectionStart: null, selectionEnd: null } as const;

/** Bytes 0-15 header (chunk start at 0), 16-31 free link, rest user data. */
function heapCell(offset: number): number {
  if (offset === 0) return HEAP_ROLE_CODE.chunk_header | HEAP_CHUNK_START_BIT;
  if (offset < 8) return HEAP_ROLE_CODE.chunk_header;
  if (offset === 8) return HEAP_ROLE_CODE.free_link | HEAP_CHUNK_START_BIT;
  if (offset < 12) return HEAP_ROLE_CODE.free_link;
  if (offset === 12) return HEAP_ROLE_CODE.top;
  if (offset === 13) return HEAP_ROLE_CODE.slack;
  if (offset === 14) return HEAP_ROLE_CODE.allocator_meta;
  return HEAP_ROLE_CODE.free_data;
}

function renderRow(extra: Partial<React.ComponentProps<typeof HexRow>> = {}) {
  return render(
    <HexRow
      rowOffset={0}
      getByteAt={(o) => o}
      {...CURSOR}
      regionIndex={buildRegionIndex([])}
      getHeapCellAt={heapCell}
      {...extra}
    />,
  );
}

function cell(container: HTMLElement, offset: number, col = "hex"): HTMLElement {
  return container.querySelector(`[data-col="${col}"][data-offset="${offset}"]`) as HTMLElement;
}

describe("HexRow heap layer", () => {
  it("paints each role's class on both columns", () => {
    const { container } = renderRow();
    expect(cell(container, 1)).toHaveClass("heap-header");
    expect(cell(container, 1, "ascii")).toHaveClass("heap-header");
    expect(cell(container, 9)).toHaveClass("heap-freelink");
    expect(cell(container, 12)).toHaveClass("heap-top");
    expect(cell(container, 13)).toHaveClass("heap-slack");
    expect(cell(container, 14)).toHaveClass("heap-meta");
    expect(cell(container, 15)).toHaveClass("heap-free");
  });

  it("ticks only a chunk's first byte", () => {
    const { container } = renderRow();
    expect(cell(container, 0)).toHaveClass("heap-chunk-start");
    expect(cell(container, 8)).toHaveClass("heap-chunk-start");
    expect(cell(container, 1)).not.toHaveClass("heap-chunk-start");
  });

  it("names the role in the tooltip", () => {
    const { container } = renderRow();
    expect(cell(container, 9)).toHaveAttribute("title", "Free-list link");
  });

  it("paints user data", () => {
    const { container } = renderRow({ getHeapCellAt: () => HEAP_ROLE_CODE.user_data });
    expect(cell(container, 3)).toHaveClass("heap-user");
  });

  it("yields to an existing highlight region", () => {
    const { container } = renderRow({
      regionIndex: buildRegionIndex([{ offset: 0, length: 4, type: "search", label: "hit" }]),
    });
    expect(cell(container, 0)).toHaveClass("highlight-search");
    expect(cell(container, 0)).not.toHaveClass("heap-header");
    expect(cell(container, 0)).not.toHaveClass("heap-chunk-start");
    expect(cell(container, 4)).toHaveClass("heap-header");
  });

  it("yields to a consensus class", () => {
    const { container } = renderRow({ overlayEnabled: true, getClassificationAt: () => 0 });
    expect(cell(container, 1)).not.toHaveClass("heap-header");
  });

  it("is not asked about a cell whose byte has not loaded", () => {
    const getter = vi.fn(heapCell);
    const { container } = renderRow({
      getByteAt: (o) => (o < 4 ? undefined : o),
      getHeapCellAt: getter,
    });
    expect(cell(container, 0)).toHaveClass("hex-loading");
    expect(cell(container, 0)).not.toHaveClass("heap-header");
    expect(getter).not.toHaveBeenCalledWith(0);
  });

  it("rings a selection across a heap cell", () => {
    const { container } = renderRow({ selectionStart: 1, selectionEnd: 2 });
    expect(cell(container, 1)).toHaveClass("selected", "heap-header", "selection-ring");
  });

  it("paints nothing for role code 0 or when the layer is off", () => {
    const off = renderRow({ getHeapCellAt: undefined });
    expect(off.container.querySelector('[class*="heap-"]')).toBeNull();
    off.unmount();
    const none = renderRow({ getHeapCellAt: () => 0 });
    expect(none.container.querySelector('[class*="heap-"]')).toBeNull();
  });
});
