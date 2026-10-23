import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexRow } from "@/components/hex/HexRow";
import { buildRegionIndex } from "@/components/hex/highlight-utils";
import {
  HEAP_ROLE_CODE,
  HEAP_ROLE_MIXED,
  HEAP_ROLE_NONE,
  HEAP_ROLE_UNCOVERED,
} from "@/utils/heap-roles";

/**
 * The overlay's `heap` render mode: `HexRow` paints the consensus role codes
 * (MIXED and UNCOVERED included) and none of the count-driven marks.
 */

const CURSOR = { cursorOffset: null, selectionStart: null, selectionEnd: null } as const;

function consensusRole(offset: number): number {
  if (offset < 4) return HEAP_ROLE_CODE.chunk_header;
  if (offset < 8) return HEAP_ROLE_MIXED;
  if (offset < 12) return HEAP_ROLE_UNCOVERED;
  return HEAP_ROLE_NONE;
}

function renderRow(extra: Partial<React.ComponentProps<typeof HexRow>> = {}) {
  return render(
    <HexRow
      rowOffset={0}
      getByteAt={(o) => o}
      {...CURSOR}
      regionIndex={buildRegionIndex([])}
      overlayEnabled
      getClassificationAt={() => 0}
      getDiffersAt={() => true}
      getVariantsAt={() => 3}
      renderMode="heap"
      getHeapCellAt={consensusRole}
      {...extra}
    />,
  );
}

function cell(container: HTMLElement, offset: number): HTMLElement {
  return container.querySelector(`[data-col="hex"][data-offset="${offset}"]`) as HTMLElement;
}

describe("HexRow overlay heap mode", () => {
  it("paints the consensus role classes, MIXED with its own class", () => {
    const { container } = renderRow();
    expect(cell(container, 1)).toHaveClass("heap-header");
    expect(cell(container, 5)).toHaveClass("heap-mixed");
    expect(cell(container, 5)).toHaveAttribute("title", "Mixed (dumps disagree)");
  });

  it("paints nothing for uncovered bytes but names them on hover", () => {
    const { container } = renderRow();
    expect(cell(container, 9).className).not.toMatch(/heap-/);
    expect(cell(container, 9)).toHaveAttribute("title", "Not covered");
    expect(cell(container, 13).className).not.toMatch(/heap-/);
  });

  it("drops the consensus class, the ring and the variant ramp", () => {
    const { container } = renderRow();
    const classes = cell(container, 1).className;
    expect(classes).not.toMatch(/consensus-/);
    expect(classes).not.toMatch(/cross-dump-differs/);
    expect(classes).not.toMatch(/variant-\d/);
  });

  it("solo overrides heap mode like every other mode", () => {
    const { container } = renderRow({ soloUnderline: true, getHeapCellAt: undefined });
    expect(cell(container, 1).className).not.toMatch(/heap-/);
  });
});
