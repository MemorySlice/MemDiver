import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexRow } from "@/components/hex/HexRow";
import { buildRegionIndex } from "@/components/hex/highlight-utils";
import type { HighlightRegion } from "@/stores/hex-store";

/**
 * The COMPONENT half of the selection-clobber fix.
 *
 * `hex-css-cascade.test.ts` proves the stylesheet answers the ring marker, but
 * it composes its own cells — so it would still pass if `HexRow` stopped
 * emitting the marker. This is the other half: that a cell which really lost
 * its ground really is marked, and that one which did not is left alone.
 *
 * The four families here are the ones the stylesheet's old `:is(...)` list left
 * out, and each is a reachable way to lose a selection on screen: a structure
 * field colour, a neighborhood tint, a consensus class and the search band.
 */

const NO_SELECTION = { cursorOffset: null, selectionStart: null, selectionEnd: null } as const;

/** Whole row selected, so every cell in it is under the pointer. */
const ROW_SELECTED = { cursorOffset: null, selectionStart: 0, selectionEnd: 15 } as const;

function byteAt(offset: number): number | undefined {
  return offset % 256;
}

function renderRow(extra: Partial<React.ComponentProps<typeof HexRow>> = {}) {
  return render(
    <HexRow
      rowOffset={0}
      getByteAt={byteAt}
      {...NO_SELECTION}
      regionIndex={buildRegionIndex([])}
      {...extra}
    />,
  );
}

function regions(...list: HighlightRegion[]) {
  return buildRegionIndex(list);
}

function hexCell(container: HTMLElement, offset: number): HTMLElement {
  const el = container.querySelector(`[data-col="hex"][data-offset="${offset}"]`);
  if (!el) throw new Error(`no hex cell at offset ${offset}`);
  return el as HTMLElement;
}

function asciiCell(container: HTMLElement, offset: number): HTMLElement {
  const el = container.querySelector(`[data-col="ascii"][data-offset="${offset}"]`);
  if (!el) throw new Error(`no ascii cell at offset ${offset}`);
  return el as HTMLElement;
}

describe("HexRow marks a selection that lost its ground", () => {
  it("rings a selected cell inside a structure field", () => {
    const { container } = renderRow({
      ...ROW_SELECTED,
      regionIndex: regions({
        offset: 0,
        length: 4,
        type: "structure",
        label: "header",
        colorIndex: 3,
      }),
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("field-color-3");
    expect(cell).toHaveClass("selection-ring");
    // The ascii column carries the identical class list, and is styled by the
    // same rules — a fix that only reached the hex column would be half a fix.
    expect(asciiCell(container, 0)).toHaveClass("selection-ring");

    // Past the region the ground is free again, so the plain band resumes.
    const outside = hexCell(container, 8);
    expect(outside).toHaveClass("selected");
    expect(outside).not.toHaveClass("selection-ring");
  });

  it("rings a selected cell inside a neighborhood region", () => {
    const { container } = renderRow({
      ...ROW_SELECTED,
      regionIndex: regions({
        offset: 0,
        length: 2,
        type: "neighborhood",
        label: "key material",
      }),
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("nb-key");
    expect(cell).toHaveClass("selection-ring");
  });

  it("rings a selected invariant cell", () => {
    const { container } = renderRow({
      ...ROW_SELECTED,
      overlayEnabled: true,
      getClassificationAt: () => 0,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("consensus-invariant");
    expect(cell).toHaveClass("selection-ring");
  });

  /**
   * The three text-only consensus classes take no ground, so a selection over
   * them keeps its fill and must NOT be ringed — the count in `markRings` is a
   * claim about backgrounds, not about classes.
   */
  it("leaves a selected key-candidate cell unringed", () => {
    const { container } = renderRow({
      ...ROW_SELECTED,
      overlayEnabled: true,
      getClassificationAt: () => 3,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("consensus-key-candidate");
    expect(cell).not.toHaveClass("selection-ring");
  });

  it("rings a selected cell the alignment says is absent", () => {
    // A void cause only paints where there is genuinely no byte, so the source
    // has to withhold offset 2 as well as the alignment declaring it absent.
    const { container } = renderRow({
      ...ROW_SELECTED,
      getByteAt: (offset) => (offset === 2 ? undefined : byteAt(offset)),
      getAbsenceAt: (offset) => (offset === 2 ? "not-in-dump" : undefined),
    });

    const cell = hexCell(container, 2);
    expect(cell).toHaveClass("byte-absent");
    expect(cell).toHaveClass("selection-ring");
  });

  it("leaves an unselected tinted cell alone", () => {
    const { container } = renderRow({
      overlayEnabled: true,
      getClassificationAt: () => 0,
    });

    expect(container.querySelectorAll(".selection-ring")).toHaveLength(0);
  });
});

describe("HexRow marks a search hit that lost its ground", () => {
  it("leaves an uncontested search hit unringed", () => {
    const { container } = renderRow({
      regionIndex: regions({ offset: 0, length: 4, type: "search", label: "needle" }),
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("highlight-search");
    expect(cell).not.toHaveClass("search-ring");
  });

  it("rings a search hit whose ground the variant ramp took", () => {
    const { container } = renderRow({
      renderMode: "variants",
      getVariantsAt: () => 3,
      regionIndex: regions({ offset: 0, length: 4, type: "search", label: "needle" }),
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("variant-2");
    expect(cell).toHaveClass("search-ring");
  });

  /**
   * The search band is itself a ground and it is declared after `.selected`, so
   * a selection dragged over a hit loses its fill with no other tint in play.
   * Both markers land; the stylesheet declares the selection rule last, which
   * is what makes the selection the mark that paints.
   */
  it("rings the selection when the search hit is its only competitor", () => {
    const { container } = renderRow({
      ...ROW_SELECTED,
      regionIndex: regions({ offset: 0, length: 4, type: "search", label: "needle" }),
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("selection-ring");
    expect(cell).not.toHaveClass("search-ring");
  });
});
