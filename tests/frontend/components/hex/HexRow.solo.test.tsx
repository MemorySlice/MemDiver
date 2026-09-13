import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexRow } from "@/components/hex/HexRow";
import { buildRegionIndex } from "@/components/hex/highlight-utils";
import { GLYPH_VOID } from "@/utils/variant-ramp";

/**
 * The solo treatment, and the one property that makes it worth having: the byte
 * stays READABLE.
 *
 * In solo the grid is painting one dump's real bytes, so the value is the whole
 * point — it is what the analyst soloed the dump to see. The cross-dump
 * variance still matters, but spending a background on it would put a tint
 * under the very value it exists to help read, which is why the design moves it
 * to a `border-bottom`. These tests pin the swap in both directions: an
 * underline where the overlay would have filled, and NO fill anywhere.
 */

const CURSOR = { cursorOffset: null, selectionStart: null, selectionEnd: null } as const;

function byteAt(offset: number): number | undefined {
  return offset % 256;
}

function renderRow(extra: Partial<React.ComponentProps<typeof HexRow>> = {}) {
  return render(
    <HexRow
      rowOffset={0}
      getByteAt={byteAt}
      {...CURSOR}
      regionIndex={buildRegionIndex([])}
      overlayEnabled
      {...extra}
    />,
  );
}

function hexCell(container: HTMLElement, offset: number): HTMLElement {
  const el = container.querySelector(`[data-col="hex"][data-offset="${offset}"]`);
  if (!el) throw new Error(`no hex cell at offset ${offset}`);
  return el as HTMLElement;
}

/** The solo underline class on a cell, or `null` when it carries none. */
function underlineClass(cell: HTMLElement): string | null {
  return [...cell.classList].find((c) => /^variant-underline-[1-5]$/.test(c)) ?? null;
}

/** The overlay FILL class on a cell, or `null` when it carries none. */
function rampClass(cell: HTMLElement): string | null {
  return [...cell.classList].find((c) => /^variant-[1-5]$/.test(c)) ?? null;
}

describe("HexRow solo underline", () => {
  it("underlines a byte that differs across the set and keeps its value", () => {
    const { container } = renderRow({
      soloUnderline: true,
      getVariantsAt: (offset) => (offset === 3 ? 3 : 1),
    });

    const cell = hexCell(container, 3);
    expect(underlineClass(cell)).toBe("variant-underline-2");
    // The whole reason for an underline rather than a fill.
    expect(cell).toHaveTextContent("03");
  });

  /** Same ordinal rule as the fill ramp: `min(variants - 1, 5)`, 1 paints nothing. */
  it("indexes the underline ramp exactly as the fill ramp is indexed", () => {
    const counts = [0, 1, 2, 3, 4, 5, 6, 7];
    const { container } = renderRow({
      soloUnderline: true,
      getVariantsAt: (offset) => counts[offset],
    });

    expect(underlineClass(hexCell(container, 0))).toBeNull();
    expect(underlineClass(hexCell(container, 1))).toBeNull();
    expect(underlineClass(hexCell(container, 2))).toBe("variant-underline-1");
    expect(underlineClass(hexCell(container, 3))).toBe("variant-underline-2");
    expect(underlineClass(hexCell(container, 4))).toBe("variant-underline-3");
    expect(underlineClass(hexCell(container, 5))).toBe("variant-underline-4");
    expect(underlineClass(hexCell(container, 6))).toBe("variant-underline-5");
    expect(underlineClass(hexCell(container, 7))).toBe("variant-underline-5");
  });

  /**
   * One vocabulary per cell. A byte carrying both a fill and an underline would
   * say the same thing twice in two different marks — and the fill is exactly
   * the treatment solo exists to avoid.
   */
  it("never lets the fill ramp and the underline land on the same byte", () => {
    const { container } = renderRow({
      soloUnderline: true,
      renderMode: "variants",
      getVariantsAt: () => 4,
    });

    for (let offset = 0; offset < 16; offset++) {
      const cell = hexCell(container, offset);
      expect(underlineClass(cell)).toBe("variant-underline-3");
      expect(rampClass(cell)).toBeNull();
    }
  });

  /**
   * Solo overrides the render mode rather than composing with it — which is why
   * the `Class │ Variants │ Glyph` switch dims in solo. All three modes describe
   * a relationship BETWEEN dumps and there is one dump on screen.
   */
  it("keeps the consensus class off the cell in solo", () => {
    const { container } = renderRow({
      soloUnderline: true,
      renderMode: "class",
      getClassificationAt: () => 3,
      getDiffersAt: () => true,
      getVariantsAt: () => 2,
    });

    const cell = hexCell(container, 0);
    expect(cell).not.toHaveClass("consensus-key-candidate");
    expect(cell).not.toHaveClass("cross-dump-differs");
    expect(underlineClass(cell)).toBe("variant-underline-1");
  });

  it("keeps the hex value even when the render mode asks for a glyph", () => {
    const { container } = renderRow({
      soloUnderline: true,
      renderMode: "glyph",
      getVariantsAt: () => 3,
    });

    expect(hexCell(container, 5)).toHaveTextContent("05");
  });

  /**
   * The structural void rule, unchanged: a cell with no byte carries its
   * absence treatment and NOTHING else. An underline there would say "the dumps
   * differ here" about a byte no dump holds.
   */
  it("leaves a void cell free of any underline", () => {
    const { container } = renderRow({
      soloUnderline: true,
      getByteAt: (offset) => (offset === 6 ? undefined : byteAt(offset)),
      getAbsenceAt: (offset) => (offset === 6 ? "not-in-dump" : undefined),
      getVariantsAt: () => 4,
    });

    const cell = hexCell(container, 6);
    expect(underlineClass(cell)).toBeNull();
    expect(cell).toHaveClass("byte-absent");
    expect(underlineClass(hexCell(container, 7))).toBe("variant-underline-3");
  });

  it("does not print the glyph-mode void mark in solo", () => {
    const { container } = renderRow({
      soloUnderline: true,
      renderMode: "glyph",
      getByteAt: (offset) => (offset === 6 ? undefined : byteAt(offset)),
      getAbsenceAt: (offset) => (offset === 6 ? "not-in-dump" : undefined),
      getVariantsAt: () => 1,
    });

    expect(hexCell(container, 6)).not.toHaveTextContent(GLYPH_VOID);
  });
});

describe("HexRow without solo", () => {
  /** The overlay is untouched: fills where it always filled, no underlines. */
  it("keeps filling in the overlay's variants mode", () => {
    const { container } = renderRow({
      renderMode: "variants",
      getVariantsAt: () => 4,
    });

    const cell = hexCell(container, 0);
    expect(rampClass(cell)).toBe("variant-3");
    expect(underlineClass(cell)).toBeNull();
  });
});
