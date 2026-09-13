import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexRow } from "@/components/hex/HexRow";
import { buildRegionIndex } from "@/components/hex/highlight-utils";
import { GLYPH_IDENTICAL, GLYPH_VOID } from "@/utils/variant-ramp";

/**
 * The `variants` and `glyph` render modes answer a DIFFERENT question from the
 * class bands — "how many distinct values do the dumps hold here", not "what
 * did the consensus conclude" — and the failure this guards against is the two
 * answers leaking into each other.
 *
 * Three ways that happens, all of them invisible on screen:
 *   1. a ramp tint on a VOID cell, which says "three dumps disagree" about a
 *      byte no dump holds;
 *   2. a `consensus-*` class surviving into a count-driven mode, so one colour
 *      means two things in the same grid;
 *   3. an off-by-one ramp index, which mislabels every cell by one step.
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

/** The ramp class on a cell, or `null` when it carries none. */
function rampClass(cell: HTMLElement): string | null {
  return [...cell.classList].find((c) => /^variant-[1-5]$/.test(c)) ?? null;
}

describe("HexRow variants ramp index", () => {
  /**
   * The design's rule verbatim: index the ramp at `min(variants - 1, 5)`, and
   * index 0 paints nothing. Every boundary of that expression in one table,
   * because an off-by-one here is a whole-grid error that still looks plausible.
   */
  const CASES: [number, string | null][] = [
    [0, null], // nobody present — never a colour
    [1, null], // every dump agrees — the quiet background, not a finding
    [2, "variant-1"],
    [3, "variant-2"],
    [4, "variant-3"],
    [5, "variant-4"],
    [6, "variant-5"],
    [7, "variant-5"], // clamped
    [64, "variant-5"], // still clamped
  ];

  it.each(CASES)("paints %i variants as %s", (variants, expected) => {
    const { container } = renderRow({
      renderMode: "variants",
      getVariantsAt: () => variants,
    });

    expect(rampClass(hexCell(container, 0))).toBe(expected);
  });

  it("paints nothing where the store has no answer yet", () => {
    const { container } = renderRow({
      renderMode: "variants",
      getVariantsAt: () => undefined,
    });

    expect(rampClass(hexCell(container, 0))).toBeNull();
  });

  it("marks exactly the offsets the count reaches 2 at", () => {
    const { container } = renderRow({
      renderMode: "variants",
      getVariantsAt: (o) => (o === 3 || o === 11 ? 4 : 1),
    });

    for (let i = 0; i < 16; i++) {
      const expected = i === 3 || i === 11 ? "variant-3" : null;
      expect(rampClass(hexCell(container, i))).toBe(expected);
    }
  });
});

describe("HexRow render modes are mutually exclusive", () => {
  /**
   * The class bands and the ramp are two different vocabularies for the same
   * cell. Either one on its own is readable; both at once is a cell whose
   * colour has no single meaning.
   */
  it("emits no consensus class in variants mode", () => {
    const { container } = renderRow({
      renderMode: "variants",
      getClassificationAt: () => 3,
      getVariantsAt: () => 4,
    });

    const cell = hexCell(container, 0);
    expect(cell).not.toHaveClass("consensus-key-candidate");
    expect(cell).toHaveClass("variant-3");
    expect(container.querySelectorAll("[class*='consensus-']")).toHaveLength(0);
  });

  it("emits no consensus class in glyph mode", () => {
    const { container } = renderRow({
      renderMode: "glyph",
      getClassificationAt: () => 2,
      getVariantsAt: () => 3,
    });

    expect(container.querySelectorAll("[class*='consensus-']")).toHaveLength(0);
  });

  it("emits no ramp class in class mode, even with a variant count to hand", () => {
    const { container } = renderRow({
      renderMode: "class",
      getClassificationAt: () => 3,
      getVariantsAt: () => 6,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("consensus-key-candidate");
    expect(rampClass(cell)).toBeNull();
  });

  it("defaults to class mode when the prop is omitted", () => {
    const { container } = renderRow({
      getClassificationAt: () => 1,
      getVariantsAt: () => 6,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("consensus-structural");
    expect(rampClass(cell)).toBeNull();
  });

  /**
   * In the count-driven modes the number itself already says the dumps
   * disagree; a ring on top would encode one fact as two marks.
   */
  it("drops the cross-dump ring outside class mode", () => {
    const { container } = renderRow({
      renderMode: "variants",
      getVariantsAt: () => 3,
      getDiffersAt: () => true,
    });

    expect(container.querySelectorAll(".cross-dump-differs")).toHaveLength(0);
  });

  it("keeps the cross-dump ring in class mode", () => {
    const { container } = renderRow({
      renderMode: "class",
      getDiffersAt: () => true,
    });

    expect(hexCell(container, 0)).toHaveClass("cross-dump-differs");
  });
});

describe("HexRow ramp never lands on a void cell", () => {
  /**
   * The SAME structural exclusivity the class branch has: `HexRow` decides a
   * cell is void BEFORE any styling branch runs, and the ramp sits inside that
   * gate. A hatched cell carrying `variant-4` would claim a disagreement
   * between dumps that hold nothing at all here.
   */
  const VOID_STATES = ["loading", "no-correspondence", "not-in-dump", "error"] as const;

  it.each(VOID_STATES)("refuses the ramp on a %s cell", (kind) => {
    const { container } = render(
      <HexRow
        rowOffset={0}
        getByteAt={() => undefined}
        {...CURSOR}
        regionIndex={buildRegionIndex([])}
        overlayEnabled
        renderMode="variants"
        getAbsenceAt={() => kind}
        // A count the store would never report for an absent byte; if it ever
        // did, the cell still must not take it.
        getVariantsAt={() => 5}
      />,
    );

    const cell = hexCell(container, 0);
    expect(rampClass(cell)).toBeNull();
    expect(cell.className).toMatch(/hex-loading|byte-gap|byte-absent|byte-error/);
  });

  /**
   * The two MSL page states are NOT void — the backend really does send a
   * zero-filled byte — so they compose with the ramp exactly as they compose
   * with a consensus class.
   */
  it("keeps the ramp on a page-state tint, which carries a real byte", () => {
    const { container } = renderRow({
      view: "va",
      renderMode: "variants",
      getAbsenceAt: () => "failed",
      getVariantsAt: () => 3,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("page-failed");
    expect(cell).toHaveClass("variant-2");
  });
});

describe("HexRow glyph mode", () => {
  it("prints the identical mark where every dump agrees", () => {
    const { container } = renderRow({
      renderMode: "glyph",
      getVariantsAt: () => 1,
    });

    expect(hexCell(container, 0)).toHaveTextContent(GLYPH_IDENTICAL);
  });

  it("prints the count as a digit, capped at 6", () => {
    const { container } = renderRow({
      renderMode: "glyph",
      getVariantsAt: (o) => o + 1,
    });

    expect(hexCell(container, 1)).toHaveTextContent("2");
    expect(hexCell(container, 4)).toHaveTextContent("5");
    expect(hexCell(container, 5)).toHaveTextContent("6");
    // 8 variants still reads "6": the vocabulary names six marks, not eight.
    expect(hexCell(container, 7)).toHaveTextContent("6");
  });

  it("prints the void mark where there is no byte", () => {
    const { container } = render(
      <HexRow
        rowOffset={0}
        getByteAt={() => undefined}
        {...CURSOR}
        regionIndex={buildRegionIndex([])}
        overlayEnabled
        renderMode="glyph"
        getAbsenceAt={() => "not-in-dump"}
        getVariantsAt={() => 0}
      />,
    );

    const cell = hexCell(container, 0);
    expect(cell).toHaveTextContent(GLYPH_VOID);
    // The CAUSE is still on the cell: the glyph collapses four reasons into one
    // mark, the class and the title keep them apart.
    expect(cell).toHaveClass("byte-absent");
    expect(cell).toHaveAttribute("title", expect.stringMatching(/not in this dump/i));
  });

  it("falls back to the hex value where the store has no count", () => {
    const { container } = renderRow({
      renderMode: "glyph",
      getVariantsAt: () => undefined,
    });

    // Offset 3 holds 0x03 under `byteAt`.
    expect(hexCell(container, 3)).toHaveTextContent("03");
  });

  it("still prints hex values in the other two modes", () => {
    for (const mode of ["class", "variants"] as const) {
      const { container } = renderRow({ renderMode: mode, getVariantsAt: () => 4 });
      expect(hexCell(container, 3)).toHaveTextContent("03");
    }
  });
});

describe("HexRow variant tooltip", () => {
  /**
   * Five ramp steps cannot name six counts, and `glyph` caps at 6. The hover
   * carries the exact number so the cap never hides a 40-way disagreement.
   */
  it("names the exact count on hover", () => {
    const { container } = renderRow({
      renderMode: "variants",
      getVariantsAt: () => 40,
    });

    expect(hexCell(container, 0)).toHaveAttribute(
      "title",
      expect.stringMatching(/40 distinct values/i),
    );
  });

  it("says nothing about counts in class mode", () => {
    const { container } = renderRow({
      renderMode: "class",
      getVariantsAt: () => 40,
    });

    expect(hexCell(container, 0)).not.toHaveAttribute("title");
  });
});
