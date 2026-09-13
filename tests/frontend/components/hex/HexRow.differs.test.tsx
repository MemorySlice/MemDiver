import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexRow } from "@/components/hex/HexRow";
import { buildRegionIndex } from "@/components/hex/highlight-utils";

/**
 * `getDiffersAt` is an ADDITIVE prop, and "additive" is a claim about the other
 * five styling layers on the same byte, not about this one.
 *
 * The failure this guards against is not a missing ring — that is obvious on
 * screen — but a ring that QUIETLY EVICTS the consensus class, the variance
 * tier, the page-state tint or the search highlight from the same cell. Those
 * losses look like ordinary bytes, so nothing downstream reports them.
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
      {...extra}
    />,
  );
}

/** The hex cell for an absolute offset, as the DOM exposes it. */
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

describe("HexRow getDiffersAt placement", () => {
  it("marks exactly the offsets the predicate accepts", () => {
    const { container } = renderRow({ getDiffersAt: (o) => o === 3 || o === 11 });

    for (let i = 0; i < 16; i++) {
      const expected = i === 3 || i === 11;
      expect(hexCell(container, i).classList.contains("cross-dump-differs")).toBe(expected);
      expect(asciiCell(container, i).classList.contains("cross-dump-differs")).toBe(expected);
    }
  });

  it("changes nothing when the prop is omitted", () => {
    const { container } = renderRow();

    expect(container.querySelectorAll(".cross-dump-differs")).toHaveLength(0);
  });
});

describe("HexRow getDiffersAt composes with the other layers", () => {
  it("keeps the consensus class on the same byte", () => {
    const { container } = renderRow({
      overlayEnabled: true,
      getClassificationAt: () => 3,
      getDiffersAt: () => true,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("consensus-key-candidate");
    expect(cell).toHaveClass("cross-dump-differs");
  });

  it("keeps the variance tier on the same byte", () => {
    const { container } = renderRow({
      getVarianceAt: () => 250,
      getDiffersAt: () => true,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("var-tier-3");
    expect(cell).toHaveClass("cross-dump-differs");
  });

  it("keeps the page-state tint on the same byte", () => {
    // The page state now reaches the row through the absence vocabulary (the
    // single-dump viewer adapts `getPageStateAt` into it); a FAILED page still
    // carries a byte, so it tints rather than voids and must still compose.
    const { container } = renderRow({
      view: "va",
      getAbsenceAt: () => "failed",
      getDiffersAt: () => true,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("page-failed");
    expect(cell).toHaveClass("cross-dump-differs");
  });

  it("keeps the search highlight on the same byte", () => {
    const { container } = renderRow({
      regionIndex: buildRegionIndex([
        { offset: 0, length: 4, type: "search", label: "hit" },
      ]),
      getDiffersAt: () => true,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("highlight-search");
    expect(cell).toHaveClass("cross-dump-differs");
  });

  it("keeps the cursor and selection classes on the same byte", () => {
    const { container } = render(
      <HexRow
        rowOffset={0}
        getByteAt={byteAt}
        cursorOffset={2}
        selectionStart={0}
        selectionEnd={4}
        regionIndex={buildRegionIndex([])}
        getDiffersAt={() => true}
      />,
    );

    const cell = hexCell(container, 2);
    expect(cell).toHaveClass("cursor");
    expect(cell).toHaveClass("selected");
    expect(cell).toHaveClass("cross-dump-differs");
  });

  it("stacks all four overlays at once without dropping any", () => {
    const { container } = renderRow({
      overlayEnabled: true,
      getClassificationAt: () => 2,
      getVarianceAt: () => 120,
      view: "va",
      getAbsenceAt: () => "unmapped",
      regionIndex: buildRegionIndex([
        { offset: 0, length: 1, type: "search", label: "hit" },
      ]),
      getDiffersAt: () => true,
    });

    const cell = hexCell(container, 0);
    for (const cls of [
      "highlight-search",
      "var-tier-2",
      "consensus-pointer",
      "page-unmapped",
      "cross-dump-differs",
    ]) {
      expect(cell).toHaveClass(cls);
    }
  });
});

describe("HexRow differs tooltip", () => {
  /**
   * The ring is the primary signal and `OverlayByteInspector` is the primary
   * affordance, but a hover that says nothing at all over a visibly marked byte
   * is worse than one word. Reuses NDumpOverlay's existing string.
   */
  it("names the disagreement in the native title", () => {
    const { container } = renderRow({ getDiffersAt: (o) => o === 0 });

    expect(hexCell(container, 0)).toHaveAttribute(
      "title",
      expect.stringMatching(/varies across dumps/i),
    );
    expect(hexCell(container, 1)).not.toHaveAttribute("title");
  });

  it("appends to an existing tooltip instead of replacing it", () => {
    const { container } = renderRow({
      regionIndex: buildRegionIndex([
        { offset: 0, length: 1, type: "search", label: "search hit" },
      ]),
      getDiffersAt: () => true,
    });

    const title = hexCell(container, 0).getAttribute("title") ?? "";
    expect(title).toMatch(/search hit/);
    expect(title).toMatch(/varies across dumps/i);
  });
});
