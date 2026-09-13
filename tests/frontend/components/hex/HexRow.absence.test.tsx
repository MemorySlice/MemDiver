import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexRow } from "@/components/hex/HexRow";
import { buildRegionIndex } from "@/components/hex/highlight-utils";
import type { AbsenceKind } from "@/utils/absence-classes";

/**
 * A cell with no byte in it has to say WHY, and the four reasons must never be
 * pixel-identical.
 *
 * Before this, `HexRow` painted a grey `--` for "still loading", "no dump holds
 * a byte here", "this dump does not hold one" and "the request failed" alike —
 * so a transport error read as a finding about memory, and a genuinely absent
 * page read as a slow network. The rule the design is emphatic about is the
 * one the last group below pins: an absent cell is NEVER folded into the
 * consensus vocabulary, because "this page was not captured" and "this byte
 * changed" are different findings.
 */

const CURSOR = { cursorOffset: null, selectionStart: null, selectionEnd: null } as const;

/** Nothing is loaded: every cell in this row is an absence of some kind. */
function noBytes(): number | undefined {
  return undefined;
}

function renderRow(extra: Partial<React.ComponentProps<typeof HexRow>> = {}) {
  return render(
    <HexRow
      rowOffset={0}
      getByteAt={noBytes}
      {...CURSOR}
      regionIndex={buildRegionIndex([])}
      {...extra}
    />,
  );
}

function hexCell(container: HTMLElement, offset: number): HTMLElement {
  const el = container.querySelector(`[data-col="hex"][data-offset="${offset}"]`);
  if (!el) throw new Error(`no hex cell at offset ${offset}`);
  return el as HTMLElement;
}

/** state -> the class it paints and the glyph it prints. */
const STATES: [AbsenceKind, string, string][] = [
  ["loading", "hex-loading", "··"],
  ["no-correspondence", "byte-gap", "--"],
  ["not-in-dump", "byte-absent", "--"],
  ["error", "byte-error", "!!"],
];

const ABSENCE_CLASSES = STATES.map(([, cls]) => cls);

describe("HexRow absence vocabulary", () => {
  it.each(STATES)("paints %s as %s with the glyph %s", (state, cls, glyph) => {
    const { container } = renderRow({ getAbsenceAt: () => state });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass(cls);
    expect(cell).toHaveTextContent(glyph);
  });

  /**
   * Distinctness is the whole claim, so it is asserted directly rather than
   * inferred from four separate assertions that each pass on their own.
   */
  it("keeps the four states mutually exclusive", () => {
    for (const [state, cls] of STATES) {
      const { container, unmount } = renderRow({ getAbsenceAt: () => state });
      const classes = [...hexCell(container, 0).classList];
      expect(classes).toContain(cls);
      for (const other of ABSENCE_CLASSES.filter((c) => c !== cls)) {
        expect(classes).not.toContain(other);
      }
      unmount();
    }
  });

  it("gives each state its own glyph", () => {
    const glyphs = new Set(STATES.map(([, , glyph]) => glyph));
    // `--` is deliberately shared by the two genuinely-absent states, which the
    // hatch colour and the tooltip tell apart; `··` and `!!` are theirs alone.
    expect(glyphs).toEqual(new Set(["··", "--", "!!"]));
  });

  it("names the reason in the native title", () => {
    const { container } = renderRow({ getAbsenceAt: () => "not-in-dump" });

    expect(hexCell(container, 0)).toHaveAttribute(
      "title",
      expect.stringMatching(/not in this dump/i),
    );
  });

  it("falls back to loading when no reader is supplied", () => {
    const { container } = renderRow();

    expect(hexCell(container, 0)).toHaveClass("hex-loading");
  });

  /**
   * A cause that claims "no byte" must never blank a cell that HAS one — the
   * byte source wins, or a slow `absenceAt` would erase real data.
   */
  it("never voids a cell that actually holds a byte", () => {
    const { container } = renderRow({
      getByteAt: () => 0x41,
      getAbsenceAt: () => "not-in-dump",
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveTextContent("41");
    expect(cell).not.toHaveClass("byte-absent");
  });
});

describe("HexRow absence excludes the consensus vocabulary", () => {
  /**
   * THE structural rule. Not a convention: `HexRow` takes the absence branch
   * and never reaches the class branch, so no future caller can produce a
   * hatched cell that also claims to be a key candidate.
   */
  it.each(STATES)("puts no consensus class on a %s cell", (state) => {
    const { container } = renderRow({
      getAbsenceAt: () => state,
      overlayEnabled: true,
      getClassificationAt: () => 3,
    });

    const classes = [...hexCell(container, 0).classList];
    expect(classes.some((c) => c.startsWith("consensus-"))).toBe(false);
  });

  it("puts no variance tier on an absent cell either", () => {
    const { container } = renderRow({
      getAbsenceAt: () => "not-in-dump",
      getVarianceAt: () => 250,
    });

    const classes = [...hexCell(container, 0).classList];
    expect(classes.some((c) => c.startsWith("var-tier-"))).toBe(false);
  });

  /**
   * The disagreement RING is the one thing that still composes: it carries no
   * background of its own, and `.byte-error`'s inset is on the bottom edge
   * precisely so the ring survives on the same cell.
   */
  it("still composes the cross-dump ring with the error state", () => {
    const { container } = renderRow({
      getAbsenceAt: () => "error",
      getDiffersAt: () => true,
    });

    const cell = hexCell(container, 0);
    expect(cell).toHaveClass("byte-error");
    expect(cell).toHaveClass("cross-dump-differs");
  });
});

describe("HexRow absence is coordinate-independent", () => {
  /**
   * The actual fix. The page-state tints used to be gated on `view === "va"`,
   * so a `"vas"` window — the coordinate the multi-dump viewers default to —
   * painted every missing byte as an anonymous `--`.
   */
  it.each(["raw", "vas", "va"] as const)("paints the hatch in the %s view", (view) => {
    const { container } = renderRow({ view, getAbsenceAt: () => "not-in-dump" });

    expect(hexCell(container, 0)).toHaveClass("byte-absent");
  });

  it("renders the page-state tints in the vas view, which it never did before", () => {
    const { container } = renderRow({
      view: "vas",
      getByteAt: () => 0x00,
      getAbsenceAt: () => "failed",
    });

    expect(hexCell(container, 0)).toHaveClass("page-failed");
  });

  /**
   * The single-dump viewer's behaviour, unchanged: its adapter maps
   * FAILED/UNMAPPED onto the tints and CAPTURED (or a not-yet-resolved page
   * state) onto `loading`, which is exactly what the old `"va"`-gated block
   * did — a zero-filled non-captured byte still prints and still tints.
   */
  it("keeps the single-dump va behaviour byte for byte", () => {
    const { container } = renderRow({
      view: "va",
      getByteAt: (offset) => (offset < 2 ? 0x00 : undefined),
      getAbsenceAt: (offset) => {
        if (offset === 0) return "failed";
        if (offset === 1) return "unmapped";
        return "loading";
      },
    });

    expect(hexCell(container, 0)).toHaveClass("page-failed");
    expect(hexCell(container, 0)).toHaveTextContent("00");
    expect(hexCell(container, 1)).toHaveClass("page-unmapped");
    expect(hexCell(container, 1)).toHaveTextContent("00");
    // A captured byte whose chunk has not arrived: the faint placeholder, as
    // before — and no hatch, because a slow fetch is not a finding.
    const pending = hexCell(container, 2);
    expect(pending).toHaveClass("hex-loading");
    expect([...pending.classList]).not.toContain("byte-absent");
  });
});
