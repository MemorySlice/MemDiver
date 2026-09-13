import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useConsensusStore } from "@/stores/consensus-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { useOverlayDetailStore } from "@/stores/overlay-detail-store";
import { useVarianceRegionsStore } from "@/stores/variance-regions-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const { VarianceClassChips } = await import("@/components/hex/VarianceClassChips");

/**
 * The clickable legend.
 *
 * Two of these cases pin a HONESTY rule rather than a rendering detail, and
 * both of them fail silently in a way a screenshot would pass:
 *
 *   - the counts must be the WHOLE-BUILD histogram. A window-scoped count
 *     changes as the user scrolls, and "Key Candidate 0 bytes" because this
 *     screen holds none reads as "this dump has none".
 *   - `differs` is the one genuine exception (there is no server-side
 *     whole-dump enumeration of it), so it must SAY it is window-scoped rather
 *     than borrow the others' framing.
 */

const CHIPS = [
  "invariant",
  "structural",
  "pointer",
  "key_candidate",
  "differs",
  "non_invariant",
] as const;

/** The store state one loaded page of the union query leaves behind. */
function seedCounts() {
  act(() => {
    useVarianceRegionsStore.setState({
      category: "non_invariant",
      counts: { invariant: 4_000_000, structural: 1_200, pointer: 3_400, key_candidate: 56 },
      total: 128,
      requestKey: "seeded",
    });
  });
}

beforeEach(() => {
  act(() => {
    useVarianceRegionsStore.getState().reset();
    // The mounted loader would otherwise re-derive these lists from an empty
    // byte cache and an absent consensus. What it loads is
    // `useVarianceRegions`'s and the store's business, pinned in their own
    // suites; here the question is what the chips DO with a loaded page.
    useVarianceRegionsStore.setState({ loadMore: async () => {} });
    useOverlayDetailStore.setState({ tab: "byte" });
    useConsensusStore.getState().reset();
    useHexStore.getState().reset();
    useMultiHexStore.getState().reset();
  });
});

afterEach(() => {
  act(() => {
    useVarianceRegionsStore.getState().reset();
    useConsensusStore.getState().reset();
  });
});

describe("VarianceClassChips", () => {
  it("offers one button per category, six in all", () => {
    render(<VarianceClassChips />);

    const group = screen.getByRole("group", { name: /class/i });
    expect(group).toBeInTheDocument();
    for (const chip of CHIPS) {
      const button = screen.getByTestId(`hex-overlay-class-chip-${chip}`);
      expect(button.tagName).toBe("BUTTON");
    }
    expect(screen.getAllByTestId(/^hex-overlay-class-chip-/)).toHaveLength(6);
  });

  it("defaults to the non-invariant union, the only query that finds a key whole", () => {
    render(<VarianceClassChips />);

    expect(useVarianceRegionsStore.getState().category).toBe("non_invariant");
    expect(screen.getByTestId("hex-overlay-class-chip-non_invariant")).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.getByTestId("hex-overlay-class-chip-pointer")).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });

  it("carries the count INSIDE the accessible name, not beside it", () => {
    seedCounts();
    render(<VarianceClassChips />);

    // getByRole matches on the accessible name, so this only passes when the
    // count is part of the button's own content.
    expect(screen.getByRole("button", { name: /Pointer\s+3,400 bytes/ })).toBeInTheDocument();
    // The union chip sums the three non-invariant bands and never includes
    // invariant, which is not part of the query it stands for.
    expect(screen.getByRole("button", { name: /Changing\s+4,656 bytes/ })).toBeInTheDocument();
  });

  it("shows a dash, never a zero, before the histogram has arrived", () => {
    render(<VarianceClassChips />);

    // "Key Candidate 0 bytes" would be a claim about the dump; this is a
    // statement about the request.
    expect(screen.getByTestId("hex-overlay-class-chip-key_candidate")).not.toHaveTextContent(
      "0 bytes",
    );
    expect(screen.getByTestId("hex-overlay-class-chip-key_candidate")).toHaveTextContent("—");
  });

  it("labels differs as window-scoped instead of implying a whole-dump total", () => {
    act(() => {
      useVarianceRegionsStore.setState({
        category: "differs",
        windowScoped: true,
        total: 12,
        requestKey: "seeded",
      });
    });
    render(<VarianceClassChips />);

    const chip = screen.getByTestId("hex-overlay-class-chip-differs");
    expect(chip).toHaveTextContent("12 in view");
    expect(chip.getAttribute("title")).toMatch(/currently loaded/i);
  });

  it("gives every chip the swatch class the stylesheet actually targets", () => {
    render(<VarianceClassChips />);

    const expected: Record<string, string> = {
      invariant: "variance-invariant",
      structural: "variance-structural",
      pointer: "variance-pointer",
      key_candidate: "variance-key-candidate",
      differs: "variance-differs",
      non_invariant: "variance-non-invariant",
    };
    for (const chip of CHIPS) {
      const swatch = screen.getByTestId(`hex-overlay-class-swatch-${chip}`);
      expect(swatch).toHaveClass("md-variance-swatch");
      expect(swatch).toHaveClass(expected[chip]);
    }
  });

  it("sets the store category and reveals the browser when clicked", () => {
    render(<VarianceClassChips />);

    act(() => {
      screen.getByTestId("hex-overlay-class-chip-pointer").click();
    });

    expect(useVarianceRegionsStore.getState().category).toBe("pointer");
    // A chip that selected a class without showing the list would look broken.
    expect(useOverlayDetailStore.getState().tab).toBe("regions");
  });
});

describe("VarianceClassChips colour explainer", () => {
  it("states the bands the BUILD used, never a hard-coded 0/200/3000", () => {
    act(() => {
      useConsensusStore.setState({
        thresholds: { invariant_max: 0, structural_max: 512, pointer_max: 9000 },
      });
    });
    render(<VarianceClassChips />);

    const legend = screen.getByTestId("hex-overlay-colour-legend");
    expect(legend).toHaveTextContent("variance ≤ 512");
    expect(legend).toHaveTextContent("variance > 9,000");
    // The module defaults must not leak in when the build reported others.
    expect(legend).not.toHaveTextContent("3,000");
  });

  it("omits the boundaries rather than guessing when the build reported none", () => {
    render(<VarianceClassChips />);

    const legend = screen.getByTestId("hex-overlay-colour-legend");
    expect(legend).not.toHaveTextContent("variance ≤");
    expect(legend).toHaveTextContent(/did not report/i);
  });

  it("explains the dimming, the ring and the mixed-class caveat", () => {
    render(<VarianceClassChips />);

    const legend = screen.getByTestId("hex-overlay-colour-legend");
    expect(legend).toHaveTextContent(/deliberately dimmed/i);
    expect(legend).toHaveTextContent(/ring, not a fill/i);
    expect(legend).toHaveTextContent(/27 key candidate \+ 18 pointer \+ 3 structural/i);
  });
});
