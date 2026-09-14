import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useVarianceRegionsStore } from "@/stores/variance-regions-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const { RegionFilterBar } = await import("@/components/hex/RegionFilterBar");

/**
 * The size question, as a control.
 *
 * Three of these cases pin a CONTRACT rather than a rendering detail:
 *
 *   - a preset is an EXACT-size query. "32 B" that set only the floor would
 *     return every run of 32 bytes OR MORE, which for a 17,000-row list is
 *     barely a filter at all and is not what the chip says.
 *   - `Any` restores the SERVER floor (8) and an unbounded ceiling — not
 *     `0`/`0`, which would ask for every one-byte run in the dump.
 *   - every control carries an accessible name. The axe suite tracks unnamed
 *     selects as existing debt, and this panel must not add to it.
 */

function filterState() {
  const { minLength, maxLength, sort } = useVarianceRegionsStore.getState();
  return { minLength, maxLength, sort };
}

beforeEach(() => {
  act(() => {
    useVarianceRegionsStore.getState().reset();
  });
});

afterEach(() => {
  act(() => {
    useVarianceRegionsStore.getState().reset();
  });
});

describe("RegionFilterBar presets", () => {
  it("offers the sizes real key material comes in, plus an escape hatch", () => {
    render(<RegionFilterBar />);

    for (const size of [16, 24, 32, 48]) {
      expect(screen.getByTestId(`region-filter-preset-${size}`)).toBeInTheDocument();
    }
    expect(screen.getByTestId("region-filter-preset-any")).toBeInTheDocument();
  });

  it("sets BOTH bounds — a preset is an exact-size query", () => {
    render(<RegionFilterBar />);

    fireEvent.click(screen.getByTestId("region-filter-preset-32"));

    expect(filterState()).toEqual({ minLength: 32, maxLength: 32, sort: "offset" });
  });

  it("Any restores the server floor and no ceiling, not zero and zero", () => {
    render(<RegionFilterBar />);
    fireEvent.click(screen.getByTestId("region-filter-preset-48"));

    fireEvent.click(screen.getByTestId("region-filter-preset-any"));

    // `minLength: 0` would ask for every one-byte run in a multi-GiB dump.
    expect(filterState()).toEqual({ minLength: 8, maxLength: 0, sort: "offset" });
  });

  it("marks exactly the active preset with aria-pressed", () => {
    render(<RegionFilterBar />);
    // A cold store is the server default, which IS "Any".
    expect(screen.getByTestId("region-filter-preset-any")).toHaveAttribute(
      "aria-pressed",
      "true",
    );

    fireEvent.click(screen.getByTestId("region-filter-preset-24"));

    expect(screen.getByTestId("region-filter-preset-24")).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.getByTestId("region-filter-preset-any")).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    expect(screen.getByTestId("region-filter-preset-32")).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });

  it("does not claim a preset for a hand-typed range that merely overlaps it", () => {
    render(<RegionFilterBar />);

    fireEvent.change(screen.getByTestId("region-filter-min"), { target: { value: "32" } });

    // min 32 with no ceiling is not "exactly 32 bytes", and no chip may say so.
    expect(screen.getByTestId("region-filter-preset-32")).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    expect(screen.getByTestId("region-filter-preset-any")).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });
});

describe("RegionFilterBar manual controls", () => {
  it("sends the typed bounds to the store", () => {
    render(<RegionFilterBar />);

    fireEvent.change(screen.getByTestId("region-filter-min"), { target: { value: "12" } });
    fireEvent.change(screen.getByTestId("region-filter-max"), { target: { value: "64" } });

    expect(filterState()).toMatchObject({ minLength: 12, maxLength: 64 });
  });

  it("reads an emptied ceiling as NO LIMIT, the way the wire spells it", () => {
    render(<RegionFilterBar />);
    fireEvent.change(screen.getByTestId("region-filter-max"), { target: { value: "64" } });

    fireEvent.change(screen.getByTestId("region-filter-max"), { target: { value: "" } });

    expect(useVarianceRegionsStore.getState().maxLength).toBe(0);
  });

  it("changes the sort through the store, not by re-ordering rows", () => {
    render(<RegionFilterBar />);

    fireEvent.change(screen.getByTestId("region-filter-sort"), {
      target: { value: "length_desc" },
    });

    expect(useVarianceRegionsStore.getState().sort).toBe("length_desc");
  });

  it("reflects a sort the store already holds", () => {
    act(() => {
      useVarianceRegionsStore.getState().setSort("length_asc");
    });

    render(<RegionFilterBar />);

    expect(screen.getByTestId("region-filter-sort")).toHaveValue("length_asc");
  });
});

describe("RegionFilterBar honesty and accessibility", () => {
  it("names every control, so none of them is an unlabelled box", () => {
    render(<RegionFilterBar />);

    expect(screen.getByLabelText("Min length")).toBe(screen.getByTestId("region-filter-min"));
    expect(screen.getByLabelText("Max length")).toBe(screen.getByTestId("region-filter-max"));
    expect(screen.getByLabelText("Sort")).toBe(screen.getByTestId("region-filter-sort"));
  });

  it("names the length it filters on, and warns that a page-spanning row differs", () => {
    render(<RegionFilterBar />);

    const note = screen.getByTestId("region-filter-length-note");
    expect(note).toHaveTextContent(/aligned length/i);
    expect(note).toHaveTextContent(/page boundary/i);
    // "slab" is the Linux kernel's heap allocator. MemSlicer does not acquire
    // kernel space at all, so borrowing the word here named the wrong thing
    // entirely — and would send an analyst looking for a kernel structure.
    expect(note.textContent).not.toMatch(/slab/i);
  });

  it("offers all three orders by name", () => {
    render(<RegionFilterBar />);

    const labels = Array.from(
      screen.getByTestId("region-filter-sort").querySelectorAll("option"),
    ).map((option) => option.textContent);
    expect(labels).toEqual(["Offset", "Longest first", "Shortest first"]);
  });
});
