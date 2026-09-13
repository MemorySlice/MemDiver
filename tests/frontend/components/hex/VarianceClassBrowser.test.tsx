import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { ClassRegion } from "@/api/consensus-regions";
import { useConsensusStore } from "@/stores/consensus-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import {
  useVarianceRegionsStore,
  type VarianceRegion,
} from "@/stores/variance-regions-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

// jsdom ships no IntersectionObserver, and the load-more sentinel constructs
// one. A no-op stub keeps the auto-paging path from throwing while leaving the
// explicit button — the accessible fallback these cases actually exercise —
// exactly as it is in the browser.
class NoopObserver implements IntersectionObserver {
  readonly root = null;
  readonly rootMargin = "";
  readonly thresholds: readonly number[] = [];
  disconnect() {}
  observe() {}
  unobserve() {}
  takeRecords(): IntersectionObserverEntry[] {
    return [];
  }
}
vi.stubGlobal("IntersectionObserver", NoopObserver);

const { VarianceClassBrowser } = await import("@/components/hex/VarianceClassBrowser");

/**
 * The browsable list of every occurrence.
 *
 * The case that matters most here is the COORDINATE one. `length` is the SLAB
 * length; the range a jump actually selects is `anchor_offset_end -
 * anchor_offset`, and the two differ whenever a region crosses an `msl_layout`
 * page boundary — `slab_to_va` is linear only within a row. A list that prints
 * `length` as "48 bytes at 0x…" describes bytes the viewer never highlights,
 * which is the exact shape of every overlay bug this repo has shipped: correct
 * types, plausible numbers, wrong place. `renders the ANCHOR span` pins it with
 * a region where the two deliberately disagree.
 */

function region(overrides: Partial<ClassRegion> = {}): ClassRegion {
  return {
    slab_start: 1024,
    slab_end: 1072,
    length: 48,
    classification: "key_candidate",
    mean_variance: 9001.5,
    class_counts: { key_candidate: 27, pointer: 18, structural: 3 },
    anchor_va: 0x7f0000001000,
    anchor_offset: 583560,
    anchor_offset_end: 583608,
    anchor_contiguous: true,
    ...overrides,
  };
}

/** Put a loaded page in the store without going near the network. */
function seed(patch: Partial<{
  regions: VarianceRegion[];
  total: number;
  nextAfter: number;
  loading: boolean;
  error: string | null;
  windowScoped: boolean;
  anchorJumpable: boolean;
  activeIndex: number;
  category: "non_invariant" | "key_candidate" | "differs";
}> = {}) {
  act(() => {
    useVarianceRegionsStore.setState({
      category: "non_invariant",
      regions: [region()],
      total: 1,
      nextAfter: -1,
      activeIndex: -1,
      loading: false,
      error: null,
      requestKey: "seeded",
      windowScoped: false,
      counts: {},
      anchorJumpable: true,
      ...patch,
    });
  });
}

beforeEach(() => {
  act(() => {
    useVarianceRegionsStore.getState().reset();
    // The mounted loader is the subject of its own suite; here it would only
    // wipe the page these cases are about.
    useVarianceRegionsStore.setState({ loadMore: async () => {} });
    useConsensusStore.getState().reset();
    useHexStore.getState().reset();
    useMultiHexStore.getState().reset();
  });
});

afterEach(() => {
  act(() => {
    useVarianceRegionsStore.getState().reset();
    useHexStore.getState().reset();
  });
});

describe("VarianceClassBrowser rows", () => {
  it("renders one row per occurrence, with its offset and classification", () => {
    seed({ regions: [region(), region({ anchor_offset: 600000, anchor_offset_end: 600016 })] });
    render(<VarianceClassBrowser />);

    const rows = screen.getAllByTestId("variance-region-row");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("0x0008e788");
    expect(rows[0]).toHaveTextContent("Key Candidate");
  });

  it("renders the ANCHOR span, never the slab length", () => {
    // A region that crossed an `msl_layout` page boundary: 48 slab bytes, but
    // the anchor-space range that gets selected is 96.
    seed({
      regions: [
        region({
          length: 48,
          anchor_offset: 583560,
          anchor_offset_end: 583656,
          anchor_contiguous: false,
        }),
      ],
    });
    render(<VarianceClassBrowser />);

    expect(screen.getByTestId("variance-region-span")).toHaveTextContent("96 B");
    expect(screen.getByTestId("variance-region-span")).not.toHaveTextContent("48");
    // ... and it says the range is a superset rather than quietly claiming it.
    expect(screen.getByTestId("variance-region-approximate")).toBeInTheDocument();
  });

  it("shows the per-class breakdown a union page carries", () => {
    seed();
    render(<VarianceClassBrowser />);

    const breakdown = screen.getByTestId("variance-region-breakdown");
    expect(breakdown).toHaveTextContent("Key Candidate 27");
    expect(breakdown).toHaveTextContent("Pointer 18");
    expect(breakdown).toHaveTextContent("Structural 3");
  });

  it("jumps through the store, and leaves focus on the row", () => {
    const jumpToIndex = vi.fn();
    seed({ regions: [region(), region({ anchor_offset: 600000, anchor_offset_end: 600016 })] });
    act(() => {
      useVarianceRegionsStore.setState({ jumpToIndex });
    });
    render(<VarianceClassBrowser />);

    const row = screen.getAllByTestId("variance-region-row")[1];
    fireEvent.click(row);

    expect(jumpToIndex).toHaveBeenCalledWith(1);
    // Stealing focus into the grid would end the walk after one step.
    expect(document.activeElement).toBe(row);
  });

  it("jumps on Enter and on Space, like every other jumpable list here", () => {
    const jumpToIndex = vi.fn();
    seed();
    act(() => {
      useVarianceRegionsStore.setState({ jumpToIndex });
    });
    render(<VarianceClassBrowser />);

    const row = screen.getByTestId("variance-region-row");
    fireEvent.keyDown(row, { key: "Enter" });
    fireEvent.keyDown(row, { key: " " });
    expect(jumpToIndex).toHaveBeenCalledTimes(2);
  });

  it("marks the selected row with aria-current", () => {
    seed({ regions: [region(), region({ anchor_offset: 600000 })], activeIndex: 1 });
    render(<VarianceClassBrowser />);

    const rows = screen.getAllByTestId("variance-region-row");
    expect(rows[0]).not.toHaveAttribute("aria-current");
    expect(rows[1]).toHaveAttribute("aria-current", "true");
  });

  it("announces the landing in a polite live region", () => {
    seed({ activeIndex: 0 });
    render(<VarianceClassBrowser />);

    const status = screen.getByTestId("variance-class-browser-status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(status).toHaveTextContent("Region 1 of 1");
    expect(status).toHaveTextContent("Key Candidate");
    expect(status).toHaveTextContent("0x0008e788");
  });
});

describe("VarianceClassBrowser non-jumpable rows", () => {
  it("is inert, and does not move the cursor, when the anchor offset is -1", () => {
    const jumpToIndex = vi.fn();
    seed({
      regions: [region({ anchor_offset: -1, anchor_offset_end: -1 })],
    });
    act(() => {
      useVarianceRegionsStore.setState({ jumpToIndex });
      useHexStore.setState({ cursorOffset: 4242 });
    });
    render(<VarianceClassBrowser />);

    const row = screen.getByTestId("variance-region-row");
    expect(row).not.toHaveAttribute("tabindex");
    expect(row.getAttribute("title")).toMatch(/No navigable offset/i);
    // `-1` renders as a dash. Never as an address, and never as offset zero.
    expect(row).toHaveTextContent("—");

    fireEvent.click(row);
    fireEvent.keyDown(row, { key: "Enter" });

    expect(jumpToIndex).not.toHaveBeenCalled();
    expect(useHexStore.getState().cursorOffset).toBe(4242);
  });

  it("hides the jump at the page level and says why when the anchor is not jumpable", () => {
    seed({ anchorJumpable: false });
    render(<VarianceClassBrowser />);

    expect(screen.getByTestId("variance-class-browser-no-jump")).toBeInTheDocument();
    expect(screen.getByTestId("variance-region-row")).not.toHaveAttribute("tabindex");
  });
});

describe("VarianceClassBrowser states", () => {
  it("has an empty state that points at the chip which actually works", () => {
    seed({ regions: [], total: 0 });
    render(<VarianceClassBrowser />);

    const empty = screen.getByTestId("variance-class-browser-empty");
    expect(empty).toHaveTextContent(/Changing/);
  });

  it("says it is loading", () => {
    seed({ regions: [], loading: true });
    render(<VarianceClassBrowser />);

    expect(screen.getByTestId("variance-class-browser-loading")).toBeInTheDocument();
    expect(screen.queryByTestId("variance-class-browser-empty")).toBeNull();
  });

  it("surfaces a failure as an alert, not as an empty list", () => {
    seed({ regions: [], error: "Internal Server Error" });
    render(<VarianceClassBrowser />);

    const error = screen.getByTestId("variance-class-browser-error");
    expect(error).toHaveTextContent("Internal Server Error");
    expect(error).toHaveAttribute("role", "alert");
  });

  it("labels a window-scoped list as such instead of implying a whole-dump total", () => {
    seed({ windowScoped: true, total: 1 });
    render(<VarianceClassBrowser />);

    expect(screen.getByTestId("variance-class-browser-window-scoped")).toBeInTheDocument();
    const count = screen.getByTestId("variance-class-browser-count");
    expect(count).toHaveTextContent("1 in the loaded window");
    expect(count).not.toHaveTextContent("of 1 shown");
  });

  it("warns about the shattered-key trap on a SINGLE-class query only", () => {
    seed({ category: "key_candidate" });
    const { unmount } = render(<VarianceClassBrowser />);
    expect(screen.getByTestId("variance-class-browser-mixed-note")).toHaveTextContent(
      /27 key candidate \+ 18 pointer \+ 3 structural/,
    );
    unmount();

    // The union does not have the problem, so it does not carry the warning.
    seed({ category: "non_invariant" });
    render(<VarianceClassBrowser />);
    expect(screen.queryByTestId("variance-class-browser-mixed-note")).toBeNull();
  });

  it("states returned against total for a server-backed list", () => {
    seed({ total: 128 });
    render(<VarianceClassBrowser />);

    expect(screen.getByTestId("variance-class-browser-count")).toHaveTextContent("1 of 128 shown");
  });
});

describe("VarianceClassBrowser pagination", () => {
  it("offers load more only while a cursor remains", () => {
    seed({ nextAfter: -1 });
    const { unmount } = render(<VarianceClassBrowser />);
    expect(screen.queryByTestId("variance-class-browser-load-more")).toBeNull();
    unmount();

    seed({ nextAfter: 2048 });
    render(<VarianceClassBrowser />);
    expect(screen.getByTestId("variance-class-browser-load-more")).toBeInTheDocument();
  });

  it("asks the store for the next page when the button is pressed", () => {
    const loadMore = vi.fn(async () => {});
    seed({ nextAfter: 2048 });
    act(() => {
      useVarianceRegionsStore.setState({ loadMore });
    });
    render(<VarianceClassBrowser />);

    fireEvent.click(screen.getByTestId("variance-class-browser-load-more"));
    expect(loadMore).toHaveBeenCalled();
  });
});
