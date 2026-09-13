import { beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_DUMP_WEIGHT,
  DUMP_WEIGHTS,
  hasUnevenWeights,
  nextWeight,
  useDumpRailStore,
  type DumpWeight,
} from "@/stores/dump-rail-store";

/**
 * The rail's state decides WHICH bytes the overlay reduces and how much each
 * one counts, so the things worth pinning are the ones that would silently
 * change the grid: a fourth weight sneaking into the cycle, an exclusion that
 * also soloed, a solo that also excluded, and a reset that left one of the
 * three behind for the next selection to inherit.
 */

const A = "/dumps/a.msl";
const B = "/dumps/b.msl";

beforeEach(() => {
  useDumpRailStore.getState().reset();
});

describe("dump rail weights", () => {
  it("starts every dump at equal weight without an entry for it", () => {
    const state = useDumpRailStore.getState();

    expect(state.weightAt(A)).toBe(DEFAULT_DUMP_WEIGHT);
    expect(state.weightByPath.size).toBe(0);
  });

  /**
   * Exactly three legal values, in exactly this order. A slider would invite a
   * 1.37 that means nothing and cannot be quoted in a report; the cycle is the
   * whole vocabulary, so a fourth stop here is a product change, not a detail.
   */
  it("cycles 1.0 -> 1.5 -> 0.5 -> 1.0 and no further", () => {
    const seen: number[] = [];
    for (let i = 0; i < 4; i++) {
      useDumpRailStore.getState().cycleWeight(A);
      seen.push(useDumpRailStore.getState().weightAt(A));
    }

    expect(seen).toEqual([1.5, 0.5, 1, 1.5]);
  });

  it("names exactly the three weights the button offers", () => {
    expect([...DUMP_WEIGHTS]).toEqual([1, 1.5, 0.5]);
  });

  it("returns an unknown weight to the default rather than carrying it on", () => {
    expect(nextWeight(0.25 as DumpWeight)).toBe(DEFAULT_DUMP_WEIGHT);
  });

  /**
   * The default is stored as ABSENCE. A dump cycled all the way round to 1.0
   * has to be indistinguishable from one nobody ever touched, or the `weighted`
   * badge would keep claiming a weighted reading after the user undid it.
   */
  it("forgets a weight that has come back round to the default", () => {
    const store = useDumpRailStore.getState();
    store.cycleWeight(A);
    expect(hasUnevenWeights(useDumpRailStore.getState().weightByPath)).toBe(true);

    store.cycleWeight(A);
    store.cycleWeight(A);

    expect(useDumpRailStore.getState().weightByPath.has(A)).toBe(false);
    expect(hasUnevenWeights(useDumpRailStore.getState().weightByPath)).toBe(false);
  });

  it("weighs each dump independently", () => {
    useDumpRailStore.getState().cycleWeight(A);

    expect(useDumpRailStore.getState().weightAt(A)).toBe(1.5);
    expect(useDumpRailStore.getState().weightAt(B)).toBe(1);
  });

  it("sets a weight directly for the callers that do not cycle", () => {
    useDumpRailStore.getState().setWeight(A, 0.5);
    expect(useDumpRailStore.getState().weightAt(A)).toBe(0.5);

    useDumpRailStore.getState().setWeight(A, 1);
    expect(useDumpRailStore.getState().weightByPath.has(A)).toBe(false);
  });
});

describe("dump rail inclusion", () => {
  it("includes every dump until one is explicitly excluded", () => {
    expect(useDumpRailStore.getState().isIncluded(A)).toBe(true);
  });

  it("toggles a dump out of and back into the consensus", () => {
    useDumpRailStore.getState().toggleIncluded(A);
    expect(useDumpRailStore.getState().isIncluded(A)).toBe(false);
    expect(useDumpRailStore.getState().isIncluded(B)).toBe(true);

    useDumpRailStore.getState().toggleIncluded(A);
    expect(useDumpRailStore.getState().isIncluded(A)).toBe(true);
  });

  /**
   * Membership and weight are separate facts. Excluding a dump the analyst had
   * weighted must not throw the weight away, or turning the eye back on would
   * quietly restore it at 1.0 and change the reading.
   */
  it("keeps a dump's weight while it is excluded", () => {
    useDumpRailStore.getState().cycleWeight(A);
    useDumpRailStore.getState().toggleIncluded(A);

    expect(useDumpRailStore.getState().weightAt(A)).toBe(1.5);
  });
});

describe("dump rail solo", () => {
  it("has no solo until one is set", () => {
    expect(useDumpRailStore.getState().soloPath).toBeNull();
  });

  it("solos a dump and returns to the overlay", () => {
    useDumpRailStore.getState().setSolo(A);
    expect(useDumpRailStore.getState().soloPath).toBe(A);

    useDumpRailStore.getState().setSolo(null);
    expect(useDumpRailStore.getState().soloPath).toBeNull();
  });

  it("moves the solo straight from one dump to another", () => {
    useDumpRailStore.getState().setSolo(A);
    useDumpRailStore.getState().setSolo(B);

    expect(useDumpRailStore.getState().soloPath).toBe(B);
  });

  it("toggles the same dump back off", () => {
    useDumpRailStore.getState().toggleSolo(A);
    expect(useDumpRailStore.getState().soloPath).toBe(A);

    useDumpRailStore.getState().toggleSolo(A);
    expect(useDumpRailStore.getState().soloPath).toBeNull();
  });

  /**
   * Solo is a VIEW, not an exclusion. "Let me look at dump A for a second" must
   * not remove every other dump from the consensus, or coming back would show a
   * different overlay than the one the analyst left.
   */
  it("leaves membership and weights untouched", () => {
    useDumpRailStore.getState().cycleWeight(B);
    useDumpRailStore.getState().setSolo(A);

    expect(useDumpRailStore.getState().isIncluded(A)).toBe(true);
    expect(useDumpRailStore.getState().isIncluded(B)).toBe(true);
    expect(useDumpRailStore.getState().weightAt(B)).toBe(1.5);
  });
});

describe("dump rail collapse", () => {
  it("starts open and toggles", () => {
    expect(useDumpRailStore.getState().collapsed).toBe(false);

    useDumpRailStore.getState().toggleCollapsed();
    expect(useDumpRailStore.getState().collapsed).toBe(true);

    useDumpRailStore.getState().setCollapsed(false);
    expect(useDumpRailStore.getState().collapsed).toBe(false);
  });
});

describe("dump rail reset", () => {
  /**
   * A workspace teardown that left a weight or a solo behind would hand the
   * next selection a reading nobody chose for it — and, worse, one the rail
   * would still describe as `weighted` without anyone having weighted anything.
   */
  it("clears weights, exclusions, the solo and the collapse together", () => {
    const store = useDumpRailStore.getState();
    store.cycleWeight(A);
    store.toggleIncluded(B);
    store.setSolo(A);
    store.setCollapsed(true);

    store.reset();

    const after = useDumpRailStore.getState();
    expect(after.weightByPath.size).toBe(0);
    expect(after.excludedPaths.size).toBe(0);
    expect(after.soloPath).toBeNull();
    expect(after.collapsed).toBe(false);
    expect(after.weightAt(A)).toBe(DEFAULT_DUMP_WEIGHT);
    expect(after.isIncluded(B)).toBe(true);
  });
});
