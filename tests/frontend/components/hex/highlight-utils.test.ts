import { describe, expect, it } from "vitest";

import { buildRegionIndex, getRegionForOffset } from "@/components/hex/highlight-utils";
import type { HighlightRegion } from "@/stores/hex-store";

/**
 * The region lookup runs once per painted cell, so it carries a `maxLength`
 * bound that stops its left-walk early. That bound is an optimisation with a
 * correctness edge: regions are sorted by START offset and may overlap, so an
 * EARLIER region with a larger length can still be the one containing the
 * offset. Cut the walk one step too short and that region silently stops being
 * highlighted — a hit the analyst never sees, with nothing on screen to say so.
 */
function region(offset: number, length: number, label = "r"): HighlightRegion {
  return { offset, length, type: "search", label };
}

describe("getRegionForOffset", () => {
  it("finds a long earlier region that a later short one does not contain", () => {
    const index = buildRegionIndex([region(0, 1000, "long"), region(500, 4, "short")]);
    // 600 is past the short region's end but well inside the long one.
    expect(getRegionForOffset(index, 600)?.label).toBe("long");
  });

  it("prefers the rightmost region that actually contains the offset", () => {
    const index = buildRegionIndex([region(0, 1000, "long"), region(500, 40, "short")]);
    expect(getRegionForOffset(index, 510)?.label).toBe("short");
  });

  it("answers null for an offset no region contains", () => {
    const index = buildRegionIndex([region(0, 4), region(100, 4), region(200, 4)]);
    expect(getRegionForOffset(index, 50)).toBeNull();
    expect(getRegionForOffset(index, 1_000_000)).toBeNull();
  });

  it("answers null for an empty index", () => {
    expect(getRegionForOffset(buildRegionIndex([]), 0)).toBeNull();
  });

  it("records the longest region's length", () => {
    expect(buildRegionIndex([region(0, 3), region(9, 17), region(40, 5)]).maxLength).toBe(17);
    expect(buildRegionIndex([]).maxLength).toBe(0);
  });

  it("includes the first and excludes the last byte of a region", () => {
    const index = buildRegionIndex([region(16, 4)]);
    expect(getRegionForOffset(index, 15)).toBeNull();
    expect(getRegionForOffset(index, 16)).not.toBeNull();
    expect(getRegionForOffset(index, 19)).not.toBeNull();
    expect(getRegionForOffset(index, 20)).toBeNull();
  });
});
