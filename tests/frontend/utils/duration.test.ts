import { describe, it, expect } from "vitest";

import { splitDuration } from "@/utils/duration";

describe("splitDuration", () => {
  it("splits a sub-minute duration into seconds only", () => {
    expect(splitDuration(0.5)).toEqual({ h: 0, m: 0, s: 0 });
    expect(splitDuration(1)).toEqual({ h: 0, m: 0, s: 1 });
    expect(splitDuration(59)).toEqual({ h: 0, m: 0, s: 59 });
  });

  it("carries into minutes and hours", () => {
    expect(splitDuration(60)).toEqual({ h: 0, m: 1, s: 0 });
    expect(splitDuration(3599)).toEqual({ h: 0, m: 59, s: 59 });
    expect(splitDuration(3600)).toEqual({ h: 1, m: 0, s: 0 });
    expect(splitDuration(3661)).toEqual({ h: 1, m: 1, s: 1 });
  });

  it("floors a fractional ETA instead of leaking decimals", () => {
    // 701084 candidates left at 256/sec -- the real brute-force shape.
    expect(splitDuration(2738.4)).toEqual({ h: 0, m: 45, s: 38 });
  });

  it("collapses zero, negative and non-finite inputs to all zeros", () => {
    expect(splitDuration(0)).toEqual({ h: 0, m: 0, s: 0 });
    expect(splitDuration(-10)).toEqual({ h: 0, m: 0, s: 0 });
    expect(splitDuration(Number.NaN)).toEqual({ h: 0, m: 0, s: 0 });
    expect(splitDuration(Number.POSITIVE_INFINITY)).toEqual({ h: 0, m: 0, s: 0 });
  });

  it("handles multi-hour durations without wrapping", () => {
    expect(splitDuration(10 * 3600 + 2 * 60 + 3)).toEqual({ h: 10, m: 2, s: 3 });
  });
});
