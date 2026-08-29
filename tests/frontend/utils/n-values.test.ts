import { describe, expect, it } from "vitest";

import { defaultNValues, parseNValues } from "@/utils/n-values";

describe("parseNValues", () => {
  it("keeps positive integers and trims whitespace", () => {
    expect(parseNValues("1, 3 ,5")).toEqual([1, 3, 5]);
  });

  it("drops blanks so a half-typed list stays usable", () => {
    expect(parseNValues("2,")).toEqual([2]);
    expect(parseNValues("2,,")).toEqual([2]);
    expect(parseNValues("")).toEqual([]);
  });

  it("drops zero, negatives and non-integers instead of yielding NaN", () => {
    expect(parseNValues("0,-1,1.5,abc,4")).toEqual([4]);
  });
});

describe("defaultNValues", () => {
  it("clamps the CLI ladder to the selected dumps and ends on the full fold", () => {
    expect(defaultNValues(2)).toEqual([1, 2]);
    expect(defaultNValues(6)).toEqual([1, 3, 5, 6]);
    expect(defaultNValues(10)).toEqual([1, 3, 5, 10]);
  });

  it("never returns an empty ladder", () => {
    expect(defaultNValues(0)).toEqual([1]);
    expect(defaultNValues(-4)).toEqual([1]);
  });
});
