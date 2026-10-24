import { describe, expect, it } from "vitest";

import { decodePageStateRuns, pageStateInRuns } from "@/utils/page-state-runs";

describe("decodePageStateRuns", () => {
  it("decodes wire runs to [start, end) runs", () => {
    expect(
      decodePageStateRuns(
        [
          [0, 16, "FAILED"],
          [16, 32, "UNMAPPED"],
        ],
        64,
      ),
    ).toEqual([
      { start: 0, end: 16, state: "FAILED" },
      { start: 16, end: 48, state: "UNMAPPED" },
    ]);
  });

  it("treats a missing field (older server) as no runs", () => {
    expect(decodePageStateRuns(undefined, 64)).toEqual([]);
  });

  it("drops CAPTURED, unknown states, malformed and empty runs", () => {
    expect(
      decodePageStateRuns(
        [
          [0, 8, "CAPTURED"],
          [8, 8, "BOGUS"],
          [16, 0, "FAILED"],
          ["x", 8, "FAILED"],
          [24, 8, "NOT_RESIDENT"],
        ],
        64,
      ),
    ).toEqual([{ start: 24, end: 32, state: "NOT_RESIDENT" }]);
  });

  it("clips runs to the window and sorts them", () => {
    expect(
      decodePageStateRuns(
        [
          [60, 100, "UNMAPPED"],
          [-4, 8, "FAILED"],
        ],
        64,
      ),
    ).toEqual([
      { start: 0, end: 4, state: "FAILED" },
      { start: 60, end: 64, state: "UNMAPPED" },
    ]);
  });
});

describe("pageStateInRuns", () => {
  const runs = decodePageStateRuns(
    [
      [2048, 8192, "FAILED"],
      [10240, 6144, "UNMAPPED"],
      [20000, 10, "NOT_RESIDENT"],
    ],
    32768,
  );

  it.each([
    [0, undefined],
    [2047, undefined],
    [2048, "FAILED"],
    [10239, "FAILED"],
    [10240, "UNMAPPED"],
    [16383, "UNMAPPED"],
    [16384, undefined],
    [20005, "NOT_RESIDENT"],
    [20010, undefined],
  ])("index %i -> %s", (index, expected) => {
    expect(pageStateInRuns(runs, index)).toBe(expected);
  });

  it("answers undefined over no runs", () => {
    expect(pageStateInRuns([], 0)).toBeUndefined();
  });
});
