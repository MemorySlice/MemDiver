import { describe, it, expect } from "vitest";

import {
  BYTES_PER_ROW,
  MAX_WINDOW_ROWS,
  CHUNK_ROWS,
  windowCount,
  clampWindowStart,
  recenterWindow,
  isRowInWindow,
} from "@/components/hex/window-utils";

describe("constants", () => {
  it("holds the expected grid sizes", () => {
    expect(BYTES_PER_ROW).toBe(16);
    expect(MAX_WINDOW_ROWS).toBe(500_000);
    expect(CHUNK_ROWS).toBe(512);
  });
});

describe("windowCount", () => {
  it("returns 0 for an empty file", () => {
    expect(windowCount(0, 0)).toBe(0);
  });

  it("returns 0 when the start is at or past the end", () => {
    expect(windowCount(100, 100)).toBe(0);
    expect(windowCount(200, 100)).toBe(0);
  });

  it("returns the remaining rows for a small file", () => {
    expect(windowCount(0, 100)).toBe(100);
    expect(windowCount(40, 100)).toBe(60);
  });

  it("clamps to maxRows for a large file", () => {
    const total = 134_217_728; // 2 GB
    expect(windowCount(0, total)).toBe(MAX_WINDOW_ROWS);
    expect(windowCount(1_000_000, total)).toBe(MAX_WINDOW_ROWS);
  });

  it("shrinks to the tail near the end of a large file", () => {
    const total = 1_000_000;
    // maxRows default 500k; start 700k leaves only 300k rows.
    expect(windowCount(700_000, total)).toBe(300_000);
  });

  it("respects an explicit maxRows override", () => {
    expect(windowCount(0, 100, 10)).toBe(10);
    expect(windowCount(95, 100, 10)).toBe(5);
  });
});

describe("clampWindowStart", () => {
  it("clamps negatives to 0", () => {
    expect(clampWindowStart(-5, 1000)).toBe(0);
  });

  it("clamps small files to 0 (window covers the whole file)", () => {
    expect(clampWindowStart(0, 100)).toBe(0);
    expect(clampWindowStart(50, 100)).toBe(0);
  });

  it("clamps to totalRows - maxRows for large files", () => {
    const total = 1_000_000;
    const maxStart = total - MAX_WINDOW_ROWS; // 500_000
    expect(clampWindowStart(999_999, total)).toBe(maxStart);
    expect(clampWindowStart(maxStart, total)).toBe(maxStart);
    expect(clampWindowStart(123_456, total)).toBe(123_456);
  });

  it("handles totalRows === maxRows (maxStart 0)", () => {
    expect(clampWindowStart(100, MAX_WINDOW_ROWS)).toBe(0);
  });

  it("respects an explicit maxRows override", () => {
    expect(clampWindowStart(95, 100, 10)).toBe(90);
    expect(clampWindowStart(5, 100, 10)).toBe(5);
  });
});

describe("isRowInWindow", () => {
  it("includes the lower boundary and excludes the upper boundary", () => {
    expect(isRowInWindow(10, 10, 5)).toBe(true); // start
    expect(isRowInWindow(14, 10, 5)).toBe(true); // last in window
    expect(isRowInWindow(15, 10, 5)).toBe(false); // one past
    expect(isRowInWindow(9, 10, 5)).toBe(false); // one before
  });

  it("is always false for an empty window", () => {
    expect(isRowInWindow(0, 0, 0)).toBe(false);
    expect(isRowInWindow(5, 5, 0)).toBe(false);
  });
});

describe("recenterWindow", () => {
  it("returns 0 for an empty file", () => {
    expect(recenterWindow(0, 0)).toBe(0);
  });

  const assertChunkAligned = (start: number, totalRows: number, maxRows = MAX_WINDOW_ROWS) => {
    const maxStart = Math.max(0, totalRows - maxRows);
    // Aligned to the chunk grid, OR clamped to the (possibly non-aligned) end.
    expect(start % CHUNK_ROWS === 0 || start === maxStart).toBe(true);
  };

  it("keeps the target inside the window across a target/total matrix", () => {
    const totals = [
      0,
      1,
      100,
      MAX_WINDOW_ROWS - 1,
      MAX_WINDOW_ROWS,
      MAX_WINDOW_ROWS + 1,
      1_000_000,
      134_217_728, // 2 GB
    ];
    for (const total of totals) {
      if (total === 0) {
        // No valid targets in an empty file; recenter must still be safe.
        const start = recenterWindow(0, total);
        expect(windowCount(start, total)).toBe(0);
        continue;
      }
      const targets = [0, Math.floor(total / 2), total - 1];
      for (const target of targets) {
        const start = recenterWindow(target, total);
        const count = windowCount(start, total);
        expect(count).toBeGreaterThan(0);
        expect(isRowInWindow(target, start, count)).toBe(true);
        assertChunkAligned(start, total);
      }
    }
  });

  it("centers the target for a large file, chunk-aligned", () => {
    const total = 134_217_728;
    const target = 50_000_000;
    const start = recenterWindow(target, total);
    // Roughly centered: target - maxRows/2, aligned down to the chunk grid.
    const expected =
      Math.floor((target - Math.floor(MAX_WINDOW_ROWS / 2)) / CHUNK_ROWS) *
      CHUNK_ROWS;
    expect(start).toBe(expected);
    expect(start % CHUNK_ROWS).toBe(0);
    expect(isRowInWindow(target, start, windowCount(start, total))).toBe(true);
  });

  it("clamps to the start near the beginning of a large file", () => {
    const total = 134_217_728;
    const start = recenterWindow(10, total);
    expect(start).toBe(0);
    expect(isRowInWindow(10, start, windowCount(start, total))).toBe(true);
  });

  it("clamps to the end near the end of a large file, target still inside", () => {
    const total = 134_217_728;
    const target = total - 1;
    const start = recenterWindow(target, total);
    expect(start).toBe(total - MAX_WINDOW_ROWS);
    expect(isRowInWindow(target, start, windowCount(start, total))).toBe(true);
  });

  it("holds the invariant with a small maxRows override", () => {
    const total = 100;
    const maxRows = 10;
    const chunkRows = 4;
    for (let target = 0; target < total; target++) {
      const start = recenterWindow(target, total, maxRows, chunkRows);
      const count = windowCount(start, total, maxRows);
      expect(isRowInWindow(target, start, count)).toBe(true);
      const maxStart = Math.max(0, total - maxRows);
      expect(start % chunkRows === 0 || start === maxStart).toBe(true);
    }
  });
});
