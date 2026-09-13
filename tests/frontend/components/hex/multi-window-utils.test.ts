import { describe, it, expect } from "vitest";

import {
  CHUNK_SIZE,
  MAX_PANES,
  PANE_COLUMN_WIDTH_PX,
  PANE_ROW_CONTENT_WIDTH_PX,
  chunkRangeForRows,
  decodeRunsToMask,
  offsetToChunkStart,
  prefetchChunksForPaneCount,
  visiblePanes,
} from "@/components/hex/multi-window-utils";

describe("prefetchChunksForPaneCount", () => {
  it("shrinks the prefetch margin as panes are added", () => {
    expect(prefetchChunksForPaneCount(1)).toBe(2);
    expect(prefetchChunksForPaneCount(2)).toBe(2);
    expect(prefetchChunksForPaneCount(3)).toBe(1);
    expect(prefetchChunksForPaneCount(5)).toBe(1);
    expect(prefetchChunksForPaneCount(6)).toBe(0);
    expect(prefetchChunksForPaneCount(12)).toBe(0);
  });

  it("never returns a negative margin", () => {
    expect(prefetchChunksForPaneCount(0)).toBe(2);
    expect(prefetchChunksForPaneCount(99)).toBe(0);
    expect(prefetchChunksForPaneCount(-4)).toBeGreaterThanOrEqual(0);
  });
});

describe("visiblePanes", () => {
  const selected = ["/a", "/b", "/c", "/d"];

  it("drops collapsed panes and preserves selection order", () => {
    expect(visiblePanes(selected, new Set(["/b"]), 10)).toEqual(["/a", "/c", "/d"]);
  });

  it("caps at maxPanes, counting only open panes", () => {
    expect(visiblePanes(selected, new Set(["/a"]), 2)).toEqual(["/b", "/c"]);
  });

  it("returns nothing for a zero or negative cap", () => {
    expect(visiblePanes(selected, new Set(), 0)).toEqual([]);
    expect(visiblePanes(selected, new Set(), -1)).toEqual([]);
  });

  it("defaults the cap to MAX_PANES", () => {
    const many = Array.from({ length: 10 }, (_, i) => `/dump-${i}`);
    expect(visiblePanes(many, new Set())).toHaveLength(MAX_PANES);
  });

  it("returns nothing when everything is collapsed", () => {
    expect(visiblePanes(selected, new Set(selected))).toEqual([]);
  });
});

describe("pane width", () => {
  it("matches the width derived from hex.css", () => {
    // 76 offset gutter + 16 x 22 hex + 16 separator + 16 x 8 ascii
    expect(PANE_ROW_CONTENT_WIDTH_PX).toBe(572);
    // ... plus `.hex-row { padding: 0 8px }` on both sides.
    expect(PANE_COLUMN_WIDTH_PX).toBe(588);
  });
});

describe("offsetToChunkStart", () => {
  it("aligns down to the chunk grid", () => {
    expect(offsetToChunkStart(0, CHUNK_SIZE)).toBe(0);
    expect(offsetToChunkStart(1, CHUNK_SIZE)).toBe(0);
    expect(offsetToChunkStart(CHUNK_SIZE - 1, CHUNK_SIZE)).toBe(0);
    expect(offsetToChunkStart(CHUNK_SIZE, CHUNK_SIZE)).toBe(CHUNK_SIZE);
    expect(offsetToChunkStart(CHUNK_SIZE + 5, CHUNK_SIZE)).toBe(CHUNK_SIZE);
  });

  it("clamps negatives to zero and defaults the chunk size", () => {
    expect(offsetToChunkStart(-1)).toBe(0);
    expect(offsetToChunkStart(CHUNK_SIZE + 1)).toBe(CHUNK_SIZE);
  });
});

describe("chunkRangeForRows", () => {
  it("covers the chunk holding the inclusive last row", () => {
    // Row 512 is the first row of chunk 8192 (512 rows x 16 bytes).
    expect(chunkRangeForRows(0, 511, CHUNK_SIZE, 0)).toEqual([0]);
    expect(chunkRangeForRows(0, 512, CHUNK_SIZE, 0)).toEqual([0, CHUNK_SIZE]);
  });

  it("widens by the prefetch margin on both sides and clamps at zero", () => {
    expect(chunkRangeForRows(512, 512, CHUNK_SIZE, 1)).toEqual([0, CHUNK_SIZE, 2 * CHUNK_SIZE]);
    expect(chunkRangeForRows(0, 0, CHUNK_SIZE, 2)).toEqual([0, CHUNK_SIZE, 2 * CHUNK_SIZE]);
  });

  it("returns nothing for an inverted range", () => {
    expect(chunkRangeForRows(10, 9, CHUNK_SIZE, 2)).toEqual([]);
  });

  it("treats negative rows as row zero", () => {
    expect(chunkRangeForRows(-5, 0, CHUNK_SIZE, 0)).toEqual([0]);
  });

  /**
   * The upper clamp. Without it the prefetch runs off the end of the dump and
   * `POST /api/analysis/consensus/aligned-window` answers
   * 400 "anchor offset does not name an addressable byte" — for bytes nobody
   * is looking at, over a window whose visible rows are perfectly correct.
   */
  describe("bounded by the anchor's addressable size", () => {
    it("leaves a window wholly inside the dump alone", () => {
      // Rows 512..514 sit in chunk 8192 of a 3-chunk dump; the 1-chunk margin
      // fits on both sides, so the clamp changes nothing.
      expect(chunkRangeForRows(512, 514, CHUNK_SIZE, 1, 3 * CHUNK_SIZE)).toEqual([
        0,
        CHUNK_SIZE,
        2 * CHUNK_SIZE,
      ]);
    });

    it("includes the chunk holding the last byte when the size ends ON a boundary", () => {
      // 2 chunks exactly: the last addressable byte is 16383, which lives in
      // chunk 8192. An off-by-one here either drops the dump's last screen or
      // re-introduces the out-of-range request.
      expect(chunkRangeForRows(0, 0, CHUNK_SIZE, 2, 2 * CHUNK_SIZE)).toEqual([
        0,
        CHUNK_SIZE,
      ]);
    });

    it("drops the part of the prefetch that runs past the end", () => {
      // The e2e case: one 8192-byte addressable window, two panes (prefetch 2).
      // Unbounded this asks for 0, 8192 and 16384; only 0 names a byte.
      expect(chunkRangeForRows(0, 10, CHUNK_SIZE, 2)).toEqual([
        0,
        CHUNK_SIZE,
        2 * CHUNK_SIZE,
      ]);
      expect(chunkRangeForRows(0, 10, CHUNK_SIZE, 2, CHUNK_SIZE)).toEqual([0]);
    });

    it("asks for nothing at all when the anchor has no addressable byte", () => {
      expect(chunkRangeForRows(0, 10, CHUNK_SIZE, 2, 0)).toEqual([]);
    });

    it("stays unbounded when the size is not known", () => {
      expect(chunkRangeForRows(0, 0, CHUNK_SIZE, 1, undefined)).toEqual([0, CHUNK_SIZE]);
      expect(chunkRangeForRows(0, 0, CHUNK_SIZE, 1, Number.NaN)).toEqual([0, CHUNK_SIZE]);
    });

    it("returns nothing for a window that starts past the end", () => {
      // Rows 1024+ are in chunk 16384, which a 2-chunk dump does not have.
      expect(chunkRangeForRows(1024, 1024, CHUNK_SIZE, 0, 2 * CHUNK_SIZE)).toEqual([]);
    });
  });
});

describe("decodeRunsToMask", () => {
  it("marks exactly the bytes inside a run", () => {
    expect([...decodeRunsToMask([[2, 3]], 8)]).toEqual([0, 0, 1, 1, 1, 0, 0, 0]);
  });

  it("returns an all-absent mask for no runs", () => {
    const mask = decodeRunsToMask([], 4);
    expect(mask).toHaveLength(4);
    expect([...mask]).toEqual([0, 0, 0, 0]);
  });

  it("merges adjacent runs seamlessly", () => {
    expect([...decodeRunsToMask([[0, 2], [2, 2]], 5)]).toEqual([1, 1, 1, 1, 0]);
  });

  it("is idempotent across overlapping runs", () => {
    expect([...decodeRunsToMask([[0, 4], [1, 2]], 5)]).toEqual([1, 1, 1, 1, 0]);
  });

  it("clips runs that extend past the window", () => {
    expect([...decodeRunsToMask([[2, 99]], 4)]).toEqual([0, 0, 1, 1]);
    expect([...decodeRunsToMask([[-3, 5]], 4)]).toEqual([1, 1, 0, 0]);
  });

  it("ignores empty and negative-length runs", () => {
    expect([...decodeRunsToMask([[1, 0], [2, -4]], 4)]).toEqual([0, 0, 0, 0]);
  });

  /**
   * The shape the backend now produces: one aligned segment whose captured
   * pages are NOT contiguous, so presence arrives as several runs with real
   * holes between them. Reading only the first run (or assuming the runs
   * merge) would mark absent bytes present — and an absent byte reads as `0`,
   * so the error is a confident `00` over a hole in the address space.
   */
  it("keeps the holes between several non-contiguous runs in one segment", () => {
    expect([...decodeRunsToMask([[0, 2], [4, 1], [6, 3]], 10)]).toEqual([
      1, 1, 0, 0, 1, 0, 1, 1, 1, 0,
    ]);
  });

  it("does not care what order the runs arrive in", () => {
    expect([...decodeRunsToMask([[6, 3], [0, 2], [4, 1]], 10)]).toEqual([
      ...decodeRunsToMask([[0, 2], [4, 1], [6, 3]], 10),
    ]);
  });

  it("returns an empty mask for a non-positive length", () => {
    expect(decodeRunsToMask([[0, 4]], 0)).toHaveLength(0);
    expect(decodeRunsToMask([[0, 4]], -2)).toHaveLength(0);
  });
});
