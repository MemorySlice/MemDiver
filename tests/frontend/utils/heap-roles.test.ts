import { describe, expect, it } from "vitest";

import {
  HEAP_CHUNK_START_BIT,
  HEAP_ROLE_CODE,
  HEAP_ROLE_NONE,
  buildRoleWindow,
  isChunkStartInWindow,
  packedCellInWindow,
  roleCodeInWindow,
  upperBound,
} from "@/utils/heap-roles";
import type { HeapRoleRun } from "@/api/types";

function win(runs: HeapRoleRun[], chunkStarts: number[] = [], start = 0, end = 0x10000) {
  return buildRoleWindow({ runs, chunk_starts: chunkStarts, partial: false, heuristic: false }, start, end);
}

describe("upperBound", () => {
  it("finds the first element strictly greater", () => {
    const a = [0, 16, 32];
    expect(upperBound(a, -1)).toBe(0);
    expect(upperBound(a, 0)).toBe(1);
    expect(upperBound(a, 15)).toBe(1);
    expect(upperBound(a, 16)).toBe(2);
    expect(upperBound(a, 99)).toBe(3);
    expect(upperBound([], 5)).toBe(0);
  });
});

describe("role lookup by binary search", () => {
  const w = win(
    [
      { offset: 0, length: 16, role: "chunk_header" },
      { offset: 16, length: 48, role: "user_data" },
      // A gap at [64, 80), then a huge top chunk.
      { offset: 80, length: 0x8000, role: "top" },
    ],
    [0, 80],
  );

  it("answers the run boundaries exactly", () => {
    expect(roleCodeInWindow(w, 0)).toBe(HEAP_ROLE_CODE.chunk_header);
    expect(roleCodeInWindow(w, 15)).toBe(HEAP_ROLE_CODE.chunk_header);
    expect(roleCodeInWindow(w, 16)).toBe(HEAP_ROLE_CODE.user_data);
    expect(roleCodeInWindow(w, 63)).toBe(HEAP_ROLE_CODE.user_data);
  });

  it("reports no role in a gap and past the last run", () => {
    expect(roleCodeInWindow(w, 64)).toBe(HEAP_ROLE_NONE);
    expect(roleCodeInWindow(w, 79)).toBe(HEAP_ROLE_NONE);
    expect(roleCodeInWindow(w, 80 + 0x8000)).toBe(HEAP_ROLE_NONE);
  });

  it("answers deep inside a huge run without walking", () => {
    expect(roleCodeInWindow(w, 80 + 0x7fff)).toBe(HEAP_ROLE_CODE.top);
  });

  it("marks chunk starts only on their first byte", () => {
    expect(isChunkStartInWindow(w, 0)).toBe(true);
    expect(isChunkStartInWindow(w, 1)).toBe(false);
    expect(isChunkStartInWindow(w, 80)).toBe(true);
    expect(packedCellInWindow(w, 80)).toBe(HEAP_ROLE_CODE.top | HEAP_CHUNK_START_BIT);
    expect(packedCellInWindow(w, 81)).toBe(HEAP_ROLE_CODE.top);
  });
});

describe("buildRoleWindow", () => {
  it("clips runs to the window and sorts them", () => {
    const w = win(
      [
        { offset: 200, length: 100, role: "free_data" },
        { offset: 50, length: 100, role: "user_data" },
      ],
      [300, 10, 50],
      100,
      250,
    );
    expect([...w.runStarts]).toEqual([100, 200]);
    expect([...w.runEnds]).toEqual([150, 250]);
    expect([...w.chunkStarts]).toEqual([]);
    expect(roleCodeInWindow(w, 99)).toBe(HEAP_ROLE_NONE);
    expect(roleCodeInWindow(w, 249)).toBe(HEAP_ROLE_CODE.free_data);
  });

  it("resolves an overlap in favour of the earlier run", () => {
    const w = win([
      { offset: 0, length: 32, role: "chunk_header" },
      { offset: 16, length: 32, role: "user_data" },
    ]);
    expect(roleCodeInWindow(w, 20)).toBe(HEAP_ROLE_CODE.chunk_header);
    expect(roleCodeInWindow(w, 32)).toBe(HEAP_ROLE_CODE.user_data);
  });

  it("drops runs carrying an unknown role", () => {
    const w = win([{ offset: 0, length: 8, role: "bogus" as HeapRoleRun["role"] }]);
    expect(w.runStarts.length).toBe(0);
  });
});

describe("consensus role codes (overlay heap mode)", () => {
  it("paints MIXED with its own ground class and swatch", async () => {
    const m = await import("@/utils/heap-roles");
    expect(m.heapRoleClassFor(m.HEAP_ROLE_MIXED)).toBe("heap-mixed");
    expect(m.heapRoleSwatchFor(m.HEAP_ROLE_MIXED)).toBe("heap-swatch-mixed");
    expect(m.heapRoleLabelFor(m.HEAP_ROLE_MIXED)).toBe("mixed");
  });

  it("paints nothing for none, uncovered and unknown codes", async () => {
    const m = await import("@/utils/heap-roles");
    for (const code of [m.HEAP_ROLE_NONE, m.HEAP_ROLE_UNCOVERED, 99]) {
      expect(m.heapRoleClassFor(code)).toBeNull();
      expect(m.heapRoleSwatchFor(code)).toBeNull();
    }
    expect(m.heapRoleLabelFor(m.HEAP_ROLE_UNCOVERED)).toBe("uncovered");
    expect(m.heapRoleLabelFor(m.HEAP_ROLE_NONE)).toBeNull();
    expect(m.heapRoleLabelFor(99)).toBeNull();
  });

  it("maps the seven roles to the same classes as the per-dump layer", async () => {
    const m = await import("@/utils/heap-roles");
    for (const [name, code] of Object.entries(m.HEAP_ROLE_CODE)) {
      expect(m.heapRoleClassFor(code)).toBe(m.HEAP_ROLE_CLASS[code]);
      expect(m.heapRoleLabelFor(code)).toBe(name);
      expect(m.heapRoleSwatchFor(code)).toBe(
        m.HEAP_ROLE_SWATCH[name as keyof typeof m.HEAP_ROLE_SWATCH],
      );
    }
  });
});
