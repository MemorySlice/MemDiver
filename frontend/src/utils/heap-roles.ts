/**
 * The heap byte-role vocabulary, and the window index the hex layer reads.
 *
 * ── Why a packed number per byte ─────────────────────────────────────────────
 * `HexRow` is memoised and asks its getters once per cell on the hot render
 * path. The heap layer therefore answers with ONE primitive per byte — the
 * role code in the low byte, `HEAP_CHUNK_START_BIT` OR-ed in when a chunk
 * starts there — so no object is allocated per cell and the getter's identity
 * is the only thing that has to change when a window arrives.
 *
 * ── Why binary search, not a left-walk ───────────────────────────────────────
 * `highlight-utils` walks left from the byte to find its region, which is fine
 * for key-sized highlights and falls apart on a 100 KiB top chunk. Role runs
 * are non-overlapping and sorted, so the run covering a byte is the LAST run
 * whose start is <= the byte: one `upperBound` over the starts, O(log n).
 */

import type { HeapRoleName, HeapRolesResponse } from "@/api/types";

/** Role codes, matching the backend `heap.model.HeapRole` IntEnum. */
export const HEAP_ROLE_CODE: Readonly<Record<HeapRoleName, number>> = {
  chunk_header: 1,
  user_data: 2,
  free_link: 3,
  free_data: 4,
  allocator_meta: 5,
  top: 6,
  slack: 7,
};

/** No role known here (outside every run, or no window loaded). */
export const HEAP_ROLE_NONE = 0;

/** OR-ed into a packed cell value when a chunk starts at that byte. */
export const HEAP_CHUNK_START_BIT = 0x100;

/** Mask that recovers the role code from a packed cell value. */
export const HEAP_ROLE_MASK = 0xff;

/** The hex-cell ground class each role paints, indexed by role code. */
export const HEAP_ROLE_CLASS: readonly (string | null)[] = [
  null,
  "heap-header",
  "heap-user",
  "heap-freelink",
  "heap-free",
  "heap-meta",
  "heap-top",
  "heap-slack",
];

/** The role name for a code, or `null` (also for MIXED / UNCOVERED). */
export const HEAP_ROLE_NAME_BY_CODE: readonly (HeapRoleName | null)[] = [
  null,
  "chunk_header",
  "user_data",
  "free_link",
  "free_data",
  "allocator_meta",
  "top",
  "slack",
];

/** The tick class a chunk's first byte carries (a box-shadow, not a ground). */
export const HEAP_CHUNK_START_CLASS = "heap-chunk-start";

/**
 * One fetched role window, indexed for lookup. Runs are clipped to
 * `[start, end)`, sorted and non-overlapping; `runStarts` is strictly
 * increasing so it can be binary searched.
 */
export interface RoleWindow {
  start: number;
  end: number;
  runStarts: Float64Array;
  runEnds: Float64Array;
  runCodes: Uint8Array;
  chunkStarts: Float64Array;
  partial: boolean;
  heuristic: boolean;
}

/** Index of the first element of sorted `arr` strictly greater than `x`. */
export function upperBound(arr: ArrayLike<number>, x: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (arr[mid] <= x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * Build a `RoleWindow` from a `/api/heap/roles` answer for `[start, end)`.
 *
 * Defensive about the wire: runs are clipped to the window, sorted, and an
 * overlap (which the backend promises never to send) is resolved in favour of
 * the earlier run so the index stays non-overlapping.
 */
export function buildRoleWindow(
  response: Pick<HeapRolesResponse, "runs" | "chunk_starts" | "partial" | "heuristic">,
  start: number,
  end: number,
): RoleWindow {
  const clipped: { s: number; e: number; code: number }[] = [];
  for (const run of response.runs) {
    const code = HEAP_ROLE_CODE[run.role];
    if (code === undefined) continue;
    const s = Math.max(run.offset, start);
    const e = Math.min(run.offset + run.length, end);
    if (e > s) clipped.push({ s, e, code });
  }
  clipped.sort((a, b) => a.s - b.s);

  const starts: number[] = [];
  const ends: number[] = [];
  const codes: number[] = [];
  let cursor = -Infinity;
  for (const run of clipped) {
    const s = Math.max(run.s, cursor);
    if (run.e <= s) continue;
    starts.push(s);
    ends.push(run.e);
    codes.push(run.code);
    cursor = run.e;
  }

  const chunkStarts = response.chunk_starts
    .filter((o) => o >= start && o < end)
    .sort((a, b) => a - b);

  return {
    start,
    end,
    runStarts: Float64Array.from(starts),
    runEnds: Float64Array.from(ends),
    runCodes: Uint8Array.from(codes),
    chunkStarts: Float64Array.from(chunkStarts),
    partial: response.partial,
    heuristic: response.heuristic,
  };
}

/** The role code at `offset`, or `HEAP_ROLE_NONE`. */
export function roleCodeInWindow(window: RoleWindow, offset: number): number {
  const i = upperBound(window.runStarts, offset) - 1;
  if (i < 0 || offset >= window.runEnds[i]) return HEAP_ROLE_NONE;
  return window.runCodes[i];
}

/** Whether a chunk starts exactly at `offset`. */
export function isChunkStartInWindow(window: RoleWindow, offset: number): boolean {
  const i = upperBound(window.chunkStarts, offset) - 1;
  return i >= 0 && window.chunkStarts[i] === offset;
}

/** The packed cell value (`role | chunk-start bit`) at `offset`. */
export function packedCellInWindow(window: RoleWindow, offset: number): number {
  const code = roleCodeInWindow(window, offset);
  return isChunkStartInWindow(window, offset) ? code | HEAP_CHUNK_START_BIT : code;
}

// ---------------------------------------------------------------------------
// Consensus (aligned-window) role codes — the overlay's `Heap` render mode
// ---------------------------------------------------------------------------

/** `HeapRole.MIXED`: the dumps hold different roles at this byte. */
export const HEAP_ROLE_MIXED = 254;

/** `HeapRole.UNCOVERED`: the byte lies outside every annotated run. */
export const HEAP_ROLE_UNCOVERED = 255;

/** The ground class the MIXED code paints (its own token, `--md-hl-heap-mixed`). */
export const HEAP_MIXED_CLASS = "heap-mixed";

/**
 * The hex-cell ground class for ANY role code — the seven per-dump roles plus
 * the consensus-only MIXED. `null` for none, uncovered and unknown codes, so
 * an unrecognised code paints nothing rather than a guessed colour.
 */
export function heapRoleClassFor(code: number): string | null {
  if (code === HEAP_ROLE_MIXED) return HEAP_MIXED_CLASS;
  return HEAP_ROLE_CLASS[code] ?? null;
}

/** The `heap:roles.*` key suffix a role code reads as, or `null` for none/unknown. */
export type HeapRoleLabel = HeapRoleName | "mixed" | "uncovered";

export function heapRoleLabelFor(code: number): HeapRoleLabel | null {
  if (code === HEAP_ROLE_MIXED) return "mixed";
  if (code === HEAP_ROLE_UNCOVERED) return "uncovered";
  return HEAP_ROLE_NAME_BY_CODE[code] ?? null;
}

/** The legend swatch class each role carries (see hex.css). */
export const HEAP_ROLE_SWATCH: Readonly<Record<HeapRoleName, string>> = {
  chunk_header: "heap-swatch-header",
  user_data: "heap-swatch-user",
  free_link: "heap-swatch-freelink",
  free_data: "heap-swatch-free",
  allocator_meta: "heap-swatch-meta",
  top: "heap-swatch-top",
  slack: "heap-swatch-slack",
};

/** The legend swatch for the consensus-only MIXED code. */
export const HEAP_MIXED_SWATCH = "heap-swatch-mixed";

/** The legend swatch class for any role code, or `null` (none/uncovered/unknown). */
export function heapRoleSwatchFor(code: number): string | null {
  if (code === HEAP_ROLE_MIXED) return HEAP_MIXED_SWATCH;
  const name = HEAP_ROLE_NAME_BY_CODE[code];
  return name ? HEAP_ROLE_SWATCH[name] : null;
}
