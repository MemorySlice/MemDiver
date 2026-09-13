/**
 * Pure layout and chunking math for the N-pane (multi-dump) hex viewer.
 *
 * Deliberately free of React, zustand and the DOM so every rule below can be
 * unit-tested in isolation — the single-dump `./window-utils` follows the same
 * posture, and `BYTES_PER_ROW` is imported from there rather than respelled.
 */

import { BYTES_PER_ROW } from "./window-utils";

/**
 * Hard ceiling on simultaneously rendered panes.
 *
 * Not a styling preference: each pane is an independently virtualized byte
 * grid, and past six the aligned-window response, the per-pane row memoization
 * and the horizontal scroll all degrade at once.
 */
export const MAX_PANES = 6;

/** Fetch granularity, matching the single-dump viewer (512 rows of 16 bytes). */
export const CHUNK_SIZE = 8192;

/**
 * Width of one pane column, in CSS pixels, derived from `frontend/src/styles/hex.css`:
 *
 *   `.hex-offset`   width 76px                     =  76   (offset gutter)
 *   `.hex-byte`     width 22px x 16 bytes per row  = 352   (hex column)
 *   `.hex-separator` width 16px                    =  16   (gutter)
 *   `.hex-char`     width 8px x 16 chars per row   = 128   (ascii column)
 *                                                   ----
 *                                                    572   row CONTENT
 *   `.hex-row`      padding 0 8px (both sides)     =  16
 *                                                   ----
 *                                                    588   pane column
 *
 * The 572 figure is the width of the row's content box. `.hex-row` also carries
 * `padding: 0 8px`, and with the default `box-sizing: border-box` a 572px pane
 * would clip the last ascii character. The exported constant is therefore the
 * full 588px border box; `PANE_ROW_CONTENT_WIDTH_PX` keeps the content figure
 * available for anything that needs to align to the byte grid itself.
 */
export const PANE_ROW_CONTENT_WIDTH_PX = 76 + 22 * BYTES_PER_ROW + 16 + 8 * BYTES_PER_ROW;
export const PANE_COLUMN_WIDTH_PX = PANE_ROW_CONTENT_WIDTH_PX + 16;

/**
 * How many extra chunks to prefetch on each side of the visible rows.
 *
 * Prefetch cost is multiplied by the pane count — every chunk is fetched for
 * every pane — so the margin shrinks as panes are added: 2 chunks up to 2
 * panes, 1 up to 5, 0 from 6 on. Never negative.
 */
export function prefetchChunksForPaneCount(n: number): number {
  return Math.max(0, 2 - Math.floor(n / 3));
}

/**
 * The panes that should actually render: the selected dumps minus the ones the
 * user collapsed, capped at `maxPanes`. Selection order is preserved, because
 * pane order is how the user tells the panes apart.
 */
export function visiblePanes(
  selected: string[],
  collapsed: Set<string>,
  maxPanes: number = MAX_PANES,
): string[] {
  if (maxPanes <= 0) return [];
  const open: string[] = [];
  for (const path of selected) {
    if (collapsed.has(path)) continue;
    open.push(path);
    if (open.length === maxPanes) break;
  }
  return open;
}

/** Align `offset` down to the start of the chunk that contains it. */
export function offsetToChunkStart(offset: number, chunkSize: number = CHUNK_SIZE): number {
  if (offset <= 0) return 0;
  return Math.floor(offset / chunkSize) * chunkSize;
}

/**
 * The chunk starts covering rows `[startRow, endRow]`, widened by
 * `prefetchChunks` on each side and clamped at BOTH ends.
 *
 * `endRow` is INCLUSIVE (it is the last visible row), so the chunk holding its
 * last byte is always included.
 *
 * ── Why the upper clamp is not optional ──────────────────────────────────────
 * `prefetchChunksForPaneCount` widens the range by up to 2 chunks (16 KiB) on
 * each side. Clamping only the low end means that as soon as the user reaches
 * the LAST screen of ANY dump — not just a small one — the loader asks
 * `POST /api/analysis/consensus/aligned-window` for an offset past the end,
 * and the backend correctly answers
 * `400 {"error":"anchor offset does not name an addressable byte"}`.
 * The bytes on screen are fine; the only thing the request produces is an
 * error banner over a perfectly good window.
 *
 * `addressableSize` is the anchor's addressable size IN THE CURRENT VIEW —
 * `hex-store.fileSize`, which tracks raw/VAS/VA — not the file's size on disk.
 * Pass `undefined` (or a non-finite value) when it is genuinely not known yet;
 * that keeps the old, unclamped behaviour rather than silently fetching
 * nothing. A size of `0` means "no addressable byte at all", which is an empty
 * range, not an unknown one.
 */
export function chunkRangeForRows(
  startRow: number,
  endRow: number,
  chunkSize: number = CHUNK_SIZE,
  prefetchChunks = 0,
  addressableSize?: number,
): number[] {
  if (endRow < startRow) return [];
  const limit =
    typeof addressableSize === "number" && Number.isFinite(addressableSize)
      ? addressableSize
      : null;
  if (limit !== null && limit <= 0) return [];
  const margin = Math.max(0, prefetchChunks) * chunkSize;
  const first = Math.max(
    0,
    offsetToChunkStart(Math.max(0, startRow) * BYTES_PER_ROW, chunkSize) - margin,
  );
  let last =
    offsetToChunkStart(Math.max(0, endRow) * BYTES_PER_ROW, chunkSize) + margin;
  if (limit !== null) {
    // The chunk holding the LAST addressable byte; anything beyond it names no
    // byte the anchor holds.
    last = Math.min(last, offsetToChunkStart(limit - 1, chunkSize));
  }
  const starts: number[] = [];
  for (let off = first; off <= last; off += chunkSize) {
    starts.push(off);
  }
  return starts;
}

/**
 * Expand `bytes_valid` runs into a per-byte 0/1 presence mask of `length`.
 *
 * This mask is the ONLY way to tell a genuine `0x00` from a byte the dump does
 * not hold — in a gap the backend also sends `0`. Runs are `[start, runLength]`
 * in window index space; anything outside `[0, length)` is clipped, and
 * adjacent or overlapping runs simply merge (a byte is present or it is not, so
 * marking it twice is not an error).
 */
export function decodeRunsToMask(runs: [number, number][], length: number): Uint8Array {
  const mask = new Uint8Array(Math.max(0, length));
  for (const [start, runLength] of runs) {
    if (runLength <= 0) continue;
    const from = Math.max(0, start);
    const to = Math.min(mask.length, start + runLength);
    for (let i = from; i < to; i++) mask[i] = 1;
  }
  return mask;
}
