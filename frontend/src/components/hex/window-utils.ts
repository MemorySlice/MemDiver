/**
 * Bounded-window virtualization math for the hex viewer.
 *
 * The virtualizer renders a spacer whose pixel height is `count * rowHeight`.
 * For a multi-GB dump the absolute row count (`ceil(fileSize / 16)`) yields a
 * spacer far beyond the browser's maximum element height (~33M px in Chrome,
 * lower elsewhere), which overflows and crashes the renderer. To stay well
 * inside every browser's limit we only ever hand the virtualizer a bounded
 * *window* of rows (`MAX_WINDOW_ROWS`), sliding that window across the file as
 * the user scrolls or jumps. These helpers are pure so they can be unit-tested
 * in isolation — no React, store, or DOM dependencies.
 */

export const BYTES_PER_ROW = 16;

// 500k rows × 20px per row = 10M px, comfortably below every browser's
// maximum element height.
export const MAX_WINDOW_ROWS = 500_000;

// 8192-byte fetch chunk / 16 bytes per row = 512 rows. Aligning window edges
// to this grid keeps the window boundary coincident with the fetch layer's
// chunk boundaries.
export const CHUNK_ROWS = 512;

/**
 * Number of rows the window actually spans: the smaller of the rows remaining
 * from `windowStartRow` and `maxRows`, never negative.
 */
export function windowCount(
  windowStartRow: number,
  totalRows: number,
  maxRows: number = MAX_WINDOW_ROWS,
): number {
  const remaining = totalRows - windowStartRow;
  if (remaining <= 0) return 0;
  return Math.min(remaining, maxRows);
}

/**
 * Clamp a proposed window start into `[0, max(0, totalRows - maxRows)]` so the
 * window never begins before the file or extends past its end.
 */
export function clampWindowStart(
  windowStartRow: number,
  totalRows: number,
  maxRows: number = MAX_WINDOW_ROWS,
): number {
  const maxStart = Math.max(0, totalRows - maxRows);
  if (windowStartRow < 0) return 0;
  if (windowStartRow > maxStart) return maxStart;
  return windowStartRow;
}

/**
 * Compute a window start that centers `targetRow` within a `maxRows` window,
 * aligned down to the `chunkRows` fetch grid, then clamped into valid bounds.
 *
 * Guarantees that `targetRow` always lands inside the resulting window (see
 * `isRowInWindow`), which the viewer's scroll effect relies on to terminate.
 */
export function recenterWindow(
  targetRow: number,
  totalRows: number,
  maxRows: number = MAX_WINDOW_ROWS,
  chunkRows: number = CHUNK_ROWS,
): number {
  const centered = targetRow - Math.floor(maxRows / 2);
  const aligned = Math.floor(centered / chunkRows) * chunkRows;
  return clampWindowStart(aligned, totalRows, maxRows);
}

/**
 * True when `row` falls inside the window `[windowStartRow, windowStartRow + count)`.
 */
export function isRowInWindow(
  row: number,
  windowStartRow: number,
  count: number,
): boolean {
  return row >= windowStartRow && row < windowStartRow + count;
}
