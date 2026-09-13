/**
 * The load failures under the rows the analyst is actually LOOKING AT.
 *
 * Both multi-dump viewers carried a verbatim copy of this, and both copies
 * asked the store about the FIRST and LAST visible row only. A chunk failing
 * anywhere between them — the common case on a tall window, where three or
 * four chunks are on screen at once — raised no banner at all: just a band of
 * `--` in the middle of the grid, with `retryChunkAt` reachable from nowhere.
 *
 * The range walk itself lives in `multi-hex-store.getChunkErrorsInRange`, so
 * the "which chunks are on screen" rule is unit-testable without a DOM; what
 * is left here is the row→offset translation and the sentence.
 */

import { useCallback, useMemo } from "react";
import { useTranslation } from "react-i18next";

import { useMultiHexStore } from "@/stores/multi-hex-store";
import { BYTES_PER_ROW } from "@/components/hex/window-utils";

export interface VisibleWindowError {
  /** A finished sentence for the banner, or `null` when nothing in view failed. */
  error: string | null;
  /** How many distinct chunks under the visible rows failed. */
  failedChunkCount: number;
  /** Re-request every one of them, each with its retry budget reset. */
  retry: () => void;
}

/**
 * `firstRow` / `lastRow` are ABSOLUTE row indices (the viewer's `absRow`), and
 * `lastRow` is inclusive. A negative `firstRow` means "no rows rendered yet".
 */
export function useVisibleWindowError(
  firstRow: number,
  lastRow: number,
): VisibleWindowError {
  const { t } = useTranslation("hex");
  // Subscribing to the MAP, not to a getter: the getters are stable, so a new
  // failure would otherwise never re-render the banner.
  const chunkErrors = useMultiHexStore((s) => s.chunkErrors);

  const hasRows = firstRow >= 0 && lastRow >= firstRow;
  const startOffset = firstRow * BYTES_PER_ROW;
  // The LAST byte of the last row, so the chunk that row ends in is covered.
  const endOffset = lastRow * BYTES_PER_ROW + BYTES_PER_ROW - 1;

  const { error, failedChunkCount } = useMemo(() => {
    void chunkErrors;
    if (!hasRows) return { error: null, failedChunkCount: 0 };
    const failures = useMultiHexStore
      .getState()
      .getChunkErrorsInRange(startOffset, endOffset);
    if (failures.length === 0) return { error: null, failedChunkCount: 0 };
    // One failure is named; several are counted and then named once. Printing
    // every message would bury the retry control under repeated text that is
    // almost always the same sentence anyway.
    const message = failures[0].message;
    return {
      error:
        failures.length === 1
          ? t("multiHex.windowError", { error: message })
          : t("multiHex.windowErrorMany", { chunks: failures.length, error: message }),
      failedChunkCount: failures.length,
    };
  }, [chunkErrors, hasRows, startOffset, endOffset, t]);

  const retry = useCallback(() => {
    if (!hasRows) return;
    useMultiHexStore.getState().retryChunksInRange(startOffset, endOffset);
  }, [hasRows, startOffset, endOffset]);

  return { error, failedChunkCount, retry };
}
