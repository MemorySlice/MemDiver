/**
 * The hex viewer's seam onto the heap role layer.
 *
 * Returns the per-byte getter `HexRow` consumes (`getHeapCellAt`), or
 * `undefined` while the layer is off — so a viewer that never enables it pays
 * nothing and its rows' memo props are unchanged.
 *
 * The getter answers a PACKED primitive (`role | HEAP_CHUNK_START_BIT`, see
 * `@/utils/heap-roles`) and reads the store through `getState()`; its identity
 * rotates only when `roleWindowsVersion` moves, which is exactly when a row's
 * answer can have changed. Same pattern as `HexViewer.getByteAtStable` and
 * `chunkVersion`.
 *
 * Fetching is a side effect of WHAT IS ON SCREEN, so it lives in an effect;
 * everything the render reads is derived from store state during render.
 */

import { useCallback, useEffect } from "react";

import type { DumpViewMode } from "@/api/client";
import { selectHeapLayerEnabled, useHeapStore } from "@/stores/heap-store";

export interface HeapLayerRange {
  dumpPath: string;
  view: DumpViewMode;
  /** First visible byte offset (inclusive), or < 0 while nothing is laid out. */
  firstOffset: number;
  /** One past the last visible byte. */
  endOffset: number;
}

export function useHeapLayer({
  dumpPath,
  view,
  firstOffset,
  endOffset,
}: HeapLayerRange): ((offset: number) => number) | undefined {
  const enabled = useHeapStore(selectHeapLayerEnabled(dumpPath));
  const version = useHeapStore((s) => s.roleWindowsVersion);

  useEffect(() => {
    if (!enabled || firstOffset < 0) return;
    void useHeapStore.getState().ensureRoleWindows(dumpPath, view, firstOffset, endOffset);
  }, [enabled, dumpPath, view, firstOffset, endOffset]);

  const getHeapCellAt = useCallback(
    (offset: number): number => {
      void version;
      return useHeapStore.getState().heapCellAt(dumpPath, view, offset);
    },
    [version, dumpPath, view],
  );

  return enabled ? getHeapCellAt : undefined;
}
