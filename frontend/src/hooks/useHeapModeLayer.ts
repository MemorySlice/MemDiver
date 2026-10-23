/**
 * Heap mode paints the heap layer on the active dump.
 *
 * Which dump that is (if any) is DERIVED during render from the app mode and
 * the active dump; the effect only mirrors that answer into the heap store,
 * which is an external system to this component (writing another store's
 * state during render would update its other subscribers mid-render). The
 * cleanup turns the layer off again when heap mode is left or the active dump
 * changes, so the layer follows the mode instead of lingering in exploration.
 * The hex toolbar's toggle still lets the user hide it while in heap mode.
 *
 * An `.msl`'s "raw" view is the file container, not memory: the backend maps
 * no chunk into it (`heap/memory.py` `_raw_runs`), so the layer would paint
 * nothing and a chunk-row click would have nowhere to jump. Entering heap mode
 * on an `.msl` in that view therefore shows the flat memory ("vas") view,
 * via `showView` so the user's persisted view preference is left untouched.
 */

import { useEffect } from "react";

import { useAppStore } from "@/stores/app-store";
import { useHeapStore } from "@/stores/heap-store";
import { useHexStore } from "@/stores/hex-store";

export function useHeapModeLayer(activeDumpPath: string | null | undefined): void {
  const heapMode = useAppStore((s) => s.mode === "heap");
  const target = heapMode && activeDumpPath ? activeDumpPath : null;

  useEffect(() => {
    if (!target) return;
    useHeapStore.getState().setLayerEnabled(target, true);
    showHeapMemoryView();
    return () => useHeapStore.getState().setLayerEnabled(target, false);
  }, [target]);
}

/** Leave an `.msl`'s container ("raw") view for its memory ("vas") view. */
export function showHeapMemoryView(): void {
  const hex = useHexStore.getState();
  const isMsl = hex.format === "msl" || hex.detectedFormat === "msl";
  if (isMsl && hex.viewMode === "raw") hex.showView("vas");
}
