/**
 * Fetch-on-show for the heap panels.
 *
 * Each hook asks the heap store for one resource the first time a panel needs
 * it for a dump (status `"idle"`): the store owns the request, its staleness
 * guard and the cached answer, so mounting several panels never duplicates a
 * request and a changed allocator (which resets the entry to idle) refetches.
 */

import { useEffect } from "react";

import { selectHeapDump, useHeapStore, type HeapDumpEntry } from "@/stores/heap-store";

type StatusField = "detectionStatus" | "summaryStatus" | "freeListsStatus";

/**
 * Re-read the LIVE status: two panels mounting in one commit both rendered
 * "idle", but the first effect's request has already flipped it to loading.
 */
function stillIdle(dumpPath: string, field: StatusField): boolean {
  const entry: Readonly<HeapDumpEntry> = selectHeapDump(dumpPath)(useHeapStore.getState());
  return entry[field] === "idle";
}

/** Detection + summary for `dumpPath` (both overview and panel read them). */
export function useHeapOverviewData(dumpPath: string): void {
  const detectionStatus = useHeapStore((s) => selectHeapDump(dumpPath)(s).detectionStatus);
  const summaryStatus = useHeapStore((s) => selectHeapDump(dumpPath)(s).summaryStatus);

  useEffect(() => {
    if (!dumpPath || detectionStatus !== "idle" || !stillIdle(dumpPath, "detectionStatus")) return;
    void useHeapStore.getState().loadDetection(dumpPath);
  }, [dumpPath, detectionStatus]);

  useEffect(() => {
    if (!dumpPath || summaryStatus !== "idle" || !stillIdle(dumpPath, "summaryStatus")) return;
    void useHeapStore.getState().loadSummary(dumpPath);
  }, [dumpPath, summaryStatus]);
}

/** Free lists for `dumpPath`, once the free-list view is shown. */
export function useHeapFreeListData(dumpPath: string): void {
  const status = useHeapStore((s) => selectHeapDump(dumpPath)(s).freeListsStatus);
  useEffect(() => {
    if (!dumpPath || status !== "idle" || !stillIdle(dumpPath, "freeListsStatus")) return;
    void useHeapStore.getState().loadFreeLists(dumpPath);
  }, [dumpPath, status]);
}
