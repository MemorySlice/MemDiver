/**
 * Moving the hex viewer to a heap location.
 *
 * Offsets the heap API returns in a view's coordinate (`view_offset`) go
 * straight to `hex-store.scrollToOffset`, the same jump bookmarks, search and
 * the candidate panel use. A bare virtual address (a region start, a
 * free-list entry) is first translated by `/api/heap/chunk-at`, which answers
 * `view_offset` for any mapped VA in the requested view, inside a chunk or not.
 */

import { fetchHeapChunkAt } from "@/api/heap";
import { useDumpStore } from "@/stores/dump-store";
import { useHeapStore } from "@/stores/heap-store";
import { useHexStore } from "@/stores/hex-store";

/** Scroll the hex viewer to `offset` in its current view and put the cursor there. */
export function jumpHexToViewOffset(offset: number | null | undefined): boolean {
  if (offset === null || offset === undefined || offset < 0) return false;
  useHexStore.getState().scrollToOffset(offset);
  return true;
}

/**
 * Translate `va` into the hex viewer's current view and jump there.
 * Resolves `false` when the address is not mapped in that view.
 */
export async function jumpHexToVa(dumpPath: string, va: number): Promise<boolean> {
  const view = useHexStore.getState().viewMode;
  const entry = useHeapStore.getState().dumps[dumpPath];
  const response = await fetchHeapChunkAt({
    dumpPath,
    allocator: entry?.allocator,
    key: useDumpStore.getState().getKeyMaterialByPath(dumpPath),
    va,
    view,
  });
  return jumpHexToViewOffset(response.view_offset);
}
