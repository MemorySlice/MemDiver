import { useEffect, useSyncExternalStore } from "react";

import { previewImport } from "@/api/client";
import type { ImageViewFacts, ImportPreview } from "@/api/types";

/** The state of one view's facts request: not asked, in flight, answered, or failed. */
export type ImageViewFactsState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; preview: ImportPreview };

const IDLE: ImageViewFactsState = { status: "idle" };
const entries = new Map<string, ImageViewFactsState>();
const listeners = new Set<() => void>();
const notify = () => listeners.forEach((listener) => listener());
const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
};

/**
 * Forget the cached facts of one view (its descriptor was rewritten under the same
 * path), or of every view. Mounted users re-request.
 */
export function invalidateImageViewFacts(path?: string): void {
  if (path === undefined) entries.clear();
  else entries.delete(path);
  notify();
}

function request(path: string): void {
  const pending: ImageViewFactsState = { status: "loading" };
  entries.set(path, pending);
  const settle = (next: ImageViewFactsState) => {
    // A newer request (after an invalidation) owns the entry now.
    if (entries.get(path) === pending) { entries.set(path, next); notify(); }
  };
  Promise.resolve()
    .then(() => previewImport(path))
    .then((preview) => settle({ status: "ready", preview }))
    .catch(() => settle({ status: "error" }));
}

/** The view block of a ready answer, else `null` (not ready, or an older server without one). */
export const viewFactsOf = (state: ImageViewFactsState): ImageViewFacts | null =>
  state.status === "ready" ? state.preview.view ?? null : null;

/**
 * The one source of truth for an `.mdview`'s facts: the import preview's `view`
 * block, fetched once per path (module-level cache, in-flight requests shared)
 * and read by the badge, the view context, the Image panel and the ISF builder.
 * An empty path is `idle` and requests nothing.
 */
export function useImageViewFacts(path: string): ImageViewFactsState {
  const state = useSyncExternalStore(subscribe, () => (path ? entries.get(path) : undefined));
  useEffect(() => {
    if (path && !entries.has(path)) request(path);
  }, [path, state]);
  return path ? state ?? { status: "loading" } : IDLE;
}
