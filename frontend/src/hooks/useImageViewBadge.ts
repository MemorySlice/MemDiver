import { isMdview } from "@/components/image/open-view-in-workspace";
import { invalidateImageViewFacts, useImageViewFacts } from "./useImageViewFacts";

/** What an `.mdview` descriptor exposes: its kind and (process views) pid. */
export interface ImageViewBadge {
  kind: "process" | "kernel" | "physical";
  pid: number | null;
}

/** Forget cached view facts (tests; a descriptor rewritten under the same path). */
export const clearImageViewBadges = () => invalidateImageViewFacts();

/**
 * The view kind of an `.mdview` path, from the shared view facts (the import
 * preview's `view` block, `view_kind` as a fallback). `null` for any other path,
 * while the preview is in flight, or when it fails — callers then keep showing
 * the file format.
 */
export function useImageViewBadge(path: string): ImageViewBadge | null {
  const state = useImageViewFacts(isMdview(path) ? path : "");
  if (state.status !== "ready") return null;
  const { preview } = state;
  const kind = preview.view?.kind ?? preview.view_kind ?? null;
  return kind ? { kind, pid: preview.view?.pid ?? null } : null;
}
