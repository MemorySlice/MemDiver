import { useEffect, useState } from "react";

import { previewImport } from "@/api/client";
import { isMdview } from "@/components/image/open-view-in-workspace";

/** What an `.mdview` descriptor exposes: its kind and (process views) pid. */
export interface ImageViewBadge {
  kind: "process" | "kernel" | "physical";
  pid: number | null;
}

const known = new Map<string, ImageViewBadge | null>();

/** Forget cached kinds (tests; a descriptor rewritten under the same path). */
export const clearImageViewBadges = () => known.clear();

/**
 * The view kind of an `.mdview` path, from the import preview's `view` block
 * (`view_kind` as a fallback). `null` for any other path, while the preview is
 * in flight, or when it fails — callers then keep showing the file format.
 */
export function useImageViewBadge(path: string): ImageViewBadge | null {
  const [, bump] = useState(0);
  const wanted = isMdview(path);

  useEffect(() => {
    if (!wanted || known.has(path)) return;
    let cancelled = false;
    Promise.resolve()
      .then(() => previewImport(path))
      .then((p) => {
        const kind = p.view?.kind ?? p.view_kind ?? null;
        known.set(path, kind ? { kind, pid: p.view?.pid ?? null } : null);
      })
      .catch(() => known.set(path, null))
      .finally(() => { if (!cancelled) bump((n) => n + 1); });
    return () => { cancelled = true; };
  }, [path, wanted]);

  return wanted ? known.get(path) ?? null : null;
}
