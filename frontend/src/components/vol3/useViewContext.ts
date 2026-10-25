import { useCallback, useEffect, useRef, useState } from "react";

import { previewImport } from "@/api/client";
import type { ImportPreview, PageStateInterval } from "@/api/types";
import { getVasNavigationMap, type Vol3RunResult, type Vol3ViewBlock } from "@/api/vol3";
import { useHexStore } from "@/stores/hex-store";
import type { ImageViewKind, ViewContext } from "./vol3-navigation";

/**
 * Flatten the page-state regions into one interval list (all CAPTURED/other states).
 * Lossless and `view=vas`: a kernel view refuses the default `va` request and its
 * VAs exceed 2^53 (`va` may be a decimal string; `resolveOffset` reads it with BigInt).
 */
async function fetchIntervals(viewPath: string): Promise<PageStateInterval[]> {
  const data = await getVasNavigationMap(viewPath);
  return data.regions.flatMap((region) => region.intervals);
}

/**
 * Where the hex viewer is, for address translation: the active `.mdview`'s kind
 * (from the import preview), the viewer's mode and span, and a lazy loader of the
 * page-state intervals the packed `vas` view needs. The pid is the descriptor's
 * own (`view.pid`), else what the latest run revealed.
 */
export function useViewContext(viewPath: string, result: Vol3RunResult | null) {
  const [known, setKnown] = useState<{
    path: string; kind: ImageViewKind | null; view: Vol3ViewBlock | null;
  } | null>(null);
  const mode = useHexStore((s) => s.viewMode);
  const vaSpanStart = useHexStore((s) => s.vaSpanStart);
  const vaSize = useHexStore((s) => s.vaSize);
  const pageStatesLoaded = useHexStore((s) => s.pageStatesLoaded);
  const intervals = useRef<{ path: string; list: PageStateInterval[] } | null>(null);

  useEffect(() => {
    if (!viewPath) return;
    let cancelled = false;
    previewImport(viewPath)
      .then((p) => { if (!cancelled) setKnown({ path: viewPath, kind: p.view_kind ?? null, view: viewOf(p) }); })
      .catch(() => { if (!cancelled) setKnown({ path: viewPath, kind: null, view: null }); });
    return () => { cancelled = true; };
  }, [viewPath]);

  const loadIntervals = useCallback(async (): Promise<PageStateInterval[] | null> => {
    if (!viewPath) return null;
    if (intervals.current?.path !== viewPath) {
      try {
        intervals.current = { path: viewPath, list: await fetchIntervals(viewPath) };
      } catch {
        return null;
      }
    }
    return intervals.current.list;
  }, [viewPath]);

  // A kind learned for another view is stale: never reuse it for this one.
  const current = known?.path === viewPath ? known : null;
  const kind = current?.kind ?? null;
  const view = current?.view ?? null;
  const ctx: ViewContext = {
    kind, pid: kind === "process" ? viewPidOf(view, result, viewPath) : null, mode, vaSpanStart, vaSize, pageStatesLoaded,
  };
  return { ctx, loadIntervals, view };
}

const viewOf = (preview: ImportPreview): Vol3ViewBlock | null => preview.view ?? null;

/**
 * The process view's pid: the descriptor's own (`view.pid`, from the preview or a
 * run answer for THIS view), else the single pid a backend default filled in.
 */
export function viewPidOf(
  previewView: Vol3ViewBlock | null, result: Vol3RunResult | null, viewPath: string,
): number | null {
  const own = result?.view && result.view.view_path === viewPath ? result.view : null;
  return previewView?.pid ?? own?.pid ?? viewPidFrom(result?.defaults_applied);
}

/** The single pid a backend default filled into a pid-list argument, else `null`. */
export function viewPidFrom(defaults: Record<string, unknown> | undefined): number | null {
  for (const name of ["pid", "pids"]) {
    const value = defaults?.[name];
    if (Array.isArray(value) && value.length === 1 && Number.isSafeInteger(value[0])) {
      return value[0] as number;
    }
  }
  return null;
}
