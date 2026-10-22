import type { HexViewMode } from "@/stores/hex-store";

/** i18n keys (namespace "misc") naming each hex view next to the offset input. */
export const VIEW_LABEL_KEYS: Record<HexViewMode, string> = {
  raw: "verification.viewRaw",
  vas: "verification.viewVas",
  va: "verification.viewVa",
};

interface RequestViewInput {
  typedOffset: boolean;
  prefillFromViewer: boolean;
  hasDistinctViews: boolean;
  viewMode: HexViewMode;
}

/**
 * The view the verify request reads its offset in. A cursor/selection prefill
 * is a number in the viewer's current view, so it always carries that view.
 * A typed offset follows the viewer too when the dump has several distinct
 * views; on a single-view dump it sends none (the backend default).
 */
export function resolveRequestView({
  typedOffset,
  prefillFromViewer,
  hasDistinctViews,
  viewMode,
}: RequestViewInput): HexViewMode | undefined {
  if (!typedOffset && prefillFromViewer) return viewMode;
  return hasDistinctViews ? viewMode : undefined;
}
