import { create } from "zustand";

/**
 * How the aligned overlay PAINTS its one byte stream.
 *
 * ── Why this is its own store ────────────────────────────────────────────────
 * It is deliberately not a field on any of the three stores it sits next to:
 *
 *   - `consensus-store` already carries four unrelated jobs and is shared with
 *     the single-dump viewer, which has no N-dump variant count to render.
 *   - `multi-hex-store` is a byte cache. Putting a view preference in it would
 *     make every mode click invalidate the subscribers of a chunk map.
 *   - `dump-store` answers "which dumps, in what layout"; this answers "how are
 *     the bytes of ONE pane coloured", a strictly narrower question that only
 *     the overlay asks.
 *
 * So: one field, one setter, one `reset` — small enough that a selector read is
 * always a single field, which is what `scripts/check-store-selectors.mjs`
 * wants, and cheap enough that switching the mode re-renders the overlay and
 * nothing else.
 */

export const OVERLAY_RENDER_MODES = ["class", "variants", "glyph", "heap"] as const;

export type OverlayRenderMode = (typeof OVERLAY_RENDER_MODES)[number];

/**
 * `class` is the default on purpose. It is the reading the backend consensus
 * actually computed; the other two are client-side re-descriptions of the same
 * window, useful but weaker, and a viewer that opened on one of them would show
 * a colour the consensus never produced.
 */
export const DEFAULT_OVERLAY_RENDER_MODE: OverlayRenderMode = "class";

/**
 * Whether `mode` can paint given the aligned window's `heap_status`.
 *
 * Only `heap` depends on it: it paints the consensus heap roles, which exist
 * only when the window says `"ok"`. Every other mode is always available.
 */
export function overlayRenderModeAvailable(
  mode: OverlayRenderMode,
  heapStatus: string | null,
): boolean {
  return mode !== "heap" || heapStatus === "ok";
}

/**
 * The mode the overlay ACTUALLY paints: the chosen one, or the default when
 * the chosen one cannot paint right now (`heap` with no usable roles).
 *
 * Derived, never written back: the choice survives a window whose heap roles
 * are unavailable, so returning to one that has them restores `heap` without
 * the analyst having to pick it again.
 */
export function effectiveOverlayRenderMode(
  mode: OverlayRenderMode,
  heapStatus: string | null,
): OverlayRenderMode {
  return overlayRenderModeAvailable(mode, heapStatus) ? mode : DEFAULT_OVERLAY_RENDER_MODE;
}

export interface OverlayRenderState {
  renderMode: OverlayRenderMode;
  setRenderMode: (mode: OverlayRenderMode) => void;
  reset: () => void;
}

export const useOverlayRenderStore = create<OverlayRenderState>((set) => ({
  renderMode: DEFAULT_OVERLAY_RENDER_MODE,
  setRenderMode: (mode) => set({ renderMode: mode }),
  reset: () => set({ renderMode: DEFAULT_OVERLAY_RENDER_MODE }),
}));
