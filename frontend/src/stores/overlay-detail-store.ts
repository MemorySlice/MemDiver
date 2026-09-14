/**
 * WHICH question the overlay's right-hand panel is answering.
 *
 * Two, and they are genuinely different questions about the same bytes:
 *
 *   - `"byte"`    — "what does every dump hold AT THE CURSOR?"  (cursor-driven,
 *                   `OverlayByteInspector`, the ground-truth surface)
 *   - `"regions"` — "where is EVERY key candidate in this dump?" (class-driven,
 *                   `VarianceClassBrowser`, the navigation surface)
 *
 * It lives in a store rather than in `Workspace.DetailPanel`'s local state for
 * one reason: the control that switches it — a category chip in the overlay's
 * legend — is in the LEFT pane, several components away, and "click a class,
 * get its list" is the whole point of the chips. Lifting the state to a common
 * React ancestor would mean threading a callback through `HexOverlayPane` and
 * `OverlayModeLegend`, neither of which has any other reason to know the detail
 * panel exists.
 *
 * Modelled on `overlay-render-store`: one field, one setter, no persistence —
 * which pane you last looked at is not worth restoring across a reload, and a
 * remembered `"regions"` tab would greet the next session with an empty list.
 */

import { create } from "zustand";

/** The two tabs, in the order they are rendered. */
export const OVERLAY_DETAIL_TABS = ["byte", "regions"] as const;

export type OverlayDetailTab = (typeof OVERLAY_DETAIL_TABS)[number];

/**
 * `"byte"` needs nothing: a cursor is always somewhere, whereas the region list
 * needs a consensus and a round trip.
 */
export const DEFAULT_OVERLAY_DETAIL_TAB: OverlayDetailTab = "byte";

interface OverlayDetailState {
  tab: OverlayDetailTab;
  setTab(tab: OverlayDetailTab): void;
  /** Starting a new session must not leave the previous one's tab selected. */
  reset(): void;
}

export const useOverlayDetailStore = create<OverlayDetailState>((set) => ({
  tab: DEFAULT_OVERLAY_DETAIL_TAB,
  setTab: (tab) => set({ tab }),
  reset: () => set({ tab: DEFAULT_OVERLAY_DETAIL_TAB }),
}));
