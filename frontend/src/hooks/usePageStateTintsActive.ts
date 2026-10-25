import { useAlignedSelection, useAnchorServesPageStates } from "@/hooks/useAlignedPanes";
import { useHexStore } from "@/stores/hex-store";

/**
 * Whether the MSL page-state tints (failed / unmapped / not resident) can
 * currently be on screen: the hex store has page states loaded and the
 * coordinate is "va", the only one `getPageStateAt` answers in. Both
 * page-state readers (`HexViewer`, `HexOverlayPane`) gate on exactly this, so a
 * legend gated on it never explains a tint the grid is not painting.
 */
export function usePageStateTintsActive(): boolean {
  return useHexStore((s) => s.viewMode === "va" && s.pageStatesLoaded);
}

/**
 * The multi-dump counterpart of `usePageStateTintsActive`: whether the ALIGNED
 * panes (side-by-side and overlay) can paint page-state tints right now.
 *
 * They read the aligned window's own `page_states`, not `hex-store`, and the
 * backend sends runs only for an `.msl` or `.mdview` anchor in the "va" coordinate. Gating
 * on exactly that — rather than on "some window has delivered runs" — is known
 * before the first window lands and does not move while scrolling, so the
 * legend neither flickers in on arrival nor out on a window that happens to be
 * all captured. A separate hook so the single view's gate keeps its meaning.
 */
export function useAlignedPageStateTintsActive(): boolean {
  const { anchor } = useAlignedSelection();
  const viewMode = useHexStore((s) => s.viewMode);
  const servesPageStates = useAnchorServesPageStates(anchor);
  return servesPageStates && viewMode === "va";
}
