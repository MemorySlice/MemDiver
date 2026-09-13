/**
 * Honours `hex-store.scrollTarget` inside a bounded virtualization window.
 *
 * Shared verbatim by the single-dump `HexViewer` and the N-pane
 * `MultiHexViewer` so there is exactly ONE implementation of "jump to this
 * row". Both viewers read `windowStartRow` from the same store, so a bookmark,
 * a search hit or a `CandidatePanel` click lands on the same row whichever
 * layout happens to be mounted — and switching Single <-> Side-by-side keeps
 * the scroll position instead of snapping back to row 0.
 *
 * `scrollTarget` is an ABSOLUTE file row. If it already falls inside the
 * current window, scroll to its window-relative index. Otherwise slide the
 * window to recenter on it: this hook re-runs on the resulting `safeStart`
 * change and then takes the in-window branch, so it terminates thanks to
 * `recenterWindow`'s in-window guarantee.
 */

import { useEffect } from "react";
import type { Virtualizer } from "@tanstack/react-virtual";
import { useHexStore } from "@/stores/hex-store";
import { isRowInWindow, recenterWindow, windowCount } from "@/components/hex/window-utils";

export function useHexScrollTarget(
  virtualizer: Virtualizer<HTMLDivElement, Element>,
  safeStart: number,
  totalRows: number,
): void {
  const scrollTarget = useHexStore((s) => s.scrollTarget);
  const clearScrollTarget = useHexStore((s) => s.clearScrollTarget);
  const setWindowStart = useHexStore((s) => s.setWindowStart);

  useEffect(() => {
    if (scrollTarget === null) return;
    const count = windowCount(safeStart, totalRows);
    if (count > 0 && isRowInWindow(scrollTarget, safeStart, count)) {
      virtualizer.scrollToIndex(scrollTarget - safeStart, { align: "center" });
      clearScrollTarget();
    } else {
      setWindowStart(recenterWindow(scrollTarget, totalRows));
    }
  }, [scrollTarget, safeStart, totalRows, virtualizer, clearScrollTarget, setWindowStart]);
}
