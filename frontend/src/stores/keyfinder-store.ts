import { create } from "zustand";

import type { HighlightRegion } from "./hex-store";

interface KeyFinderState {
  /** Highlight regions this panel painted (so a re-run replaces only its own). */
  painted: HighlightRegion[];
  /** Bumped by "verify with oracle"; the workspace opens the Verify Key tab on a change. */
  verifyRequestSeq: number;
  setPainted: (regions: HighlightRegion[]) => void;
  requestVerifyTab: () => void;
}

export const useKeyFinderStore = create<KeyFinderState>((set) => ({
  painted: [],
  verifyRequestSeq: 0,
  setPainted: (painted) => set({ painted }),
  requestVerifyTab: () => set((s) => ({ verifyRequestSeq: s.verifyRequestSeq + 1 })),
}));
