import { create } from "zustand";

import type { HighlightRegion } from "./hex-store";

interface YaraState {
  /** Highlight regions the YARA panel painted (so a re-run replaces only its own). */
  painted: HighlightRegion[];
  setPainted: (regions: HighlightRegion[]) => void;
}

export const useYaraStore = create<YaraState>((set) => ({
  painted: [],
  setPainted: (painted) => set({ painted }),
}));
