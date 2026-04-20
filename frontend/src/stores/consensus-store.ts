import { create } from "zustand";

interface StaticRegion {
  start: number;
  end: number;
  length: number;
  mean_variance: number;
}

interface ConsensusState {
  available: boolean;
  loading: boolean;
  error: string | null;
  size: number;
  numDumps: number;
  counts: Record<string, number> | null;
  staticRegions: StaticRegion[];
  volatileRegions: StaticRegion[];
  overlayEnabled: boolean;

  pageClassifications: Map<number, number[]>;

  runConsensus: (dumpPaths: string[], normalize: boolean) => Promise<void>;
  fetchRange: (offset: number, length: number) => Promise<number[]>;
  toggleOverlay: () => void;
  reset: () => void;
}

export const useConsensusStore = create<ConsensusState>((set, get) => ({
  available: false,
  loading: false,
  error: null,
  size: 0,
  numDumps: 0,
  counts: null,
  staticRegions: [],
  volatileRegions: [],
  overlayEnabled: false,
  pageClassifications: new Map(),

  runConsensus: async (dumpPaths, normalize) => {
    set({ loading: true, error: null });
    try {
      const res = await fetch("/api/analysis/consensus", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dump_paths: dumpPaths, normalize }),
      });
      if (!res.ok) {
        const detail = await res.text();
        throw new Error(`Consensus failed: ${res.status} ${detail}`);
      }
      const json = await res.json();
      set({
        available: true,
        loading: false,
        size: json.size ?? 0,
        numDumps: json.num_dumps ?? 0,
        counts: json.counts ?? null,
        staticRegions: json.static_regions ?? [],
        volatileRegions: json.volatile_regions ?? [],
        pageClassifications: new Map(),
      });
    } catch (err) {
      set({
        loading: false,
        error: err instanceof Error ? err.message : String(err),
        available: false,
      });
    }
  },

  fetchRange: async (offset, length) => {
    const state = get();
    const cached = state.pageClassifications.get(offset);
    if (cached && cached.length >= length) {
      return cached.slice(0, length);
    }
    const url =
      `/api/analysis/consensus/range?offset=${offset}&length=${length}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Consensus range fetch failed: ${res.status}`);
    }
    const json = await res.json();
    const classifications: number[] = json.classifications ?? [];
    set((prev) => {
      const next = new Map(prev.pageClassifications);
      next.set(offset, classifications);
      return { pageClassifications: next };
    });
    return classifications;
  },

  toggleOverlay: () =>
    set((state) => ({ overlayEnabled: !state.overlayEnabled })),

  reset: () =>
    set({
      available: false,
      loading: false,
      error: null,
      size: 0,
      numDumps: 0,
      counts: null,
      staticRegions: [],
      volatileRegions: [],
      overlayEnabled: false,
      pageClassifications: new Map(),
    }),
}));
