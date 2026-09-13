import { create } from "zustand";

// Cap on cached page-classification entries. Scrolling a large dump would
// otherwise grow pageClassifications without bound; once the cap is hit we
// drop the oldest entries (Map preserves insertion order).
const MAX_CACHED_PAGES = 256;

interface StaticRegion {
  start: number;
  end: number;
  length: number;
  mean_variance: number;
}

// Down-sampled change/variance heatmap over a dump's whole VA span, used by
// the ConsensusVarianceMinimap. `changing[i]`/`high[i]` are per-bin fractions
// (0..1); `level[i]` is the peak ByteClass code (0..3) in bin i.
interface VaOverview {
  va_start: number;
  va_end: number;
  bin_size: number;
  changing: number[];
  high: number[];
  level: number[];
}

/** A finalized incremental session, as the consensus store sees it. */
export interface IncrementalAdoption {
  consensusId: string;
  size: number;
  numDumps: number;
  counts: Record<string, number> | null;
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

  // Server-assigned id of the most recent consensus build. Range queries are
  // scoped to this id so concurrent clients can't read each other's results.
  consensusId: string | null;
  pageClassifications: Map<number, number[]>;

  // VA-keyed classifications for the hex viewer's "va" view of .msl dumps.
  // The container offset overlay (pageClassifications) is coordinate-wrong for
  // .msl because the classification array lives in an aligned-slab coordinate;
  // these are keyed by row-aligned ABSOLUTE virtual address instead.
  vaClassifications: Map<number, number[]>;
  vaOverview: VaOverview | null;

  runConsensus: (dumpPaths: string[], normalize: boolean) => Promise<void>;
  /**
   * Adopt a FINALIZED incremental session as the consensus the rest of the app
   * reads.
   *
   * `ConsensusSessionManager` is one process-wide singleton shared by
   * `api/routers/consensus.py` and `api/routers/analysis.py`, and
   * `/analysis/consensus/range` resolves its `consensus_id` through
   * `manager.get(...)`. So a finalized incremental `session_id` IS a valid
   * `consensus_id` — without this, Finalize was a dead end: the id landed in
   * `consensus-incremental-store.finalResult` and nothing ever read it.
   *
   * Note the fold is FLAT (offset-keyed Welford), so `staticRegions` /
   * `volatileRegions` / the VA caches stay empty: there is no alignment to
   * report and the VA endpoints reject a non-aligned build.
   */
  adoptIncremental: (adoption: IncrementalAdoption) => void;
  setOverlayEnabled: (enabled: boolean) => void;
  fetchRange: (offset: number, length: number) => Promise<number[]>;
  fetchVaRange: (dumpPath: string, va: number, length: number) => Promise<number[]>;
  fetchVaOverview: (dumpPath: string, bins: number) => Promise<void>;
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
  consensusId: null,
  pageClassifications: new Map(),
  vaClassifications: new Map(),
  vaOverview: null,

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
        consensusId: json.consensus_id ?? null,
        pageClassifications: new Map(),
        vaClassifications: new Map(),
        vaOverview: null,
      });
    } catch (err) {
      set({
        loading: false,
        error: err instanceof Error ? err.message : String(err),
        available: false,
      });
    }
  },

  adoptIncremental: ({ consensusId, size, numDumps, counts }) =>
    set({
      available: true,
      loading: false,
      error: null,
      size,
      numDumps,
      counts,
      staticRegions: [],
      volatileRegions: [],
      consensusId,
      pageClassifications: new Map(),
      vaClassifications: new Map(),
      vaOverview: null,
    }),

  setOverlayEnabled: (enabled) => set({ overlayEnabled: enabled }),

  fetchRange: async (offset, length) => {
    const state = get();
    const cached = state.pageClassifications.get(offset);
    if (cached && cached.length >= length) {
      return cached.slice(0, length);
    }
    if (!state.consensusId) {
      // No consensus built yet — nothing to range over.
      return [];
    }
    const url =
      `/api/analysis/consensus/range?consensus_id=${encodeURIComponent(state.consensusId)}` +
      `&offset=${offset}&length=${length}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Consensus range fetch failed: ${res.status}`);
    }
    const json = await res.json();
    const classifications: number[] = json.classifications ?? [];
    set((prev) => {
      const next = new Map(prev.pageClassifications);
      next.set(offset, classifications);
      // Evict oldest entries once the cache exceeds its bound so scrolling a
      // large dump cannot grow the map unbounded.
      while (next.size > MAX_CACHED_PAGES) {
        const oldest = next.keys().next().value;
        if (oldest === undefined) break;
        next.delete(oldest);
      }
      return { pageClassifications: next };
    });
    return classifications;
  },

  fetchVaRange: async (dumpPath, va, length) => {
    const state = get();
    const cached = state.vaClassifications.get(va);
    if (cached && cached.length >= length) {
      return cached.slice(0, length);
    }
    if (!state.consensusId) {
      // No consensus built yet — nothing to range over.
      return [];
    }
    const url =
      `/api/analysis/consensus/va-range?consensus_id=${encodeURIComponent(state.consensusId)}` +
      `&dump_path=${encodeURIComponent(dumpPath)}&va=${va}&length=${length}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Consensus VA range fetch failed: ${res.status}`);
    }
    const json = await res.json();
    const classes: number[] = json.classes ?? [];
    set((prev) => {
      const next = new Map(prev.vaClassifications);
      next.set(va, classes);
      // Evict oldest entries once the cache exceeds its bound so scrolling a
      // large VA span cannot grow the map unbounded.
      while (next.size > MAX_CACHED_PAGES) {
        const oldest = next.keys().next().value;
        if (oldest === undefined) break;
        next.delete(oldest);
      }
      return { vaClassifications: next };
    });
    return classes;
  },

  fetchVaOverview: async (dumpPath, bins) => {
    const state = get();
    if (!state.consensusId) return;
    const url =
      `/api/analysis/consensus/va-overview?consensus_id=${encodeURIComponent(state.consensusId)}` +
      `&dump_path=${encodeURIComponent(dumpPath)}&bins=${bins}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Consensus VA overview fetch failed: ${res.status}`);
    }
    const json = await res.json();
    set({
      vaOverview: {
        va_start: json.va_start ?? 0,
        va_end: json.va_end ?? 0,
        bin_size: json.bin_size ?? 0,
        changing: json.changing ?? [],
        high: json.high ?? [],
        level: json.level ?? [],
      },
    });
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
      consensusId: null,
      pageClassifications: new Map(),
      vaClassifications: new Map(),
      vaOverview: null,
    }),
}));
