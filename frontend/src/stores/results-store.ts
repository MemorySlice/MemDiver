import { create } from "zustand";
import type { SecretHit } from "@/api/types";

export type SortField = "offset" | "confidence" | "length" | "algorithm";
export type SortDirection = "asc" | "desc";

interface AlgorithmResult {
  algorithm: string;
  hits: SecretHit[];
  running: boolean;
  error: string | null;
  lastRunAt: string | null;
}

interface ResultsState {
  algorithmResults: Record<string, AlgorithmResult>;
  filterAlgorithm: string | null;
  sortField: SortField;
  sortDirection: SortDirection;

  // Actions
  setAlgorithmResults: (algo: string, hits: SecretHit[]) => void;
  setAlgorithmRunning: (algo: string, running: boolean) => void;
  setAlgorithmError: (algo: string, error: string | null) => void;
  clearResults: () => void;
  setFilter: (algo: string | null) => void;
  setSort: (field: SortField, direction: SortDirection) => void;

  // Derived helpers
  getAllHits: () => SecretHit[];
  getFilteredHits: () => { algorithm: string; hit: SecretHit }[];
  getHitCountByAlgorithm: () => Record<string, number>;
  getTotalHitCount: () => number;
}

function ensureEntry(
  results: Record<string, AlgorithmResult>,
  algo: string,
): AlgorithmResult {
  return (
    results[algo] ?? {
      algorithm: algo,
      hits: [],
      running: false,
      error: null,
      lastRunAt: null,
    }
  );
}

function compareHits(
  a: SecretHit,
  b: SecretHit,
  field: SortField,
  direction: SortDirection,
  algoA?: string,
  algoB?: string,
): number {
  let cmp = 0;
  switch (field) {
    case "offset":
      cmp = a.offset - b.offset;
      break;
    case "confidence":
      cmp = (a.confidence ?? 0) - (b.confidence ?? 0);
      break;
    case "length":
      cmp = a.length - b.length;
      break;
    case "algorithm":
      cmp = (algoA ?? "").localeCompare(algoB ?? "");
      break;
  }
  return direction === "asc" ? cmp : -cmp;
}

export const useResultsStore = create<ResultsState>((set, get) => ({
  algorithmResults: {},
  filterAlgorithm: null,
  sortField: "offset",
  sortDirection: "asc",

  setAlgorithmResults: (algo, hits) =>
    set((state) => ({
      algorithmResults: {
        ...state.algorithmResults,
        [algo]: {
          ...ensureEntry(state.algorithmResults, algo),
          hits,
          running: false,
          error: null,
          lastRunAt: new Date().toISOString(),
        },
      },
    })),

  setAlgorithmRunning: (algo, running) =>
    set((state) => ({
      algorithmResults: {
        ...state.algorithmResults,
        [algo]: {
          ...ensureEntry(state.algorithmResults, algo),
          running,
        },
      },
    })),

  setAlgorithmError: (algo, error) =>
    set((state) => ({
      algorithmResults: {
        ...state.algorithmResults,
        [algo]: {
          ...ensureEntry(state.algorithmResults, algo),
          running: false,
          error,
        },
      },
    })),

  clearResults: () =>
    set({ algorithmResults: {}, filterAlgorithm: null }),

  setFilter: (algo) => set({ filterAlgorithm: algo }),

  setSort: (field, direction) =>
    set({ sortField: field, sortDirection: direction }),

  getAllHits: () => {
    const { algorithmResults, sortField, sortDirection } = get();
    const all: SecretHit[] = [];
    for (const entry of Object.values(algorithmResults)) {
      all.push(...entry.hits);
    }
    return all.sort((a, b) =>
      compareHits(a, b, sortField, sortDirection),
    );
  },

  getFilteredHits: () => {
    const { algorithmResults, filterAlgorithm, sortField, sortDirection } =
      get();
    const tagged: { algorithm: string; hit: SecretHit }[] = [];

    for (const [algo, entry] of Object.entries(algorithmResults)) {
      if (filterAlgorithm !== null && algo !== filterAlgorithm) continue;
      for (const hit of entry.hits) {
        tagged.push({ algorithm: algo, hit });
      }
    }

    return tagged.sort((a, b) =>
      compareHits(a.hit, b.hit, sortField, sortDirection, a.algorithm, b.algorithm),
    );
  },

  getHitCountByAlgorithm: () => {
    const { algorithmResults } = get();
    const counts: Record<string, number> = {};
    for (const [algo, entry] of Object.entries(algorithmResults)) {
      counts[algo] = entry.hits.length;
    }
    return counts;
  },

  getTotalHitCount: () => {
    const { algorithmResults } = get();
    let total = 0;
    for (const entry of Object.values(algorithmResults)) {
      total += entry.hits.length;
    }
    return total;
  },
}));
