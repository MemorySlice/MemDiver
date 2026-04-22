import { create } from "zustand";
import { extractStrings } from "@/api/client";
import type { StringMatch } from "@/api/types";
import { useHexStore } from "@/stores/hex-store";
import type { HighlightRegion } from "@/stores/hex-store";

const MAX_ROWS = 10_000;
const PAGE_SIZE = 500;
const CHUNK_SIZE = 8 * 1024 * 1024;
const VIEWPORT_MARGIN = 200;
const HIGHLIGHT_DEBOUNCE_MS = 60;

type Encoding = "ascii" | "utf-8";

interface StringsState {
  dumpPath: string | null;
  rows: StringMatch[];
  cursor: number | null;
  fetching: boolean;
  done: boolean;
  error: string | null;

  totalCount: number | string;
  truncated: boolean;

  visibleFirst: number;
  visibleLast: number;

  highlightActive: boolean;
  highlightAllWarn: boolean;

  filterText: string;
  encoding: Encoding;
  minLength: number;

  resetAndFetch: (dumpPath: string) => Promise<void>;
  fetchNextPage: () => Promise<void>;
  setVisibleRange: (first: number, last: number) => void;
  setHighlightActive: (active: boolean) => void;
  setHighlightAllWarn: (confirmed: boolean) => void;
  setFilterText: (text: string) => void;
  setEncoding: (enc: Encoding) => void;
  setMinLength: (n: number) => void;
  getFilteredStrings: () => StringMatch[];
  clear: () => void;
}

function buildHighlightPayload(
  rows: StringMatch[],
  visibleFirst: number,
  visibleLast: number,
  mode: "viewport" | "all",
): HighlightRegion[] {
  if (rows.length === 0) return [];
  const from = mode === "all" ? 0 : Math.max(0, visibleFirst - VIEWPORT_MARGIN);
  const to =
    mode === "all"
      ? rows.length
      : Math.min(rows.length, visibleLast + VIEWPORT_MARGIN + 1);
  const slice = rows.slice(from, to);
  return slice.map((s) => ({
    offset: s.offset,
    length: s.length,
    type: "strings" as const,
    label: s.value.length > 30 ? `"${s.value.slice(0, 30)}..."` : `"${s.value}"`,
  }));
}

function stripStringHighlights(): void {
  const hex = useHexStore.getState();
  const nonString = hex.highlightedRegions.filter((r) => r.type !== "strings");
  if (nonString.length === hex.highlightedRegions.length) return;
  hex.setHighlightedRegions(nonString);
}

function pushHighlights(regions: HighlightRegion[]): void {
  const hex = useHexStore.getState();
  const nonString = hex.highlightedRegions.filter((r) => r.type !== "strings");
  hex.setHighlightedRegions([...nonString, ...regions]);
}

let highlightTimer: ReturnType<typeof setTimeout> | null = null;
function scheduleHighlightSync(sync: () => void): void {
  if (highlightTimer !== null) clearTimeout(highlightTimer);
  highlightTimer = setTimeout(() => {
    highlightTimer = null;
    sync();
  }, HIGHLIGHT_DEBOUNCE_MS);
}

export const useStringsStore = create<StringsState>((set, get) => {
  const syncHighlights = (): void => {
    const state = get();
    if (!state.highlightActive) {
      stripStringHighlights();
      return;
    }
    const mode = state.highlightAllWarn ? "all" : "viewport";
    const payload = buildHighlightPayload(
      state.rows,
      state.visibleFirst,
      state.visibleLast,
      mode,
    );
    pushHighlights(payload);
  };

  const syncHighlightsImmediate = (): void => {
    if (highlightTimer !== null) {
      clearTimeout(highlightTimer);
      highlightTimer = null;
    }
    syncHighlights();
  };

  return {
    dumpPath: null,
    rows: [],
    cursor: 0,
    fetching: false,
    done: false,
    error: null,
    totalCount: 0,
    truncated: false,

    visibleFirst: 0,
    visibleLast: 0,

    highlightActive: false,
    highlightAllWarn: false,

    filterText: "",
    encoding: "ascii",
    minLength: 4,

    resetAndFetch: async (dumpPath: string) => {
      stripStringHighlights();
      set({
        dumpPath,
        rows: [],
        cursor: 0,
        fetching: false,
        done: false,
        error: null,
        totalCount: 0,
        truncated: false,
        visibleFirst: 0,
        visibleLast: 0,
        highlightAllWarn: false,
      });
      await get().fetchNextPage();
    },

    fetchNextPage: async () => {
      const { fetching, done, dumpPath, cursor, encoding, minLength } = get();
      if (fetching || done || !dumpPath) return;
      set({ fetching: true, error: null });
      try {
        const res = await extractStrings(dumpPath, {
          minLength,
          encoding,
          maxResults: PAGE_SIZE,
          cursor: cursor ?? 0,
          chunkSize: CHUNK_SIZE,
        });
        const incoming = res.strings ?? [];
        const merged = get().rows.concat(incoming);
        const trimmed =
          merged.length > MAX_ROWS ? merged.slice(merged.length - MAX_ROWS) : merged;
        const nextCursor = res.next_cursor ?? null;
        const exhausted = nextCursor === null || incoming.length === 0;
        set({
          rows: trimmed,
          cursor: nextCursor,
          fetching: false,
          done: exhausted,
          totalCount: res.total_count,
          truncated: res.truncated,
        });
        if (get().highlightActive) scheduleHighlightSync(syncHighlights);
      } catch (e) {
        set({
          fetching: false,
          error: e instanceof Error ? e.message : "Failed to extract strings",
        });
      }
    },

    setVisibleRange: (first: number, last: number) => {
      const { visibleFirst, visibleLast } = get();
      if (visibleFirst === first && visibleLast === last) return;
      set({ visibleFirst: first, visibleLast: last });
      if (get().highlightActive && !get().highlightAllWarn) {
        scheduleHighlightSync(syncHighlights);
      }
    },

    setHighlightActive: (active: boolean) => {
      set({ highlightActive: active });
      if (!active) set({ highlightAllWarn: false });
      syncHighlightsImmediate();
    },

    setHighlightAllWarn: (confirmed: boolean) => {
      set({ highlightAllWarn: confirmed });
      syncHighlightsImmediate();
    },

    setFilterText: (text: string) => set({ filterText: text }),

    setEncoding: (enc: Encoding) => set({ encoding: enc }),

    setMinLength: (n: number) => set({ minLength: n }),

    getFilteredStrings: () => {
      const { rows, filterText } = get();
      if (!filterText) return rows;
      const lower = filterText.toLowerCase();
      return rows.filter((s) => s.value.toLowerCase().includes(lower));
    },

    clear: () => {
      stripStringHighlights();
      set({
        dumpPath: null,
        rows: [],
        cursor: 0,
        fetching: false,
        done: false,
        error: null,
        totalCount: 0,
        truncated: false,
        visibleFirst: 0,
        visibleLast: 0,
        filterText: "",
        highlightActive: false,
        highlightAllWarn: false,
      });
    },
  };
});
