import { create } from "zustand";
import { extractStrings } from "@/api/client";
import type { StringMatch } from "@/api/types";
import { useHexStore } from "@/stores/hex-store";
import type { HighlightRegion } from "@/stores/hex-store";

interface StringsState {
  strings: StringMatch[];
  totalCount: number | string;
  truncated: boolean;
  loading: boolean;
  error: string | null;
  filterText: string;
  encoding: "ascii" | "utf-8";
  minLength: number;
  highlightActive: boolean;
  lastFetchedKey: string;

  fetchStrings: (dumpPath: string) => Promise<void>;
  setFilterText: (text: string) => void;
  setEncoding: (enc: "ascii" | "utf-8") => void;
  setMinLength: (n: number) => void;
  setHighlightActive: (active: boolean) => void;
  getFilteredStrings: () => StringMatch[];
  clear: () => void;
}

function pushHighlights(strings: StringMatch[]) {
  const hexState = useHexStore.getState();
  const nonString = hexState.highlightedRegions.filter((r) => r.type !== "strings");
  const stringRegions: HighlightRegion[] = strings.map((s) => ({
    offset: s.offset,
    length: s.length,
    type: "strings" as const,
    label: s.value.length > 30 ? `"${s.value.slice(0, 30)}..."` : `"${s.value}"`,
  }));
  hexState.setHighlightedRegions([...nonString, ...stringRegions]);
}

function removeHighlights() {
  const hexState = useHexStore.getState();
  hexState.setHighlightedRegions(
    hexState.highlightedRegions.filter((r) => r.type !== "strings"),
  );
}

export const useStringsStore = create<StringsState>((set, get) => ({
  strings: [],
  totalCount: 0,
  truncated: false,
  loading: false,
  error: null,
  filterText: "",
  encoding: "ascii",
  minLength: 4,
  highlightActive: false,
  lastFetchedKey: "",

  fetchStrings: async (dumpPath: string) => {
    const { encoding, minLength } = get();
    const key = `${dumpPath}:${encoding}:${minLength}`;
    if (key === get().lastFetchedKey && get().strings.length > 0) return;
    set({ loading: true, error: null });
    try {
      const res = await extractStrings(dumpPath, minLength, encoding);
      set({
        strings: res.strings,
        totalCount: res.total_count,
        truncated: res.truncated,
        loading: false,
        lastFetchedKey: key,
      });
      if (get().highlightActive) pushHighlights(res.strings);
    } catch (e) {
      set({ loading: false, error: e instanceof Error ? e.message : "Failed to extract strings" });
    }
  },

  setFilterText: (text) => set({ filterText: text }),

  setEncoding: (enc) => set({ encoding: enc, lastFetchedKey: "" }),

  setMinLength: (n) => set({ minLength: n, lastFetchedKey: "" }),

  setHighlightActive: (active) => {
    set({ highlightActive: active });
    if (active) {
      pushHighlights(get().strings);
    } else {
      removeHighlights();
    }
  },

  getFilteredStrings: () => {
    const { strings, filterText } = get();
    if (!filterText) return strings;
    const lower = filterText.toLowerCase();
    return strings.filter((s) => s.value.toLowerCase().includes(lower));
  },

  clear: () => {
    removeHighlights();
    set({
      strings: [],
      totalCount: 0,
      truncated: false,
      loading: false,
      error: null,
      filterText: "",
      highlightActive: false,
      lastFetchedKey: "",
    });
  },
}));
