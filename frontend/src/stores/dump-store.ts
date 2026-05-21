import { create } from "zustand";
import { getTagStatus, probeTagStatusWithKey } from "@/api/client";
import type { TagStatus } from "@/api/types";

export interface DumpEntry {
  id: string;
  path: string;
  name: string;
  size: number;
  format: "raw" | "msl";
  sameProcess: boolean;
  tagStatus?: TagStatus;
}

interface DumpState {
  dumps: DumpEntry[];
  activeDumpId: string | null;
  comparisonDumpIds: [string, string] | null;
  viewMode: "single" | "comparison" | "overlay";
  aslrNormalize: boolean;
  selectedDumpIds: string[];
  visibleDumps: Set<string>;

  addDump: (entry: Omit<DumpEntry, "id" | "sameProcess">) => string;
  removeDump: (id: string) => void;
  setActiveDump: (id: string) => void;
  setComparisonPair: (a: string, b: string) => void;
  setViewMode: (mode: "single" | "comparison" | "overlay") => void;
  toggleAslrNormalize: () => void;
  toggleSameProcess: (id: string) => void;
  fetchTagStatus: (id: string) => Promise<void>;
  unlockTagStatus: (
    id: string,
    secret: { passphrase?: string; key_hex?: string; kem_key_hex?: string },
  ) => Promise<TagStatus>;
  setSelectedDumps: (ids: string[]) => void;
  toggleDumpVisibility: (id: string) => void;
  clearAll: () => void;
  getDumpPaths: () => string[];
}

export const useDumpStore = create<DumpState>((set, get) => ({
  dumps: [],
  activeDumpId: null,
  comparisonDumpIds: null,
  viewMode: "single",
  aslrNormalize: false,
  selectedDumpIds: [],
  visibleDumps: new Set<string>(),

  addDump: (entry) => {
    const id = crypto.randomUUID();
    const newDump: DumpEntry = { ...entry, id, sameProcess: true };
    set((state) => ({
      dumps: [...state.dumps, newDump],
      activeDumpId: state.dumps.length === 0 ? id : state.activeDumpId,
    }));
    return id;
  },

  removeDump: (id) =>
    set((state) => {
      const remaining = state.dumps.filter((d) => d.id !== id);
      let nextActive = state.activeDumpId;
      if (state.activeDumpId === id) {
        nextActive = remaining.length > 0 ? remaining[0].id : null;
      }
      let nextComparison = state.comparisonDumpIds;
      if (nextComparison && (nextComparison[0] === id || nextComparison[1] === id)) {
        nextComparison = null;
      }
      return {
        dumps: remaining,
        activeDumpId: nextActive,
        comparisonDumpIds: nextComparison,
      };
    }),

  setActiveDump: (id) => set({ activeDumpId: id }),

  setComparisonPair: (a, b) => set({ comparisonDumpIds: [a, b] }),

  setViewMode: (mode) => set({ viewMode: mode }),

  toggleAslrNormalize: () =>
    set((state) => ({ aslrNormalize: !state.aslrNormalize })),

  toggleSameProcess: (id) =>
    set((state) => ({
      dumps: state.dumps.map((d) =>
        d.id === id ? { ...d, sameProcess: !d.sameProcess } : d,
      ),
    })),

  fetchTagStatus: async (id) => {
    const dump = get().dumps.find((d) => d.id === id);
    if (!dump || dump.format !== "msl") return;
    try {
      const { tag_status } = await getTagStatus(dump.path);
      set((state) => ({
        dumps: state.dumps.map((d) =>
          d.id === id ? { ...d, tagStatus: tag_status } : d,
        ),
      }));
    } catch {
      // Tag status is advisory; leave undefined on failure.
    }
  },

  unlockTagStatus: async (id, secret) => {
    const dump = get().dumps.find((d) => d.id === id);
    if (!dump) throw new Error("Dump not found");
    const { tag_status } = await probeTagStatusWithKey(dump.path, secret);
    set((state) => ({
      dumps: state.dumps.map((d) =>
        d.id === id ? { ...d, tagStatus: tag_status } : d,
      ),
    }));
    return tag_status;
  },

  setSelectedDumps: (ids) =>
    set({ selectedDumpIds: ids }),

  toggleDumpVisibility: (id) =>
    set((state) => {
      const next = new Set(state.visibleDumps);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return { visibleDumps: next };
    }),

  clearAll: () =>
    set({
      dumps: [],
      activeDumpId: null,
      comparisonDumpIds: null,
      viewMode: "single",
      aslrNormalize: false,
      selectedDumpIds: [],
      visibleDumps: new Set<string>(),
    }),

  getDumpPaths: () => get().dumps.map((d) => d.path),
}));
