import { create } from "zustand";
import type { SeenTour, Tour } from "./types";

const STORAGE_KEY = "memdiver:ftue:seen";

function loadSeen(): SeenTour[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e) =>
        e &&
        typeof e.id === "string" &&
        typeof e.version === "number" &&
        typeof e.seenAt === "number" &&
        typeof e.completed === "boolean"
    );
  } catch {
    return [];
  }
}

function persistSeen(seen: SeenTour[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seen));
  } catch {
    /* localStorage unavailable / quota — ignore */
  }
}

interface FtueState {
  seenTours: SeenTour[];
  activeTourId: string | null;
  activeStepIndex: number;

  markSeen: (id: string, version: number, completed: boolean) => void;
  startTour: (id: string) => void;
  advance: () => void;
  dismiss: () => void;
  complete: () => void;
  shouldShow: (tour: Tour) => boolean;
}

function upsertSeen(
  list: SeenTour[],
  id: string,
  version: number,
  completed: boolean
): SeenTour[] {
  const entry: SeenTour = { id, version, seenAt: Date.now(), completed };
  const idx = list.findIndex((s) => s.id === id);
  if (idx === -1) return [...list, entry];
  const next = list.slice();
  next[idx] = entry;
  return next;
}

export const useFtueStore = create<FtueState>((set, get) => ({
  seenTours: loadSeen(),
  activeTourId: null,
  activeStepIndex: 0,

  markSeen: (id, version, completed) => {
    const next = upsertSeen(get().seenTours, id, version, completed);
    persistSeen(next);
    set({ seenTours: next });
  },

  startTour: (id) => set({ activeTourId: id, activeStepIndex: 0 }),

  advance: () =>
    set((s) => ({ activeStepIndex: s.activeStepIndex + 1 })),

  // dismiss/complete are pure state resets. Persistence is the caller's job
  // (TourRenderer calls markSeen with the correct tour version first); the
  // store never has to guess at a version.
  dismiss: () => set({ activeTourId: null, activeStepIndex: 0 }),
  complete: () => set({ activeTourId: null, activeStepIndex: 0 }),

  shouldShow: (tour) => {
    const seen = get().seenTours.find((s) => s.id === tour.id);
    if (!seen) return true;
    return seen.version < tour.version;
  },
}));

/** Test-only helper: clear state + localStorage. Not exported from index. */
export function __resetFtueStoreForTests(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
  useFtueStore.setState({
    seenTours: [],
    activeTourId: null,
    activeStepIndex: 0,
  });
}
