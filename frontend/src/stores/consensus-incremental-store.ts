import { create } from "zustand";

export interface LiveStats {
  mean_variance: number;
  max_variance: number;
  top_offsets: Array<{ offset: number; variance: number }>;
}

export interface FinalizeResult {
  session_id: string;
  num_dumps: number;
  size: number;
  classification_counts: Record<string, number>;
  variance_summary: { mean: number; max: number; min: number };
}

export type IncrementalStatus = "idle" | "building" | "finalized" | "error";

interface State {
  sessionId: string | null;
  size: number;
  numDumps: number;
  status: IncrementalStatus;
  liveStats: LiveStats | null;
  history: number[]; // rolling max_variance after each add, for sparkline
  finalResult: FinalizeResult | null;
  error: string | null;

  begin: (size: number) => Promise<void>;
  addFile: (file: File) => Promise<void>;
  addPath: (path: string) => Promise<void>;
  finalize: () => Promise<void>;
  reset: () => void;
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`${url} failed: ${res.status} ${await res.text()}`);
  }
  return res.json();
}

export const useConsensusIncrementalStore = create<State>((set, get) => ({
  sessionId: null,
  size: 0,
  numDumps: 0,
  status: "idle",
  liveStats: null,
  history: [],
  finalResult: null,
  error: null,

  begin: async (size: number) => {
    set({ status: "building", error: null, history: [], numDumps: 0 });
    try {
      const res = await postJson<{ session_id: string; size: number }>(
        "/api/consensus/begin",
        { size },
      );
      set({
        sessionId: res.session_id,
        size: res.size,
        liveStats: null,
        finalResult: null,
      });
    } catch (err) {
      set({
        status: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  },

  addFile: async (file: File) => {
    const { sessionId } = get();
    if (!sessionId) return;
    const form = new FormData();
    form.append("file", file);
    form.append("label", file.name);
    try {
      const res = await fetch(
        `/api/consensus/${sessionId}/add-upload`,
        { method: "POST", body: form },
      );
      if (!res.ok) {
        throw new Error(`add-upload failed: ${res.status} ${await res.text()}`);
      }
      const json = (await res.json()) as {
        num_dumps: number;
        live_stats: LiveStats;
      };
      set((prev) => ({
        numDumps: json.num_dumps,
        liveStats: json.live_stats,
        history: [...prev.history, json.live_stats.max_variance],
      }));
    } catch (err) {
      set({
        status: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  },

  addPath: async (path: string) => {
    const { sessionId } = get();
    if (!sessionId) return;
    try {
      const json = await postJson<{
        num_dumps: number;
        live_stats: LiveStats;
      }>(`/api/consensus/${sessionId}/add-path`, { path });
      set((prev) => ({
        numDumps: json.num_dumps,
        liveStats: json.live_stats,
        history: [...prev.history, json.live_stats.max_variance],
      }));
    } catch (err) {
      set({
        status: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  },

  finalize: async () => {
    const { sessionId } = get();
    if (!sessionId) return;
    try {
      const json = await postJson<FinalizeResult>(
        `/api/consensus/${sessionId}/finalize`,
        {},
      );
      set({ status: "finalized", finalResult: json });
    } catch (err) {
      set({
        status: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  },

  reset: () =>
    set({
      sessionId: null,
      size: 0,
      numDumps: 0,
      status: "idle",
      liveStats: null,
      history: [],
      finalResult: null,
      error: null,
    }),
}));
