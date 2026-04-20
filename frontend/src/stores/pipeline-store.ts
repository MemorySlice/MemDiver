/**
 * Pipeline tab Zustand store.
 *
 * Owns the entire state machine for the "Pipeline" bottom tab: which
 * wizard stage the user is on, the form values they've filled in, the
 * in-flight task id, live-progress rollups (funnel stage counts,
 * n-sweep survivor curve, timings), verified hits, registered
 * artifacts, and terminal status.
 *
 * State that should survive a tab-switch re-mount (form values,
 * stage, taskId, lastSeq) is persisted to localStorage via Zustand's
 * ``persist`` middleware; live event state (funnel, timings, hits)
 * is rehydrated from the WebSocket ring buffer on reconnect and does
 * not need to persist.
 *
 * The ``ingestEvent`` reducer translates backend TaskProgressEvents into
 * state deltas. The hook ``useTaskProgress`` wires events into this
 * reducer; ingestEvent itself is pure and trivially unit-testable.
 */

import { create } from "zustand";
import { persist } from "zustand/middleware";

import type {
  ArtifactSpec,
  BruteForceParams,
  EmitParams,
  NSweepParams,
  ReduceParams,
  TaskStatus,
} from "@/api/pipeline";
import type { TaskProgressEvent } from "@/api/websocket";

const PIPELINE_STORE_VERSION = 1;

export type WizardStage =
  | "recipe"
  | "dumps"
  | "oracle"
  | "thresholds"
  | "running"
  | "results";

/** Narrow set of survivor counts we animate in the funnel viz. */
export interface FunnelCounts {
  raw: number;
  variance: number;
  aligned: number;
  high_entropy: number;
  candidates: number;
  verified: number;
}

export interface StageTimings {
  consensus_ms: number;
  reduce_ms: number;
  brute_force_ms: number;
}

/** A single convergence measurement after folding N dumps. */
export interface ConvergencePoint {
  n: number;
  staticCount: number;
  dynamicCount: number;
}

/** One (N, counts) sample from an n-sweep run, for the survivor curve. */
export interface NSweepPoint {
  n: number;
  stages: Record<string, number>;
  candidates: number;
  hits: number;
  hit_offset: number | null;
  timing_ms: Partial<StageTimings>;
}

export interface HitRecord {
  offset: number;
  size: number;
  region_index: number;
  key_hex: string;
  neighborhood_start: number;
  neighborhood_variance: number[];
}

export interface InferredField {
  offset: number;
  length: number;
  type: "static" | "key_material" | "dynamic";
  label: string;
  mean_variance: number;
}

export interface PipelineFormValues {
  sourcePaths: string[];
  oracleId: string | null;
  oracleSha256: string | null;
  reduce: ReduceParams;
  bruteForce: BruteForceParams;
  nsweep: NSweepParams | null;
  emit: EmitParams | null;
}

export interface PipelineState {
  // persisted
  stage: WizardStage;
  form: PipelineFormValues;
  taskId: string | null;
  lastSeq: number;

  // ephemeral (rebuilt from the WS replay on reconnect)
  status: TaskStatus | "idle";
  funnel: FunnelCounts;
  nsweepPoints: NSweepPoint[];
  timings: StageTimings;
  hits: HitRecord[];
  inferredFields: InferredField[];
  artifacts: ArtifactSpec[];
  activeStage: string | null;
  activeStagePct: number;
  activeStageMsg: string;
  error: string | null;

  // refine workflow (Phase C)
  convergenceHistory: ConvergencePoint[];
  refineLoading: boolean;
  consensusNumDumps: number;

  // actions
  setStage: (stage: WizardStage) => void;
  updateForm: (patch: Partial<PipelineFormValues>) => void;
  setTaskId: (taskId: string | null) => void;
  ingestEvent: (event: TaskProgressEvent) => void;
  resetRun: () => void;
  addConvergencePoint: (point: ConvergencePoint) => void;
  setRefineLoading: (loading: boolean) => void;
}

const DEFAULT_FORM: PipelineFormValues = {
  sourcePaths: [],
  oracleId: null,
  oracleSha256: null,
  reduce: {
    alignment: 8,
    block_size: 32,
    density_threshold: 0.5,
    min_variance: 3000.0,
    entropy_window: 32,
    entropy_threshold: 4.5,
    min_region: 16,
  },
  bruteForce: {
    key_sizes: [32],
    stride: 8,
    jobs: 1,
    exhaustive: true,
    top_k: 10,
  },
  nsweep: null,
  emit: null,
};

const DEFAULT_FUNNEL: FunnelCounts = {
  raw: 0,
  variance: 0,
  aligned: 0,
  high_entropy: 0,
  candidates: 0,
  verified: 0,
};

const DEFAULT_TIMINGS: StageTimings = {
  consensus_ms: 0,
  reduce_ms: 0,
  brute_force_ms: 0,
};

function baseRunState(): Pick<
  PipelineState,
  | "status"
  | "funnel"
  | "nsweepPoints"
  | "timings"
  | "hits"
  | "inferredFields"
  | "artifacts"
  | "activeStage"
  | "activeStagePct"
  | "activeStageMsg"
  | "error"
  | "convergenceHistory"
  | "refineLoading"
  | "consensusNumDumps"
> {
  return {
    status: "idle",
    funnel: { ...DEFAULT_FUNNEL },
    nsweepPoints: [],
    timings: { ...DEFAULT_TIMINGS },
    hits: [],
    inferredFields: [],
    artifacts: [],
    activeStage: null,
    activeStagePct: 0,
    activeStageMsg: "",
    error: null,
    convergenceHistory: [],
    refineLoading: false,
    consensusNumDumps: 0,
  };
}

/**
 * Apply one TaskProgressEvent to the current state. Pure function; no
 * Zustand ``set`` call inside. Exported so unit tests can verify
 * each event type in isolation without mounting a store.
 */
export function reducePipelineEvent(
  state: PipelineState,
  event: TaskProgressEvent,
): Partial<PipelineState> {
  // Already-seen events (e.g. replayed from the ring on reconnect) never
  // produce a state change — dropping them here avoids re-rendering
  // every subscriber for a no-op update.
  if (event.seq > 0 && event.seq <= state.lastSeq) {
    return {};
  }
  const patch: Partial<PipelineState> = {};
  if (event.seq > state.lastSeq) {
    patch.lastSeq = event.seq;
  }

  switch (event.type) {
    case "stage_start": {
      if (state.status === "idle") {
        patch.status = "running";
      }
      if (event.stage) {
        patch.activeStage = event.stage;
        patch.activeStagePct = 0;
        patch.activeStageMsg = event.msg ?? "";
      }
      break;
    }
    case "progress": {
      if (event.stage) {
        patch.activeStage = event.stage;
      }
      if (typeof event.pct === "number" && event.pct >= 0) {
        patch.activeStagePct = event.pct;
      }
      if (event.msg) {
        patch.activeStageMsg = event.msg;
      }
      // Engine search_reduce sub-stages carry funnel counts via extra.
      const extra = event.extra as
        | { survivor_bytes?: number; input_bytes?: number }
        | null
        | undefined;
      if (extra && typeof extra.survivor_bytes === "number") {
        const survivor = extra.survivor_bytes;
        const input = extra.input_bytes;
        const next: FunnelCounts = { ...state.funnel };
        if (event.stage === "search_reduce:variance") {
          next.variance = survivor;
          if (typeof input === "number") next.raw = input;
        } else if (event.stage === "search_reduce:aligned") {
          next.aligned = survivor;
        } else if (event.stage === "search_reduce:entropy") {
          next.high_entropy = survivor;
          next.candidates = survivor;
        }
        patch.funnel = next;
      }
      break;
    }
    case "stage_end": {
      if (event.stage) {
        patch.activeStage = event.stage;
        patch.activeStagePct = 1;
        patch.activeStageMsg = event.msg ?? "";
      }
      // brute_force stage_end carries the verified count + hits.
      if (event.stage === "brute_force" && event.extra) {
        const extra = event.extra as {
          verified_count?: number;
          total_candidates?: number;
          hits?: Array<{
            offset?: number;
            length?: number;
            region_index?: number;
            key_hex?: string;
            neighborhood_start?: number;
            neighborhood_variance?: number[];
          }>;
        };
        if (typeof extra.verified_count === "number") {
          patch.funnel = {
            ...state.funnel,
            verified: extra.verified_count,
          };
        }
        if (Array.isArray(extra.hits)) {
          const mappedHits = extra.hits.map((h) => ({
            offset: Number(h.offset ?? 0),
            size: Number(h.length ?? 0),
            region_index: Number(h.region_index ?? 0),
            key_hex: String(h.key_hex ?? ""),
            neighborhood_start: Number(h.neighborhood_start ?? 0),
            neighborhood_variance: Array.isArray(h.neighborhood_variance) ? h.neighborhood_variance : [],
          }));
          patch.hits = mappedHits;
          // Seed the initial convergence point from the first hit's neighborhood
          if (mappedHits.length > 0 && mappedHits[0].neighborhood_variance.length > 0) {
            const nbv = mappedHits[0].neighborhood_variance;
            const sc = nbv.filter((v) => v <= 2000).length;
            const numDumps = state.consensusNumDumps || 0;
            patch.convergenceHistory = [{ n: numDumps, staticCount: sc, dynamicCount: nbv.length - sc }];
          }
        }
      }
      // consensus stage_end carries total_bytes so we can seed the funnel's
      // ``raw`` bar before the variance filter has a chance to run.
      if (event.stage === "consensus" && event.extra) {
        const extra = event.extra as { total_bytes?: number; num_dumps?: number };
        if (typeof extra.total_bytes === "number") {
          patch.funnel = {
            ...state.funnel,
            raw: extra.total_bytes,
          };
        }
        if (typeof extra.num_dumps === "number") {
          patch.consensusNumDumps = extra.num_dumps;
        }
      }
      // emit_plugin stage_end carries inferred structure fields.
      if (event.stage === "emit_plugin" && event.extra) {
        const extra = event.extra as { fields?: InferredField[] };
        if (extra.fields && Array.isArray(extra.fields)) {
          patch.inferredFields = extra.fields;
        }
      }
      break;
    }
    case "nsweep_point": {
      if (event.extra && typeof event.extra === "object") {
        const extra = event.extra as {
          n?: number;
          stages?: Record<string, number>;
          candidates_tried?: number;
          hits?: number;
          hit_offset?: number | null;
          timing_ms?: Partial<StageTimings>;
        };
        if (typeof extra.n === "number") {
          const point: NSweepPoint = {
            n: extra.n,
            stages: extra.stages ?? {},
            candidates: extra.candidates_tried ?? 0,
            hits: extra.hits ?? 0,
            hit_offset: extra.hit_offset ?? null,
            timing_ms: extra.timing_ms ?? {},
          };
          patch.nsweepPoints = [...state.nsweepPoints, point];
        }
      }
      break;
    }
    case "oracle_hit": {
      if (event.extra && typeof event.extra === "object") {
        const extra = event.extra as {
          offset?: number;
          size?: number;
          region_index?: number;
          key_hex?: string;
          neighborhood_start?: number;
          neighborhood_variance?: number[];
        };
        if (typeof extra.offset === "number") {
          patch.hits = [
            ...state.hits,
            {
              offset: extra.offset,
              size: Number(extra.size ?? 0),
              region_index: Number(extra.region_index ?? 0),
              key_hex: String(extra.key_hex ?? ""),
              neighborhood_start: Number(extra.neighborhood_start ?? 0),
              neighborhood_variance: Array.isArray(extra.neighborhood_variance) ? extra.neighborhood_variance : [],
            },
          ];
        }
      }
      break;
    }
    case "artifact": {
      if (event.artifact?.name) {
        const artifact: ArtifactSpec = {
          name: event.artifact.name,
          relpath: event.artifact.relpath ?? event.artifact.path ?? "",
          media_type: event.artifact.media_type ?? "application/octet-stream",
          size: event.artifact.size ?? 0,
          sha256: event.artifact.sha256 ?? null,
          registered_at: event.ts,
        };
        patch.artifacts = [...state.artifacts, artifact];
      }
      break;
    }
    case "done": {
      patch.status = "succeeded";
      patch.activeStagePct = 1;
      break;
    }
    case "error": {
      // ``cancelled`` uses the error event with that specific payload
      // per TaskManager.cancel(); discriminate so the UI can show a
      // neutral "cancelled" status instead of a red error banner.
      if (event.error === "cancelled") {
        patch.status = "cancelled";
      } else {
        patch.status = "failed";
        patch.error = event.error ?? "unknown error";
      }
      break;
    }
  }
  return patch;
}

export const usePipelineStore = create<PipelineState>()(
  persist(
    (set, get) => ({
      stage: "recipe",
      form: { ...DEFAULT_FORM },
      taskId: null,
      lastSeq: 0,
      ...baseRunState(),

      setStage: (stage) => set({ stage }),
      updateForm: (patch) =>
        set((prev) => ({ form: { ...prev.form, ...patch } })),
      setTaskId: (taskId) =>
        set({
          taskId,
          lastSeq: 0,
          ...baseRunState(),
          status: taskId ? "pending" : "idle",
        }),
      ingestEvent: (event) => {
        // Skip the set() entirely when the reducer short-circuits; an
        // empty patch would still allocate a fresh state object and
        // notify every subscriber on the hot path.
        const patch = reducePipelineEvent(get(), event);
        if (Object.keys(patch).length > 0) {
          set(patch);
        }
      },
      resetRun: () =>
        set({
          taskId: null,
          lastSeq: 0,
          stage: "recipe",
          ...baseRunState(),
        }),
      addConvergencePoint: (point) =>
        set((s) => ({
          convergenceHistory: [...s.convergenceHistory, point],
        })),
      setRefineLoading: (loading) => set({ refineLoading: loading }),
    }),
    {
      name: "memdiver-pipeline",
      version: PIPELINE_STORE_VERSION,
      partialize: (state) => ({
        stage: state.stage,
        form: state.form,
        taskId: state.taskId,
        lastSeq: state.lastSeq,
      }),
    },
  ),
);

/**
 * Non-hook convenience used by Workspace.tsx's auto-switch guard.
 * Reads the current status without subscribing, so the
 * component it's called from doesn't re-render on every event.
 */
export function isPipelineRunning(): boolean {
  const status = usePipelineStore.getState().status;
  return status === "running" || status === "pending";
}
