/**
 * Discriminated-union payload types for backend TaskProgressEvents.
 *
 * Mirrors the ProgressBus.Event schema emitted by
 * api/services/progress_bus.py. Every ``type`` literal below carries its
 * own ``extra`` payload shape (where the backend actually attaches one),
 * so consumers narrow on ``event.type`` via a ``switch`` and read
 * ``event.extra.<field>`` with full type safety and no ``as`` casts.
 *
 * ``stage_end`` is special: its ``extra`` shape also depends on
 * ``event.stage`` (brute_force / consensus / emit_plugin each attach a
 * different payload). ``stage`` is a plain ``string`` on some
 * constituents, so TypeScript's automatic discriminated-union narrowing
 * can't reliably exclude the wrong branch on a `stage ===` check alone
 * -- use the ``isBruteForceStageEnd`` / ``isConsensusStageEnd`` /
 * ``isEmitPluginStageEnd`` type-guards below, which state the narrowed
 * type directly instead of relying on that inference.
 *
 * ``isTaskProgressEvent`` is the runtime validation boundary: the one
 * place that decides whether a value parsed off the wire is shaped
 * enough to trust as a ``TaskProgressEvent`` before it is dispatched to
 * any handler.
 */

import type { InferredField } from "./pipeline";
import type { StageTimings } from "@/stores/pipeline-store";

export type TaskProgressEventType =
  | "stage_start"
  | "progress"
  | "stage_end"
  | "funnel"
  | "nsweep_point"
  | "oracle_tick"
  | "oracle_hit"
  | "artifact"
  | "done"
  | "error";

const TASK_PROGRESS_EVENT_TYPES: ReadonlySet<string> = new Set<TaskProgressEventType>([
  "stage_start",
  "progress",
  "stage_end",
  "funnel",
  "nsweep_point",
  "oracle_tick",
  "oracle_hit",
  "artifact",
  "done",
  "error",
]);

export interface ProgressArtifact {
  name: string;
  relpath?: string;
  path?: string;
  size?: number;
  sha256?: string;
  media_type?: string;
}

/** Fields every TaskProgressEvent variant carries, regardless of type. */
interface ProgressEventBase {
  task_id: string;
  seq: number;
  ts: number;
  stage?: string | null;
  pct?: number | null;
  msg?: string | null;
  artifact?: ProgressArtifact | null;
  error?: string | null;
}

// ---- per-type `extra` payload shapes --------------------------------------

/** `progress` events for the search_reduce sub-stages carry funnel counts. */
export interface ProgressStageExtra {
  survivor_bytes?: number;
  input_bytes?: number;
}

/** One verified brute-force hit, as attached to a `stage_end` payload. */
export interface BruteForceHitPayload {
  offset?: number;
  length?: number;
  region_index?: number;
  key_hex?: string;
  neighborhood_start?: number;
  neighborhood_variance?: number[];
}

/** `stage_end` for stage === "brute_force": verified hits + threshold. */
export interface BruteForceStageEndExtra {
  verified_count?: number;
  total_candidates?: number;
  variance_threshold?: number;
  hits?: BruteForceHitPayload[];
}

/** `stage_end` for stage === "consensus": bytes folded + dump count. */
export interface ConsensusStageEndExtra {
  total_bytes?: number;
  num_dumps?: number;
}

/** `stage_end` for stage === "emit_plugin": inferred structure fields. */
export interface EmitPluginStageEndExtra {
  fields?: InferredField[];
}

/** `nsweep_point`: one (N, counts) sample from an n-sweep run. */
export interface NSweepPointExtra {
  n?: number;
  stages?: Record<string, number>;
  candidates_tried?: number;
  hits?: number;
  hit_offset?: number | null;
  timing_ms?: Partial<StageTimings>;
}

/** `oracle_hit`: a single verified key hit. */
export interface OracleHitExtra {
  offset?: number;
  size?: number;
  region_index?: number;
  key_hex?: string;
  neighborhood_start?: number;
  neighborhood_variance?: number[];
}

// ---- per-type event variants -----------------------------------------------

export interface StageStartEvent extends ProgressEventBase {
  type: "stage_start";
  extra?: Record<string, unknown> | null;
}

export interface ProgressEvent extends ProgressEventBase {
  type: "progress";
  extra?: ProgressStageExtra | null;
}

export interface BruteForceStageEndEvent extends ProgressEventBase {
  type: "stage_end";
  stage: "brute_force";
  extra?: BruteForceStageEndExtra | null;
}

export interface ConsensusStageEndEvent extends ProgressEventBase {
  type: "stage_end";
  stage: "consensus";
  extra?: ConsensusStageEndExtra | null;
}

export interface EmitPluginStageEndEvent extends ProgressEventBase {
  type: "stage_end";
  stage: "emit_plugin";
  extra?: EmitPluginStageEndExtra | null;
}

/** `stage_end` for any other stage (e.g. "reduce"): no typed extra. */
export interface GenericStageEndEvent extends ProgressEventBase {
  type: "stage_end";
  stage?: string | null;
  extra?: Record<string, unknown> | null;
}

export type StageEndEvent =
  | BruteForceStageEndEvent
  | ConsensusStageEndEvent
  | EmitPluginStageEndEvent
  | GenericStageEndEvent;

export interface FunnelEvent extends ProgressEventBase {
  type: "funnel";
  extra?: Record<string, unknown> | null;
}

export interface NSweepPointEvent extends ProgressEventBase {
  type: "nsweep_point";
  extra?: NSweepPointExtra | null;
}

export interface OracleTickEvent extends ProgressEventBase {
  type: "oracle_tick";
  extra?: Record<string, unknown> | null;
}

export interface OracleHitEvent extends ProgressEventBase {
  type: "oracle_hit";
  extra?: OracleHitExtra | null;
}

export interface ArtifactEvent extends ProgressEventBase {
  type: "artifact";
  extra?: Record<string, unknown> | null;
}

export interface DoneEvent extends ProgressEventBase {
  type: "done";
  extra?: Record<string, unknown> | null;
}

export interface ErrorEvent extends ProgressEventBase {
  type: "error";
  extra?: Record<string, unknown> | null;
}

/**
 * The full superset discriminated union the backend can emit; consumers
 * pick out the fields they care about.
 */
export type TaskProgressEvent =
  | StageStartEvent
  | ProgressEvent
  | StageEndEvent
  | FunnelEvent
  | NSweepPointEvent
  | OracleTickEvent
  | OracleHitEvent
  | ArtifactEvent
  | DoneEvent
  | ErrorEvent;

// ---- stage_end sub-narrowing guards ----------------------------------------
//
// `stage` is not a discriminant TypeScript can use automatically here
// (GenericStageEndEvent's `stage` is a plain `string`, so it isn't
// excluded by an `event.stage === "brute_force"` equality check the way
// a true literal discriminant would be). These guards state the
// narrowed type directly so callers get a precisely-typed `extra` with
// no cast.

export function isBruteForceStageEnd(
  event: TaskProgressEvent,
): event is BruteForceStageEndEvent {
  return event.type === "stage_end" && event.stage === "brute_force";
}

export function isConsensusStageEnd(
  event: TaskProgressEvent,
): event is ConsensusStageEndEvent {
  return event.type === "stage_end" && event.stage === "consensus";
}

export function isEmitPluginStageEnd(
  event: TaskProgressEvent,
): event is EmitPluginStageEndEvent {
  return event.type === "stage_end" && event.stage === "emit_plugin";
}

// ---- runtime validation boundary -------------------------------------------

/**
 * Minimal structural check that a value parsed off the wire is shaped
 * like a TaskProgressEvent: a known ``type`` literal plus the required
 * common scalar fields. This intentionally does NOT validate every
 * variant's ``extra`` shape -- the reducer already guards each field
 * defensively with ``typeof``/``Array.isArray`` checks before use. Its
 * job is to stop garbage/unknown ``type`` values and malformed common
 * fields from ever reaching a handler.
 */
export function isTaskProgressEvent(value: unknown): value is TaskProgressEvent {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.type === "string" &&
    TASK_PROGRESS_EVENT_TYPES.has(v.type) &&
    typeof v.task_id === "string" &&
    typeof v.seq === "number" &&
    typeof v.ts === "number"
  );
}
