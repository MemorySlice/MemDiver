/**
 * The memory-guard override, centralised.
 *
 * Budget-gated endpoints refuse with HTTP 507 and a JSON envelope
 * `{error, code: "memory_budget_exceeded", category, message, estimate_bytes,
 * budget_bytes, details}`. `withMemoryBudgetOverride` turns that refusal into
 * a question (rendered by `MemoryBudgetDialog`) and, if the user confirms,
 * re-sends the same request with `force_memory: true`.
 */

import { ApiError } from "./client";
import {
  useMemoryBudgetStore,
  type MemoryBudgetInfo,
} from "@/stores/memory-budget-store";

export type { MemoryBudgetInfo } from "@/stores/memory-budget-store";

export const MEMORY_BUDGET_CODE = "memory_budget_exceeded";
const INSUFFICIENT_STORAGE = 507;

type Envelope = Record<string, unknown>;

function parseEnvelope(body: string): Envelope | null {
  try {
    const parsed: unknown = JSON.parse(body);
    if (!parsed || typeof parsed !== "object") return null;
    // Tolerate FastAPI's `{"detail": {...}}` wrapping as well as the flat body.
    const detail = (parsed as Envelope).detail;
    return detail && typeof detail === "object" ? (detail as Envelope) : (parsed as Envelope);
  } catch {
    return null;
  }
}

const numberOrNull = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

const firstString = (...values: unknown[]): string | undefined =>
  values.find((v): v is string => typeof v === "string" && v.trim() !== "");

function infoFromEnvelope(envelope: Envelope, fallbackMessage: string): MemoryBudgetInfo {
  const details = (envelope.details ?? {}) as Envelope;
  return {
    message: firstString(envelope.message, envelope.error) ?? fallbackMessage,
    estimateBytes: numberOrNull(envelope.estimate_bytes ?? details.estimate_bytes),
    budgetBytes: numberOrNull(envelope.budget_bytes ?? details.budget_bytes),
  };
}

/**
 * A background task (pipeline / analysis run) that failed on the memory
 * guard. Thrown by pollers such as `awaitAnalysisResult` so the failure flows
 * through `withMemoryBudgetOverride` exactly like a synchronous 507.
 */
export class MemoryBudgetTaskError extends Error {
  info: MemoryBudgetInfo;
  constructor(info: MemoryBudgetInfo) {
    super(info.message);
    this.name = "MemoryBudgetTaskError";
    this.info = info;
  }
}

/** The refusal's details, or `null` when `err` is any other failure. */
export function isMemoryBudgetError(err: unknown): MemoryBudgetInfo | null {
  if (err instanceof MemoryBudgetTaskError) return err.info;
  if (!(err instanceof ApiError)) return null;
  const envelope = parseEnvelope(err.body) ?? {};
  const isBudget =
    envelope.code === MEMORY_BUDGET_CODE ||
    (err.status === INSUFFICIENT_STORAGE && envelope.code === undefined);
  return isBudget ? infoFromEnvelope(envelope, err.message) : null;
}

/**
 * What a failed background task reports: the terminal WebSocket `error` event
 * (`error` + `extra`) or the task record (`error` + `error_info`).
 */
export interface TaskFailureSource {
  error?: string | null;
  // `object` so every TaskProgressEvent variant's typed `extra` is accepted.
  extra?: object | null;
  error_info?: object | null;
}

/** The memory-guard details of a failed task, or `null` for any other failure. */
export function memoryBudgetInfoFromTask(source: TaskFailureSource): MemoryBudgetInfo | null {
  const envelope = (source.error_info ?? source.extra) as Envelope | null | undefined;
  if (!envelope || envelope.code !== MEMORY_BUDGET_CODE) return null;
  return infoFromEnvelope(
    { ...envelope, message: envelope.message ?? source.error },
    source.error ?? "",
  );
}

export type MemoryBudgetConfirm = (info: MemoryBudgetInfo) => Promise<boolean>;

const askViaDialog: MemoryBudgetConfirm = (info) =>
  useMemoryBudgetStore.getState().ask(info);

/**
 * Run `send(false)`; on a memory-budget refusal ask `confirm` and, if the user
 * agrees, run `send(true)`. A declined prompt rethrows the ORIGINAL refusal,
 * so call sites keep surfacing it through their existing error handling.
 * Any other error passes through untouched.
 */
export async function withMemoryBudgetOverride<T>(
  send: (forceMemory: boolean) => Promise<T>,
  confirm: MemoryBudgetConfirm = askViaDialog,
): Promise<T> {
  try {
    return await send(false);
  } catch (err) {
    const info = isMemoryBudgetError(err);
    if (!info || !(await confirm(info))) throw err;
    return send(true);
  }
}

/** `body` with `force_memory: true` added only when forcing, so unforced bodies stay unchanged. */
export function withForceMemory<B extends object>(
  body: B,
  forceMemory: boolean,
): B & { force_memory?: boolean } {
  return forceMemory ? { ...body, force_memory: true } : body;
}

/** Task ids already offered a forced re-run, so a replayed error event never asks twice. */
const offeredTaskIds = new Set<string>();

/**
 * The background-task counterpart of `withMemoryBudgetOverride`: when task
 * `taskId` failed on the memory guard, ask once and, if confirmed, run
 * `resubmit` (which re-sends the original body with `force_memory: true`).
 * Resolves `null` when the failure was something else or the user declined.
 */
export async function offerForcedResubmit<T>(
  taskId: string,
  source: TaskFailureSource,
  resubmit: () => Promise<T>,
  confirm: MemoryBudgetConfirm = askViaDialog,
): Promise<T | null> {
  const info = memoryBudgetInfoFromTask(source);
  if (!info || offeredTaskIds.has(taskId)) return null;
  offeredTaskIds.add(taskId);
  return (await confirm(info)) ? resubmit() : null;
}
