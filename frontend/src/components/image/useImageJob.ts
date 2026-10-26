import { useCallback, useEffect, useRef, useState } from "react";

import i18n from "@/i18n";
import { readableFailure } from "@/api/client";
import { cancelImageJob, type ImageJobTicket } from "@/api/image";
import { useTaskProgress } from "@/hooks/useTaskProgress";
import { implicatedOf, type ImplicatedItem } from "./failure-details";

export interface ImageJobState<T> {
  status: "idle" | "running" | "done" | "error" | "cancelled";
  pct: number | null;
  msg: string | null;
  /** Pakunoda stage + seconds elapsed, from a progress event's `extra` (null when absent). */
  stage: string | null;
  elapsedS: number | null;
  /** Seconds since the job was started (client clock; null while idle). */
  totalElapsedS: number | null;
  /** True once Cancel was clicked, until the job ends. */
  cancelling: boolean;
  result: T | null;
  error: string | null;
  /** Items a rejected submit named as the cause (e.g. `profile_build_failed`). */
  implicated?: ImplicatedItem[];
}

const IDLE = {
  status: "idle", pct: null, msg: null, stage: null, elapsedS: null, totalElapsedS: null, cancelling: false,
  result: null, error: null,
} as const;

const CANCELLED_ERROR = "cancelled";
const TICK_MS = 250;

/** Last reported stage seconds + the client time that report arrived. */
interface StageAnchor { elapsedS: number; receivedAt: number }

/**
 * One image job: `start(submit)` posts it, the task WebSocket reports
 * progress, and the terminal `done` event's `extra` (the producer payload)
 * becomes `result`. Failures are rendered as a sentence, never raw JSON.
 */
export function useImageJob<T>(
  onResult?: (result: T) => void,
  /** Read the result from the stored task payload (lossless) instead of the `done` event. */
  loadPayload?: (taskId: string) => Promise<T | null>,
) {
  const [taskId, setTaskId] = useState<string | null>(null);
  const [state, setState] = useState<ImageJobState<T>>(IDLE);
  const cancelled = useRef(false);
  const [stageAnchor, setStageAnchor] = useState<StageAnchor | null>(null);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());

  // Tick only while running, so an idle panel never re-renders on a timer.
  useEffect(() => {
    if (state.status !== "running") return;
    const id = setInterval(() => setNow(Date.now()), TICK_MS);
    return () => clearInterval(id);
  }, [state.status]);

  useTaskProgress(taskId, {
    onProgress: (pct, msg, event) => {
      const extra = (event.extra ?? {}) as { pakunoda_stage?: unknown; elapsed_s?: unknown };
      const stage = typeof extra.pakunoda_stage === "string" ? extra.pakunoda_stage : null;
      const elapsedS = typeof extra.elapsed_s === "number" ? extra.elapsed_s : null;
      if (cancelled.current) return;
      if (stage !== null && elapsedS !== null) setStageAnchor({ elapsedS, receivedAt: Date.now() });
      else if (stage === null) setStageAnchor(null);
      setState((s) => ({ ...s, pct, msg, stage, elapsedS }));
    },
    onDone: (event) => {
      if (cancelled.current) return;
      if (loadPayload && taskId) {
        void loadPayload(taskId).then((result) => {
          if (cancelled.current) return;
          setState((s) => (result
            ? { ...s, status: "done", pct: 1, result }
            : { ...s, status: "error", error: i18n.t("image:job.noPayload") }));
          if (result) onResult?.(result);
        }).catch((err) => {
          if (!cancelled.current) setState((s) => ({ ...s, status: "error", error: readableFailure(err) }));
        });
        return;
      }
      const result = (event.extra ?? null) as T | null;
      setState((s) => ({ ...s, status: "done", pct: 1, result }));
      if (result) onResult?.(result);
    },
    onError: (error) => setState((s) => (error === CANCELLED_ERROR || cancelled.current
      ? { ...IDLE, status: "cancelled" }
      : { ...s, status: "error", cancelling: false, error })),
  });

  const start = useCallback(async (submit: () => Promise<ImageJobTicket>) => {
    cancelled.current = false;
    setStageAnchor(null);
    const t0 = Date.now();
    setStartedAt(t0);
    setNow(t0);
    setTaskId(null);
    setState({ ...IDLE, status: "running" });
    try {
      const ticket = await submit();
      setTaskId(ticket.task_id);
    } catch (err) {
      setState({ ...IDLE, status: "error", error: readableFailure(err), implicated: implicatedOf(err) });
    }
  }, []);

  const cancel = useCallback(async () => {
    if (!taskId) return;
    cancelled.current = true;
    setState((s) => ({ ...s, cancelling: true }));
    try {
      await cancelImageJob(taskId);
    } catch {
      // Already finished or unknown: nothing is left to wait for.
    }
    setState({ ...IDLE, status: "cancelled" });
  }, [taskId]);

  return { state: withLiveClocks(state, stageAnchor, startedAt, now), start, cancel, taskId };
}

/** Extrapolate the reported stage seconds and the job total to `now` while running. */
function withLiveClocks<T>(
  state: ImageJobState<T>, anchor: StageAnchor | null, startedAt: number | null, now: number,
): ImageJobState<T> {
  if (state.status !== "running") return state;
  const sinceS = (from: number) => Math.max(0, (now - from) / 1000);
  const elapsedS = anchor ? anchor.elapsedS + sinceS(anchor.receivedAt) : state.elapsedS;
  const totalElapsedS = startedAt === null ? null : sinceS(startedAt);
  return { ...state, elapsedS, totalElapsedS };
}
