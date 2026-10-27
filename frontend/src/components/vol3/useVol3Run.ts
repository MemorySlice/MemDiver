import { useCallback, useRef, useState } from "react";

import { readableFailure } from "@/api/client";
import {
  cancelVol3Job, getVol3JobPayload, isJobTicket, runVol3Plugin, type Vol3RunRequest, type Vol3RunResult,
} from "@/api/vol3";
import { useTaskProgress } from "@/hooks/useTaskProgress";

export interface Vol3RunState {
  status: "idle" | "running" | "cancelling" | "done" | "error" | "cancelled";
  /** Set while a JOB runs (an inline run has neither progress nor cancel). */
  taskId: string | null;
  pct: number | null;
  msg: string | null;
  result: Vol3RunResult | null;
  error: string | null;
}

const IDLE: Vol3RunState = {
  status: "idle", taskId: null, pct: null, msg: null, result: null, error: null,
};

/** The lossless run document of a finished job, or `null` (absent or unreachable). */
async function exactPayload(taskId: string | null): Promise<Vol3RunResult | null> {
  if (!taskId) return null;
  try {
    return await getVol3JobPayload(taskId);
  } catch {
    return null;
  }
}

/**
 * One plugin run. `run(req)` posts it: an inline answer becomes `result` at once;
 * a job ticket switches to the task WebSocket (progress, then the terminal
 * `done` event; the exact result is then fetched from the task record, the
 * event's `extra` being the rounded fallback). `cancel()` stops a job: the state
 * is `cancelling` until the task WebSocket reports a terminal event, then `cancelled`.
 */
export function useVol3Run() {
  const [state, setState] = useState<Vol3RunState>(IDLE);
  const cancelled = useRef(false);

  useTaskProgress(state.taskId, {
    onProgress: (pct, msg) => setState((s) => (cancelled.current ? s : { ...s, pct, msg })),
    onDone: (event) => {
      const taskId = state.taskId;
      if (cancelled.current) {
        setState((s) => (s.status === "cancelling" ? { ...IDLE, status: "cancelled" } : s));
        return;
      }
      // The event's `extra` went through JSON.parse (kernel addresses rounded); the
      // task record's payload is the exact run document. Fall back to `extra`.
      void exactPayload(taskId).then((exact) => {
        const result = exact ?? ((event.extra ?? null) as Vol3RunResult | null);
        setState((s) => (cancelled.current || s.taskId !== taskId ? s : {
          ...s, status: result ? "done" : "error", pct: 1, result,
          error: result ? null : "The job finished without a result payload.",
        }));
      });
    },
    onError: (error) => setState((s) => {
      if (cancelled.current) return s.status === "cancelling" ? { ...IDLE, status: "cancelled" } : s;
      return { ...s, status: "error", error };
    }),
  });

  const run = useCallback(async (req: Vol3RunRequest) => {
    cancelled.current = false;
    setState({ ...IDLE, status: "running" });
    try {
      const answer = await runVol3Plugin(req);
      setState(isJobTicket(answer)
        ? { ...IDLE, status: "running", taskId: answer.task_id }
        : { ...IDLE, status: "done", result: answer });
    } catch (err) {
      setState({ ...IDLE, status: "error", error: readableFailure(err) });
    }
  }, []);

  const cancel = useCallback(async () => {
    const taskId = state.taskId;
    if (!taskId) return;
    cancelled.current = true;
    setState((s) => ({ ...s, status: "cancelling", pct: null, msg: null }));
    try {
      await cancelVol3Job(taskId);
    } catch {
      // Already finished or unknown: the job is no longer ours to wait for.
    }
  }, [state.taskId]);

  return { state, run, cancel };
}
