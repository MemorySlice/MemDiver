import {
  cancelVol3Job, getVol3JobPayload, isJobTicket, runVol3Plugin,
  type Vol3JobTicket, type Vol3RunRequest, type Vol3RunResult,
} from "@/api/vol3";
import { useJobRun } from "@/hooks/useJobRun";

export interface Vol3RunState {
  status: "idle" | "running" | "cancelling" | "done" | "error" | "cancelled";
  /** Set while a JOB runs (an inline run has neither progress nor cancel). */
  taskId: string | null;
  pct: number | null;
  msg: string | null;
  result: Vol3RunResult | null;
  error: string | null;
}

/**
 * One plugin run. `run(req)` posts it: an inline answer becomes `result` at once;
 * a job ticket switches to the task WebSocket (progress, then the terminal
 * `done` event; the exact result is then fetched from the task record, the
 * event's `extra` being the rounded fallback). `cancel()` stops a job: the state
 * is `cancelling` until the task WebSocket reports a terminal event, then `cancelled`.
 */
export function useVol3Run() {
  const { state, run, cancel } = useJobRun<Vol3RunRequest, Vol3RunResult, Vol3JobTicket>({
    submit: runVol3Plugin,
    isTicket: isJobTicket,
    getPayload: getVol3JobPayload,
    cancelJob: cancelVol3Job,
    noPayloadKey: "vol3:run.noPayload",
    // The event's `extra` went through JSON.parse (kernel addresses rounded); the
    // task record's payload is the exact run document. Fall back to `extra`.
    eventFallback: true,
    cancelMode: "awaitTerminal",
  });
  const typed: Vol3RunState = state;
  return { state: typed, run, cancel };
}
