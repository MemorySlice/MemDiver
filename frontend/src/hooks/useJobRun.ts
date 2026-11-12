/**
 * One "inline answer or background job" run, shared by the feature hooks
 * (`useKeyFinderScan`, `useYaraScan`, `useVol3Run`).
 *
 * `run(req)` submits the request. An inline answer becomes `result` at once; a
 * job ticket switches to the task WebSocket (progress, then the terminal
 * `done` event), after which the exact result is fetched from the stored task
 * payload. Without a payload the run is an error -- unless `eventFallback` lets
 * the `done` event's `extra` (decoded by `JSON.parse`, so possibly rounded)
 * stand in for it.
 *
 * `cancel()` stops a job. With `cancelMode: "immediate"` the state becomes
 * `cancelled` at once and the WebSocket is dropped; with `"awaitTerminal"` it
 * stays `cancelling` until the WebSocket reports a terminal event.
 *
 * `reset()` drops the run and any answer still in flight (a job is cancelled
 * at the server): an answer that belongs to an older epoch is ignored.
 *
 * `onEvent` sees every raw task event of the followed job (e.g. a queued job's
 * first `stage_start`, or a failure's `extra.code`), before the hook's own
 * handling; the state shape stays the same for every caller.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import i18n from "@/i18n";
import { readableFailure } from "@/api/client";
import type { TaskProgressEvent } from "@/api/websocket";
import { useTaskProgress } from "@/hooks/useTaskProgress";

export type JobRunStatus = "idle" | "running" | "cancelling" | "done" | "error" | "cancelled";

export interface JobRunState<Res> {
  status: JobRunStatus;
  /** Set while a JOB runs (an inline run has neither progress nor cancel). */
  taskId: string | null;
  pct: number | null;
  msg: string | null;
  result: Res | null;
  error: string | null;
}

/** The answer a submit returns when the server queued the work as a task. */
export interface JobTicketLike {
  task_id: string;
}

export interface JobRunConfig<Req, Res, Ticket extends JobTicketLike> {
  /** Post the request: the inline answer, or a job ticket. */
  submit: (req: Req) => Promise<Res | Ticket>;
  isTicket: (answer: Res | Ticket) => answer is Ticket;
  /** The finished job's stored (lossless) payload, or `null`. */
  getPayload: (taskId: string) => Promise<Res | null>;
  cancelJob: (taskId: string) => Promise<unknown>;
  /** i18n key of the error shown when a finished job has no result. */
  noPayloadKey: string;
  /** Use the `done` event's `extra` when the stored payload is absent. */
  eventFallback?: boolean;
  /** Default `"immediate"`; see the module comment. */
  cancelMode?: "immediate" | "awaitTerminal";
  /** Called with every result (inline or job). */
  onResult?: (result: Res) => void;
  /** Called with every raw event of the followed job's task WebSocket, in order. */
  onEvent?: (event: TaskProgressEvent) => void;
}

export const JOB_RUN_IDLE: JobRunState<never> = {
  status: "idle", taskId: null, pct: null, msg: null, result: null, error: null,
};

const idle = <Res>(): JobRunState<Res> => JOB_RUN_IDLE;

/** The stored payload of `taskId`, or `null` (no task, absent, or unreachable). */
async function payloadOf<Res>(
  getPayload: (taskId: string) => Promise<Res | null>,
  taskId: string | null,
): Promise<Res | null> {
  if (!taskId) return null;
  try {
    return await getPayload(taskId);
  } catch {
    return null;
  }
}

/** A requested cancel ends here: `cancelling` becomes `cancelled`, anything else is kept. */
const settleCancel = <Res>(s: JobRunState<Res>): JobRunState<Res> =>
  (s.status === "cancelling" ? { ...idle<Res>(), status: "cancelled" } : s);

export function useJobRun<Req, Res, Ticket extends JobTicketLike>({
  submit, isTicket, getPayload, cancelJob, noPayloadKey,
  eventFallback = false, cancelMode = "immediate", onResult, onEvent,
}: JobRunConfig<Req, Res, Ticket>) {
  const [state, setState] = useState<JobRunState<Res>>(idle);
  const cancelled = useRef(false);
  // Set once the job's `done` arrived: a terminal success wins over a later or
  // racing Cancel (with `awaitTerminal`, a job that succeeded despite a Cancel
  // click shows its result instead of sticking in `cancelling`).
  const doneSeen = useRef(false);
  // Bumped by `reset`: an answer that belongs to an older epoch is dropped.
  const epoch = useRef(0);
  const taskIdRef = useRef<string | null>(null);
  useEffect(() => { taskIdRef.current = state.taskId; }, [state.taskId]);

  const finishJob = (taskId: string | null, event: TaskProgressEvent) => {
    const mine = epoch.current;
    void payloadOf(getPayload, taskId).then((exact) => {
      if (mine !== epoch.current) return; // reset meanwhile: the answer is stale
      const result = exact ?? (eventFallback ? ((event.extra ?? null) as Res | null) : null);
      setState((s) => (s.taskId !== taskId ? s : {
        ...s, status: result ? "done" : "error", pct: 1, result,
        error: result ? null : i18n.t(noPayloadKey),
      }));
      if (result) onResult?.(result);
    });
  };

  useTaskProgress(state.taskId, {
    onEvent,
    onProgress: (pct, msg) => setState((s) => (cancelled.current ? s : { ...s, pct, msg })),
    onDone: (event) => {
      doneSeen.current = true;
      if (cancelled.current && cancelMode === "immediate") {
        setState(settleCancel);
        return;
      }
      finishJob(state.taskId, event);
    },
    onError: (error) => setState((s) => (cancelled.current ? settleCancel(s) : { ...s, status: "error", error })),
  });

  const run = useCallback(async (req: Req) => {
    cancelled.current = false;
    doneSeen.current = false;
    const mine = epoch.current;
    setState({ ...idle<Res>(), status: "running" });
    try {
      const answer = await submit(req);
      if (mine !== epoch.current) {
        if (isTicket(answer)) void cancelJob(answer.task_id).catch(() => undefined);
        return;
      }
      if (isTicket(answer)) {
        setState({ ...idle<Res>(), status: "running", taskId: answer.task_id });
        return;
      }
      setState({ ...idle<Res>(), status: "done", result: answer });
      onResult?.(answer);
    } catch (err) {
      if (mine !== epoch.current) return;
      setState({ ...idle<Res>(), status: "error", error: readableFailure(err) });
    }
  }, [submit, isTicket, cancelJob, onResult]);

  const cancel = useCallback(async () => {
    const taskId = state.taskId;
    if (!taskId || doneSeen.current) return; // nothing left to cancel: it succeeded
    cancelled.current = true;
    setState(cancelMode === "awaitTerminal"
      ? (s) => ({ ...s, status: "cancelling", pct: null, msg: null })
      : { ...idle<Res>(), status: "cancelled" });
    try {
      await cancelJob(taskId);
    } catch {
      // Already finished or unknown: nothing left to wait for.
    }
  }, [state.taskId, cancelMode, cancelJob]);

  /** Drop the run and its answer (a job is cancelled at the server): the context it was for changed. */
  const reset = useCallback(() => {
    epoch.current += 1;
    const taskId = taskIdRef.current;
    cancelled.current = true;
    setState(idle<Res>());
    if (taskId) void cancelJob(taskId).catch(() => undefined);
  }, [cancelJob]);

  return { state, run, cancel, reset };
}
