import { useCallback, useEffect, useRef, useState } from "react";

import i18n from "@/i18n";
import { readableFailure } from "@/api/client";
import {
  cancelYaraJob, getYaraJobPayload, isYaraTicket, scanYara,
  type YaraScanRequest, type YaraScanResult,
} from "@/api/yara";
import { useTaskProgress } from "@/hooks/useTaskProgress";

export interface YaraScanState {
  status: "idle" | "running" | "done" | "error" | "cancelled";
  /** Set while a JOB runs (an inline scan has neither progress nor cancel). */
  taskId: string | null;
  /** Honest fraction 0..1 (bytes scanned over captured bytes in scope), or `null`. */
  pct: number | null;
  msg: string | null;
  result: YaraScanResult | null;
  error: string | null;
}

const IDLE: YaraScanState = {
  status: "idle", taskId: null, pct: null, msg: null, result: null, error: null,
};

async function payloadOf(taskId: string | null): Promise<YaraScanResult | null> {
  if (!taskId) return null;
  try {
    return await getYaraJobPayload(taskId);
  } catch {
    return null;
  }
}

/**
 * One YARA scan: an inline answer at once, or a job followed over the task WebSocket.
 * A job's result is ONLY the exact stored payload: the terminal event carries a summary,
 * and a summary is not a scan, so without the payload the run is an error, never "done".
 */
export function useYaraScan(onResult?: (result: YaraScanResult) => void) {
  const [state, setState] = useState<YaraScanState>(IDLE);
  const cancelled = useRef(false);
  // Bumped by `reset`: an answer that belongs to an older epoch is dropped.
  const epoch = useRef(0);
  const taskIdRef = useRef<string | null>(null);
  useEffect(() => { taskIdRef.current = state.taskId; }, [state.taskId]);

  useTaskProgress(state.taskId, {
    onProgress: (pct, msg) => setState((s) => (cancelled.current ? s : { ...s, pct, msg })),
    onDone: () => {
      const taskId = state.taskId;
      void payloadOf(taskId).then((result) => {
        if (cancelled.current) return;
        setState((s) => (s.taskId !== taskId ? s : {
          ...s, status: result ? "done" : "error", pct: 1, result,
          error: result ? null : i18n.t("yara:run.noPayload"),
        }));
        if (result) onResult?.(result);
      });
    },
    onError: (error) => setState((s) => (cancelled.current ? s : { ...s, status: "error", error })),
  });

  const run = useCallback(async (req: YaraScanRequest) => {
    cancelled.current = false;
    const mine = epoch.current;
    setState({ ...IDLE, status: "running" });
    try {
      const answer = await scanYara(req);
      if (mine !== epoch.current) {
        if (isYaraTicket(answer)) void cancelYaraJob(answer.task_id).catch(() => undefined);
        return;
      }
      if (isYaraTicket(answer)) {
        setState({ ...IDLE, status: "running", taskId: answer.task_id });
        return;
      }
      setState({ ...IDLE, status: "done", result: answer });
      onResult?.(answer);
    } catch (err) {
      if (mine !== epoch.current) return;
      setState({ ...IDLE, status: "error", error: readableFailure(err) });
    }
  }, [onResult]);

  const cancel = useCallback(async () => {
    const taskId = state.taskId;
    if (!taskId) return;
    cancelled.current = true;
    setState({ ...IDLE, status: "cancelled" });
    try {
      await cancelYaraJob(taskId);
    } catch {
      // Already finished or unknown: nothing left to wait for.
    }
  }, [state.taskId]);

  /** Drop the run and its answer (a job is cancelled at the server): the context it was for changed. */
  const reset = useCallback(() => {
    epoch.current += 1;
    const taskId = taskIdRef.current;
    cancelled.current = true;
    setState(IDLE);
    if (taskId) void cancelYaraJob(taskId).catch(() => undefined);
  }, []);

  return { state, run, cancel, reset };
}
