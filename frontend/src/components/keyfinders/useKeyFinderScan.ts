import { useCallback, useRef, useState } from "react";

import i18n from "@/i18n";
import { readableFailure } from "@/api/client";
import {
  cancelKeyFindersJob, getKeyFindersJobPayload, isKeyFindersTicket, scanKeyFinders,
  type KeyFindersResult, type KeyFindersScanRequest,
} from "@/api/keyfinders";
import { useTaskProgress } from "@/hooks/useTaskProgress";

export interface KeyFinderScanState {
  status: "idle" | "running" | "done" | "error" | "cancelled";
  /** Set while a JOB runs (an inline scan has neither progress nor cancel). */
  taskId: string | null;
  pct: number | null;
  msg: string | null;
  result: KeyFindersResult | null;
  error: string | null;
}

const IDLE: KeyFinderScanState = {
  status: "idle", taskId: null, pct: null, msg: null, result: null, error: null,
};

async function payloadOf(taskId: string | null): Promise<KeyFindersResult | null> {
  if (!taskId) return null;
  try {
    return await getKeyFindersJobPayload(taskId);
  } catch {
    return null;
  }
}

/** One key-finder scan: inline answer at once, or a job followed over the task WebSocket. */
export function useKeyFinderScan(onResult?: (result: KeyFindersResult) => void) {
  const [state, setState] = useState<KeyFinderScanState>(IDLE);
  const cancelled = useRef(false);

  useTaskProgress(state.taskId, {
    onProgress: (pct, msg) => setState((s) => (cancelled.current ? s : { ...s, pct, msg })),
    onDone: (event) => {
      const taskId = state.taskId;
      void payloadOf(taskId).then((exact) => {
        if (cancelled.current) return;
        const result = exact ?? ((event.extra ?? null) as KeyFindersResult | null);
        setState((s) => (s.taskId !== taskId ? s : {
          ...s, status: result ? "done" : "error", pct: 1, result,
          error: result ? null : i18n.t("keyfinders:run.noPayload"),
        }));
        if (result) onResult?.(result);
      });
    },
    onError: (error) => setState((s) => (cancelled.current ? s : { ...s, status: "error", error })),
  });

  const run = useCallback(async (req: KeyFindersScanRequest) => {
    cancelled.current = false;
    setState({ ...IDLE, status: "running" });
    try {
      const answer = await scanKeyFinders(req);
      if (isKeyFindersTicket(answer)) {
        setState({ ...IDLE, status: "running", taskId: answer.task_id });
        return;
      }
      setState({ ...IDLE, status: "done", result: answer });
      onResult?.(answer);
    } catch (err) {
      setState({ ...IDLE, status: "error", error: readableFailure(err) });
    }
  }, [onResult]);

  const cancel = useCallback(async () => {
    const taskId = state.taskId;
    if (!taskId) return;
    cancelled.current = true;
    setState({ ...IDLE, status: "cancelled" });
    try {
      await cancelKeyFindersJob(taskId);
    } catch {
      // Already finished or unknown: nothing left to wait for.
    }
  }, [state.taskId]);

  return { state, run, cancel };
}
