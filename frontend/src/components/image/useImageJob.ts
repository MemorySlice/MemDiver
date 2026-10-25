import { useCallback, useState } from "react";

import { readableFailure } from "@/api/client";
import type { ImageJobTicket } from "@/api/image";
import { useTaskProgress } from "@/hooks/useTaskProgress";

export interface ImageJobState<T> {
  status: "idle" | "running" | "done" | "error";
  pct: number | null;
  msg: string | null;
  result: T | null;
  error: string | null;
}

const IDLE = { status: "idle", pct: null, msg: null, result: null, error: null } as const;

/**
 * One image job: `start(submit)` posts it, the task WebSocket reports
 * progress, and the terminal `done` event's `extra` (the producer payload)
 * becomes `result`. Failures are rendered as a sentence, never raw JSON.
 */
export function useImageJob<T>(onResult?: (result: T) => void) {
  const [taskId, setTaskId] = useState<string | null>(null);
  const [state, setState] = useState<ImageJobState<T>>(IDLE);

  useTaskProgress(taskId, {
    onProgress: (pct, msg) => setState((s) => ({ ...s, pct, msg })),
    onDone: (event) => {
      const result = (event.extra ?? null) as T | null;
      setState((s) => ({ ...s, status: "done", pct: 1, result }));
      if (result) onResult?.(result);
    },
    onError: (error) => setState((s) => ({ ...s, status: "error", error })),
  });

  const start = useCallback(async (submit: () => Promise<ImageJobTicket>) => {
    setTaskId(null);
    setState({ ...IDLE, status: "running" });
    try {
      const ticket = await submit();
      setTaskId(ticket.task_id);
    } catch (err) {
      setState({ ...IDLE, status: "error", error: readableFailure(err) });
    }
  }, []);

  return { state, start };
}
