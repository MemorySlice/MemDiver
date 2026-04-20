/**
 * Task progress WebSocket hook.
 *
 * Generic over whatever consumer wants to receive events. The
 * :class:`TaskWebSocket` handles reconnect + HTTP backfill + terminal
 * event detection; the hook just owns its lifecycle tied to the
 * ``taskId`` argument.
 *
 * Callers pass a callbacks bag; the hook guarantees the supplied
 * functions see every event at-most-once per seq. If the caller
 * omits the callbacks bag entirely (back-compat path) the hook still
 * drives the legacy ``analysis-store`` so the existing analysis tab
 * keeps working.
 *
 * Usage (pipeline tab):
 *
 *     useTaskProgress(taskId, {
 *       onEvent: (ev) => usePipelineStore.getState().ingestEvent(ev),
 *     });
 *
 * Usage (legacy analysis tab):
 *
 *     useTaskProgress(taskId);
 */

import { useEffect, useRef } from "react";

import { TaskWebSocket } from "@/api/websocket";
import type { ProgressArtifact, TaskProgressEvent } from "@/api/websocket";
import { useAnalysisStore } from "@/stores/analysis-store";

export interface UseTaskProgressCallbacks {
  /** Every event, in-order. Fired before any specialized callback. */
  onEvent?: (event: TaskProgressEvent) => void;
  /** Fine-grained progress update (stage pct + msg). */
  onProgress?: (pct: number | null, msg: string | null, event: TaskProgressEvent) => void;
  /** Stage lifecycle notification. */
  onStageStart?: (stage: string, event: TaskProgressEvent) => void;
  onStageEnd?: (stage: string, event: TaskProgressEvent) => void;
  /** Artifact registered by the worker (serialized via ProgressArtifact). */
  onArtifact?: (artifact: ProgressArtifact, event: TaskProgressEvent) => void;
  /** Terminal: task completed successfully. */
  onDone?: (event: TaskProgressEvent) => void;
  /** Terminal: task failed or was cancelled. */
  onError?: (error: string, event: TaskProgressEvent) => void;
  /** Seq from which to resume; default 0. Lets tab-switch re-mounts skip replay. */
  since?: number;
}

export function useTaskProgress(
  taskId: string | null,
  callbacks?: UseTaskProgressCallbacks,
): void {
  const wsRef = useRef<TaskWebSocket | null>(null);
  // Stable ref so the WebSocket's onmessage closure doesn't need to
  // be recreated every time the callbacks object identity changes.
  const callbacksRef = useRef<UseTaskProgressCallbacks | undefined>(callbacks);
  callbacksRef.current = callbacks;

  // Legacy analysis-store wiring; only used when no callbacks bag is
  // provided. Extracted once here so changes don't rebuild the effect.
  const legacyStore = useAnalysisStore();
  const legacySetters = useRef(legacyStore);
  legacySetters.current = legacyStore;

  useEffect(() => {
    if (!taskId) return;

    const ws = new TaskWebSocket();
    wsRef.current = ws;

    const unsubscribe = ws.onProgress((event: TaskProgressEvent) => {
      const cbs = callbacksRef.current;
      if (cbs?.onEvent) {
        cbs.onEvent(event);
      }
      switch (event.type) {
        case "stage_start":
          if (event.stage && cbs?.onStageStart) {
            cbs.onStageStart(event.stage, event);
          }
          break;
        case "stage_end":
          if (event.stage && cbs?.onStageEnd) {
            cbs.onStageEnd(event.stage, event);
          }
          break;
        case "progress":
          cbs?.onProgress?.(event.pct ?? null, event.msg ?? null, event);
          if (!cbs) {
            legacySetters.current.setProgress(event.pct ?? 0, event.msg ?? "");
          }
          break;
        case "artifact":
          if (event.artifact && cbs?.onArtifact) {
            cbs.onArtifact(event.artifact, event);
          }
          break;
        case "done":
          cbs?.onDone?.(event);
          // Legacy analysis-store fallback: the old stub never
          // delivered a real result here, so just clear the progress
          // flag by routing through setError with a sentinel empty
          // string when we have no structured extra payload.
          break;
        case "error":
          cbs?.onError?.(event.error ?? "Unknown error", event);
          if (!cbs) {
            legacySetters.current.setError(event.error ?? "Unknown error");
          }
          break;
      }
    });

    ws.connect(taskId, { since: callbacksRef.current?.since ?? 0 });

    return () => {
      unsubscribe();
      ws.close();
      wsRef.current = null;
    };
  }, [taskId]);
}
