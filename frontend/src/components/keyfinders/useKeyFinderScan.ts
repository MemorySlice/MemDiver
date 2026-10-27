import {
  cancelKeyFindersJob, getKeyFindersJobPayload, isKeyFindersTicket, scanKeyFinders,
  type KeyFindersJobTicket, type KeyFindersResult, type KeyFindersScanRequest,
} from "@/api/keyfinders";
import { useJobRun } from "@/hooks/useJobRun";

export interface KeyFinderScanState {
  status: "idle" | "running" | "done" | "error" | "cancelled";
  /** Set while a JOB runs (an inline scan has neither progress nor cancel). */
  taskId: string | null;
  pct: number | null;
  msg: string | null;
  result: KeyFindersResult | null;
  error: string | null;
}

/** One key-finder scan: inline answer at once, or a job followed over the task WebSocket. */
export function useKeyFinderScan(onResult?: (result: KeyFindersResult) => void) {
  const { state, run, cancel } = useJobRun<KeyFindersScanRequest, KeyFindersResult, KeyFindersJobTicket>({
    submit: scanKeyFinders,
    isTicket: isKeyFindersTicket,
    getPayload: getKeyFindersJobPayload,
    cancelJob: cancelKeyFindersJob,
    noPayloadKey: "keyfinders:run.noPayload",
    // The `done` event's `extra` stands in when the stored payload is absent.
    eventFallback: true,
    onResult,
  });
  // `cancelMode` is "immediate", so the state is never `cancelling`.
  return { state: state as KeyFinderScanState, run, cancel };
}
