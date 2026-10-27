import {
  cancelYaraJob, getYaraJobPayload, isYaraTicket, scanYara,
  type YaraJobTicket, type YaraScanRequest, type YaraScanResult,
} from "@/api/yara";
import { useJobRun } from "@/hooks/useJobRun";

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

/**
 * One YARA scan: an inline answer at once, or a job followed over the task WebSocket.
 * A job's result is ONLY the exact stored payload: the terminal event carries a summary,
 * and a summary is not a scan, so without the payload the run is an error, never "done".
 * `reset()` drops the run and its answer (a job is cancelled at the server).
 */
export function useYaraScan(onResult?: (result: YaraScanResult) => void) {
  const { state, run, cancel, reset } = useJobRun<YaraScanRequest, YaraScanResult, YaraJobTicket>({
    submit: scanYara,
    isTicket: isYaraTicket,
    getPayload: getYaraJobPayload,
    cancelJob: cancelYaraJob,
    noPayloadKey: "yara:run.noPayload",
    onResult,
  });
  // `cancelMode` is "immediate", so the state is never `cancelling`.
  return { state: state as YaraScanState, run, cancel, reset };
}
