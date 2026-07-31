/**
 * Higher-level helpers for the async analysis surface.
 *
 * ``POST /api/analysis/run`` and ``/run-file`` no longer run their
 * GIL-bound algorithm loops inline — they dispatch the work onto the
 * TaskManager's ProcessPool and return a ``task_id`` immediately (mirror
 * of the pipeline + batch endpoints). This module layers the two ways a
 * caller consumes that task on top of the low-level submit helpers in
 * ``@/api/client``:
 *
 *  - ``fetchAnalysisResult`` downloads the full ``AnalysisResult`` from
 *    the ``analysis_result`` artifact once a task has succeeded.
 *  - ``awaitAnalysisResult`` / ``runAnalysisAndWait`` poll the shared
 *    task-record endpoint to completion and then resolve with the
 *    result — used by callers (e.g. the scan re-run buttons) that just
 *    want a promise of the result and don't render live progress.
 *
 * Components that DO want live progress (AnalysisPanel) submit via
 * ``@/api/client`` and drive ``useTaskProgress`` + ``fetchAnalysisResult``
 * directly, reusing the same websocket.ts client as the pipeline tab.
 */

import { runAnalysis } from "./client";
import { getPipelineRun, artifactDownloadUrl } from "./pipeline";
import { request } from "./client";
import type { AnalyzeRequest, AnalysisResult } from "./types";

/** Name of the artifact the analysis runner registers (see app.pipeline.analysis_task_runner). */
export const ANALYSIS_RESULT_ARTIFACT = "analysis_result";

const TERMINAL_STATUSES = new Set(["succeeded", "failed", "cancelled"]);

/**
 * Download and parse the full ``AnalysisResult`` for a succeeded task.
 * The runner writes it as ``analysis/result.json`` and registers it under
 * the ``analysis_result`` name, served (as JSON) via the shared artifact
 * route used by the pipeline tab.
 */
export const fetchAnalysisResult = (taskId: string): Promise<AnalysisResult> =>
  request<AnalysisResult>(artifactDownloadUrl(taskId, ANALYSIS_RESULT_ARTIFACT));

export interface AwaitOptions {
  /** Poll interval in ms. Default 250. */
  pollMs?: number;
  /** Overall timeout in ms. Default 180000 (3 min). */
  timeoutMs?: number;
}

/**
 * Poll ``GET /api/pipeline/runs/{taskId}`` until the task reaches a
 * terminal state, then resolve with the downloaded result (or throw on
 * failure/cancel/timeout).
 */
export async function awaitAnalysisResult(
  taskId: string,
  { pollMs = 250, timeoutMs = 180_000 }: AwaitOptions = {},
): Promise<AnalysisResult> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const record = await getPipelineRun(taskId);
    if (TERMINAL_STATUSES.has(record.status)) {
      if (record.status !== "succeeded") {
        throw new Error(record.error ?? `analysis ${record.status}`);
      }
      return fetchAnalysisResult(taskId);
    }
    if (Date.now() > deadline) {
      throw new Error("analysis task timed out");
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}

/** Submit a library analysis and resolve with its result once complete. */
export async function runAnalysisAndWait(
  body: AnalyzeRequest,
  options?: AwaitOptions,
): Promise<AnalysisResult> {
  const { task_id } = await runAnalysis(body);
  return awaitAnalysisResult(task_id, options);
}
