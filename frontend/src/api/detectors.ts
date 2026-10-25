/**
 * Typed client for the detector-fixture routes (`api/routers/detector_fixtures.py`):
 *
 *   POST /api/detector-fixtures/run — run a detector's fixtures (YARA rule / key finder)
 *
 * The verdict vocabulary is the vol3 fixtures' (`pass | fail | indeterminate`), so the
 * vol3 `VerdictBadge` renders both.
 */

import { request } from "./client";
import type { Vol3Verdict } from "./vol3";

export type DetectorKind = "yara" | "keyfinder";

export interface DetectorFixtureResult {
  fixture: string;
  source: "bundled" | "stored" | "inline";
  verdict: Vol3Verdict;
  reason: string | null;
  reason_code: string | null;
}

export interface DetectorFixtureRun {
  artifact_kind: DetectorKind;
  verdict: Vol3Verdict;
  reason: string | null;
  /** `no_fixtures` when nothing applied: indeterminate, never a pass. */
  reason_code: string | null;
  counts: { pass: number; fail: number; indeterminate: number; total: number };
  results: DetectorFixtureResult[];
  recorded: boolean;
}

/** `artifact` is a key-finder name, or the YARA rule SOURCE for `yara`. */
export const runDetectorFixtures = (
  artifactKind: DetectorKind, artifact: string, opts: { caseDir?: string; params?: Record<string, unknown> } = {},
) => request<DetectorFixtureRun>("/api/detector-fixtures/run", {
  method: "POST",
  body: JSON.stringify({
    artifact_kind: artifactKind, artifact,
    ...(opts.caseDir ? { case_dir: opts.caseDir } : {}),
    ...(opts.params ? { params: opts.params } : {}),
  }),
});
