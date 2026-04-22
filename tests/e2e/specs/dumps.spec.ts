import { test, expect } from "@playwright/test";
import path from "node:path";
import { DATASET_ROOT, datasetAvailable } from "../fixtures/dataset";

// The /api/dataset/runs endpoint discovers runs one level up from the
// run_NNNN directories. The top-level dataset_memory_slice root has a
// nested layout; the scanner expects the immediate parent of run_NNNN.
const SCAN_ROOT = path.join(DATASET_ROOT, "gocryptfs/dataset_gocryptfs");

const BACKEND_PORT = process.env.BACKEND_PORT ?? "8091";
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;

test.describe("Dataset discovery — /api/dataset/runs", () => {
  test.skip(!datasetAvailable, "Dataset not present on this machine.");
  // /api/dataset/runs walks the full dataset tree; on this machine it
  // takes ~32s cold and can exceed the default 60s test budget when
  // the backend has been warmed up by earlier specs. Bump the per-test
  // budget so we surface the real response instead of a Playwright-
  // aborted request. If this regresses further, add a perf assertion
  // against a tighter budget (see tests/e2e/docs/perf-baseline.md).
  test.setTimeout(180_000);

  test("run_0001 is discovered with the expected pid", async ({ request }) => {
    const resp = await request.get(
      `${BACKEND_URL}/api/dataset/runs?root=${encodeURIComponent(SCAN_ROOT)}`,
    );
    expect(resp.ok(), `GET /api/dataset/runs failed: ${resp.status()}`).toBe(
      true,
    );
    const json = (await resp.json()) as {
      runs: { path: string; meta?: Record<string, unknown>; dumps?: unknown[] }[];
    };
    expect(Array.isArray(json.runs)).toBe(true);
    expect(json.runs.length).toBeGreaterThanOrEqual(1);

    // Find the run with pid 65219 — the one in run_0001/meta.json.
    const match = json.runs.find((r) => {
      const pid = (r.meta as { pid?: number } | undefined)?.pid;
      return pid === 65219;
    });
    expect(
      match,
      `no run with meta.pid === 65219 in ${json.runs.length} runs`,
    ).toBeDefined();
  });
});
