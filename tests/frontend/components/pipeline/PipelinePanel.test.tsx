import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { TaskRecord } from "@/api/pipeline";
import { usePipelineStore } from "@/stores/pipeline-store";

/**
 * Mid-run resume.
 *
 * A reload during a long brute-force stage used to leave the panel looking
 * dead: `status` is not persisted, and the only idle -> running transition is
 * a `stage_start` event that does not arrive for minutes. Both the Cancel
 * button and the "resuming" banner are gated on pending/running, so both
 * stayed hidden for the whole stage. The canonical TaskRecord now repaints
 * the run instead — the WS ring (512 events) cannot, since a stride-1 run
 * emits thousands.
 *
 * The store starts this test at "idle" on purpose: the only thing that can
 * flip it is `hydrateFromRecord`, so removing that call site fails here.
 */

const { getPipelineRunMock } = vi.hoisted(() => ({
  getPipelineRunMock: vi.fn(),
}));

vi.mock("@/api/pipeline", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/pipeline")>()),
  getPipelineRun: getPipelineRunMock,
}));

// The panel subscribes to the live WS stream; stub the hook so the test does
// not open a socket. The replay path is covered in pipeline-store.test.ts.
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: vi.fn(),
}));

const RUNNING_RECORD: TaskRecord = {
  task_id: "task-42",
  kind: "pipeline",
  status: "running",
  params: {},
  stages: [
    {
      name: "consensus",
      status: "succeeded",
      pct: 1,
      msg: "folded 4 dumps",
      started_at: 1000,
      ended_at: 1002.5,
    },
    {
      name: "brute_force",
      status: "running",
      pct: 0.12,
      msg: "tried=84000/701084 hits=0",
      started_at: 1004,
      ended_at: null,
    },
  ],
  artifacts: [],
  created_at: 999,
  started_at: 1000,
  ended_at: null,
  error: null,
  schema_version: 1,
};

describe("PipelinePanel mid-run resume", () => {
  const PRISTINE = usePipelineStore.getState();

  beforeEach(() => {
    getPipelineRunMock.mockReset();
    getPipelineRunMock.mockResolvedValue(RUNNING_RECORD);
    usePipelineStore.setState({
      ...PRISTINE,
      stage: "running",
      taskId: "task-42",
      lastSeq: 12,
      status: "idle",
    });
  });

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  it("shows the cancel button and the resuming banner for a running record", async () => {
    const { default: PipelinePanel } = await import("@/components/pipeline/PipelinePanel");
    render(<PipelinePanel />);

    await waitFor(() => {
      expect(screen.getByTestId("pipeline-cancel-btn")).toBeInTheDocument();
    });
    expect(screen.getByTestId("pipeline-resuming-banner")).toHaveTextContent(
      "task-42",
    );
  });

  it("repaints the in-flight stage instead of a blank dashboard", async () => {
    const { default: PipelinePanel } = await import("@/components/pipeline/PipelinePanel");
    render(<PipelinePanel />);

    await waitFor(() => {
      expect(usePipelineStore.getState().activeStage).toBe("brute_force");
    });
    expect(usePipelineStore.getState().status).toBe("running");
    // Hydration must never advance the progress-bus cursor, or the reducer
    // would drop every real event that follows.
    expect(usePipelineStore.getState().lastSeq).toBe(12);
  });
});
