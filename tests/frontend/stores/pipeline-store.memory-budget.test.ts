import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { usePipelineStore } from "@/stores/pipeline-store";
import { useMemoryBudgetStore } from "@/stores/memory-budget-store";
import type { PipelineRunRequest } from "@/api/pipeline";

const BODY: PipelineRunRequest = { source_paths: ["/a.msl", "/b.msl"], oracle_id: "o1" };
const BUDGET_EVENT = {
  error: "over budget",
  extra: { code: "memory_budget_exceeded", estimate_bytes: 10, budget_bytes: 5 },
};

const fetchMock = vi.fn();
let taskCounter = 0;

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockImplementation(async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ task_id: "forced-task", status: "pending" }),
  }));
  vi.stubGlobal("fetch", fetchMock);
  useMemoryBudgetStore.setState({ pending: null });
  taskCounter += 1;
  usePipelineStore.getState().setTaskId(`failed-${taskCounter}`);
  usePipelineStore.getState().setLastRunRequest(BODY);
  usePipelineStore.setState({ stage: "results" });
});
afterEach(() => vi.unstubAllGlobals());

describe("pipeline-store offerForcedRerun", () => {
  it("re-submits the last body with force_memory on Run anyway", async () => {
    const done = usePipelineStore.getState().offerForcedRerun(BUDGET_EVENT);
    await vi.waitFor(() => expect(useMemoryBudgetStore.getState().pending).not.toBeNull());
    useMemoryBudgetStore.getState().answer(true);
    await done;

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/pipeline/run");
    expect(JSON.parse(String(init.body))).toEqual(
      expect.objectContaining({ ...BODY, force_memory: true }),
    );
    const state = usePipelineStore.getState();
    expect(state.taskId).toBe("forced-task");
    expect(state.stage).toBe("running");
    expect(state.lastRunRequest).toEqual(BODY);
  });

  it("does nothing on cancel", async () => {
    const before = usePipelineStore.getState().taskId;
    const done = usePipelineStore.getState().offerForcedRerun(BUDGET_EVENT);
    await vi.waitFor(() => expect(useMemoryBudgetStore.getState().pending).not.toBeNull());
    useMemoryBudgetStore.getState().answer(false);
    await done;
    expect(fetchMock).not.toHaveBeenCalled();
    expect(usePipelineStore.getState().taskId).toBe(before);
  });

  it("ignores failures that are not memory-budget refusals", async () => {
    await usePipelineStore.getState().offerForcedRerun({ error: "boom" });
    expect(useMemoryBudgetStore.getState().pending).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
