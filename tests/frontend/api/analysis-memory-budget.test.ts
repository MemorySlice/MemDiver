import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { runAnalysisAndWait } from "@/api/analysis";
import { useMemoryBudgetStore } from "@/stores/memory-budget-store";

const BODY = { library_dirs: ["/d/lib"], phase: "p", protocol_version: "13" };

function json(body: unknown, status = 200): Response {
  return {
    ok: status < 400,
    status,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

const fetchMock = vi.fn();
beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  useMemoryBudgetStore.setState({ pending: null });
});
afterEach(() => vi.unstubAllGlobals());

describe("runAnalysisAndWait on a background memory-budget failure", () => {
  it("asks, then re-submits the same body with force_memory", async () => {
    const posted: unknown[] = [];
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === "/api/analysis/run") {
        posted.push(JSON.parse(String(init?.body)));
        return json({ task_id: `t${posted.length}` });
      }
      if (url === "/api/pipeline/runs/t1") {
        return json({
          task_id: "t1",
          status: "failed",
          error: "over budget",
          error_info: { code: "memory_budget_exceeded", estimate_bytes: 10, budget_bytes: 5 },
        });
      }
      if (url === "/api/pipeline/runs/t2") return json({ task_id: "t2", status: "succeeded" });
      return json({ ok: true }); // the analysis_result artifact
    });

    const result = runAnalysisAndWait(BODY, { pollMs: 1 });
    await vi.waitFor(() => expect(useMemoryBudgetStore.getState().pending).not.toBeNull());
    expect(useMemoryBudgetStore.getState().pending?.info.budgetBytes).toBe(5);
    useMemoryBudgetStore.getState().answer(true);

    await expect(result).resolves.toEqual({ ok: true });
    expect(posted).toEqual([BODY, { ...BODY, force_memory: true }]);
  });
});
