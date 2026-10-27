import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";

const api = vi.hoisted(() => ({ runVol3Plugin: vi.fn(), cancelVol3Job: vi.fn() }));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));
const ws = vi.hoisted(() => ({ cbs: {} as Record<string, (...a: unknown[]) => void> }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (_id: string | null, cbs: Record<string, (...a: unknown[]) => void>) => { ws.cbs = cbs; },
}));
const { useVol3Run } = await import("@/components/vol3/useVol3Run");

const KVA = "18446612682103128064"; // > 2^53: JSON.parse would round it
const doc = `{"plugin":"p","columns":[],"rows":[{"depth":0,"values":[${KVA}],"absent":{}}],"view":{"kind":"process","pid":7,"capture_id":"c","view_path":"/v.mdview"}}`;
const rounded = { plugin: "p", columns: [], rows: [{ depth: 0, values: [1.8446612682103128e19], absent: {} }] };

const fetchMock = vi.fn();
beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  api.runVol3Plugin.mockResolvedValue({ task_id: "t1", status: "pending" });
});
afterEach(() => vi.unstubAllGlobals());

const startJob = async () => {
  const hook = renderHook(() => useVol3Run());
  await act(async () => { await hook.result.current.run({ view_path: "/v.mdview", plugin: "p", async: true }); });
  return hook;
};
const reply = (body: string, ok = true) =>
  fetchMock.mockResolvedValue({ ok, status: ok ? 200 : 500, text: async () => body });

describe("useVol3Run job results", () => {
  it("fetches the task record's payload and parses it losslessly", async () => {
    reply(`{"task_id":"t1","result":{},"payload":${doc}}`);
    const hook = await startJob();
    act(() => ws.cbs.onDone({ extra: rounded }));
    await waitFor(() => expect(hook.result.current.state.status).toBe("done"));
    expect(fetchMock).toHaveBeenCalledWith("/api/tasks/t1/result");
    const result = hook.result.current.state.result!;
    expect(result.rows[0].values[0]).toBe(KVA);
    expect(result.view?.pid).toBe(7);
  });

  it("falls back to the WebSocket result when the payload is null", async () => {
    reply(`{"task_id":"t1","payload":null}`);
    const hook = await startJob();
    act(() => ws.cbs.onDone({ extra: rounded }));
    await waitFor(() => expect(hook.result.current.state.status).toBe("done"));
    expect(hook.result.current.state.result!.rows[0].values[0]).toBe(1.8446612682103128e19);
  });

  it("falls back when the fetch fails, and errors only if there is no result at all", async () => {
    reply("boom", false);
    const hook = await startJob();
    act(() => ws.cbs.onDone({ extra: rounded }));
    await waitFor(() => expect(hook.result.current.state.status).toBe("done"));

    reply(`{"payload":null}`);
    const empty = await startJob();
    act(() => ws.cbs.onDone({}));
    await waitFor(() => expect(empty.result.current.state.status).toBe("error"));
  });
});

describe("useVol3Run cancel", () => {
  it("shows cancelling until the task reports a terminal state, then cancelled", async () => {
    api.cancelVol3Job.mockResolvedValue(undefined);
    const hook = await startJob();
    await act(async () => { await hook.result.current.cancel(); });
    expect(hook.result.current.state.status).toBe("cancelling");
    expect(hook.result.current.state.taskId).toBe("t1");
    act(() => ws.cbs.onProgress(50, "late progress"));
    expect(hook.result.current.state.status).toBe("cancelling");
    expect(hook.result.current.state.msg).toBeNull();
    act(() => ws.cbs.onError("cancelled"));
    expect(hook.result.current.state.status).toBe("cancelled");
  });

  it("stays cancelling when the cancel request fails, and a late done still ends it", async () => {
    api.cancelVol3Job.mockRejectedValue(new Error("gone"));
    const hook = await startJob();
    await act(async () => { await hook.result.current.cancel(); });
    expect(hook.result.current.state.status).toBe("cancelling");
    act(() => ws.cbs.onDone({}));
    expect(hook.result.current.state.status).toBe("cancelled");
  });
});
