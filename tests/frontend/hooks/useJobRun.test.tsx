import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";

import { ApiError } from "@/api/client";

const ws = vi.hoisted(() => ({
  taskId: null as string | null,
  cbs: {} as Record<string, (...a: unknown[]) => void>,
}));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (id: string | null, cbs: Record<string, (...a: unknown[]) => void>) => {
    ws.taskId = id;
    ws.cbs = cbs;
  },
}));
const { useJobRun } = await import("@/hooks/useJobRun");

interface Res { value: number }
interface Ticket { task_id: string }
type Answer = Res | Ticket;

const submit = vi.fn<(req: string) => Promise<Answer>>();
const getPayload = vi.fn<(taskId: string) => Promise<Res | null>>();
const cancelJob = vi.fn<(taskId: string) => Promise<unknown>>();
const isTicket = (a: Answer): a is Ticket => "task_id" in a;

beforeEach(() => {
  submit.mockReset();
  getPayload.mockReset();
  cancelJob.mockReset().mockResolvedValue({ cancelled: true });
  ws.taskId = null;
  ws.cbs = {};
});

type Options = Partial<Parameters<typeof useJobRun<string, Res, Ticket>>[0]>;
const mount = (options: Options = {}) => renderHook(() => useJobRun<string, Res, Ticket>({
  submit, isTicket, getPayload, cancelJob, noPayloadKey: "yara:run.noPayload", ...options,
}));

const startJob = async (options: Options = {}) => {
  submit.mockResolvedValue({ task_id: "t1" });
  const hook = mount(options);
  await act(async () => { await hook.result.current.run("req"); });
  return hook;
};

describe("useJobRun", () => {
  it("an inline answer is the result at once and reaches onResult", async () => {
    const onResult = vi.fn();
    submit.mockResolvedValue({ value: 7 });
    const hook = mount({ onResult });
    await act(async () => { await hook.result.current.run("req"); });
    expect(submit).toHaveBeenCalledWith("req");
    expect(hook.result.current.state).toMatchObject({ status: "done", result: { value: 7 }, taskId: null });
    expect(onResult).toHaveBeenCalledWith({ value: 7 });
  });

  it("a ticket follows the task, then reads the stored payload", async () => {
    const onResult = vi.fn();
    getPayload.mockResolvedValue({ value: 42 });
    const hook = await startJob({ onResult });
    expect(hook.result.current.state).toMatchObject({ status: "running", taskId: "t1" });
    expect(ws.taskId).toBe("t1");

    act(() => ws.cbs.onProgress(0.5, "half"));
    expect(hook.result.current.state).toMatchObject({ pct: 0.5, msg: "half" });

    act(() => ws.cbs.onDone({ extra: { value: 1 } }));
    await waitFor(() => expect(hook.result.current.state.status).toBe("done"));
    expect(getPayload).toHaveBeenCalledWith("t1");
    expect(hook.result.current.state).toMatchObject({ pct: 1, result: { value: 42 }, error: null });
    expect(onResult).toHaveBeenCalledWith({ value: 42 });
  });

  it("without a payload the run is an error, unless the event may stand in", async () => {
    getPayload.mockResolvedValue(null);
    const strict = await startJob();
    act(() => ws.cbs.onDone({ extra: { value: 1 } }));
    await waitFor(() => expect(strict.result.current.state.status).toBe("error"));
    expect(strict.result.current.state.error).toBe("The job finished without a result payload.");

    getPayload.mockRejectedValue(new Error("unreachable"));
    const lenient = await startJob({ eventFallback: true });
    act(() => ws.cbs.onDone({ extra: { value: 1 } }));
    await waitFor(() => expect(lenient.result.current.state.status).toBe("done"));
    expect(lenient.result.current.state.result).toEqual({ value: 1 });
  });

  it("a rejected submit and a task error surface as readable errors", async () => {
    submit.mockRejectedValue(new ApiError(400, '{"error":"bad rule"}'));
    const hook = mount();
    await act(async () => { await hook.result.current.run("req"); });
    expect(hook.result.current.state).toMatchObject({ status: "error", error: "bad rule" });

    const job = await startJob();
    act(() => ws.cbs.onError("worker died"));
    expect(job.result.current.state).toMatchObject({ status: "error", error: "worker died" });
  });

  it("an immediate cancel ends the run and ignores a late answer", async () => {
    const onResult = vi.fn();
    getPayload.mockResolvedValue({ value: 42 });
    const hook = await startJob({ onResult });
    await act(async () => { await hook.result.current.cancel(); });
    expect(cancelJob).toHaveBeenCalledWith("t1");
    expect(hook.result.current.state).toMatchObject({ status: "cancelled", taskId: null });

    act(() => ws.cbs.onDone({}));
    act(() => ws.cbs.onError("cancelled"));
    expect(hook.result.current.state.status).toBe("cancelled");
    expect(onResult).not.toHaveBeenCalled();
  });

  it("an awaitTerminal cancel stays cancelling until the terminal event", async () => {
    const hook = await startJob({ cancelMode: "awaitTerminal" });
    act(() => ws.cbs.onProgress(0.3, "busy"));
    await act(async () => { await hook.result.current.cancel(); });
    expect(hook.result.current.state).toMatchObject({ status: "cancelling", taskId: "t1", pct: null, msg: null });

    act(() => ws.cbs.onProgress(0.6, "late"));
    expect(hook.result.current.state.pct).toBeNull();
    act(() => ws.cbs.onError("cancelled"));
    expect(hook.result.current.state).toMatchObject({ status: "cancelled", taskId: null });
    expect(getPayload).not.toHaveBeenCalled();
  });

  it("cancel without a job does nothing", async () => {
    const hook = mount();
    await act(async () => { await hook.result.current.cancel(); });
    expect(cancelJob).not.toHaveBeenCalled();
    expect(hook.result.current.state.status).toBe("idle");
  });

  it("reset drops an answer still in flight and cancels its ticket", async () => {
    let answer!: (a: Answer) => void;
    submit.mockReturnValue(new Promise<Answer>((resolve) => { answer = resolve; }));
    const onResult = vi.fn();
    const hook = mount({ onResult });
    let pending!: Promise<void>;
    act(() => { pending = hook.result.current.run("req"); });
    expect(hook.result.current.state.status).toBe("running");

    act(() => hook.result.current.reset());
    await act(async () => { answer({ task_id: "stale" }); await pending; });
    expect(hook.result.current.state.status).toBe("idle");
    expect(cancelJob).toHaveBeenCalledWith("stale");
    expect(onResult).not.toHaveBeenCalled();
  });

  it("reset cancels a running job at the server", async () => {
    const hook = await startJob();
    act(() => hook.result.current.reset());
    expect(cancelJob).toHaveBeenCalledWith("t1");
    expect(hook.result.current.state.status).toBe("idle");
  });
});
