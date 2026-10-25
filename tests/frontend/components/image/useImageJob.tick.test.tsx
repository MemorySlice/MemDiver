import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";

vi.mock("@/api/image", () => ({ cancelImageJob: vi.fn(async () => undefined) }));
vi.mock("@/api/client", () => ({ readableFailure: (e: unknown) => String(e) }));

type Cbs = Record<string, (...a: unknown[]) => void>;
const ws = vi.hoisted(() => ({ cbs: {} as Record<string, (...a: unknown[]) => void> }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (_id: string | null, cbs: Cbs) => { ws.cbs = cbs; },
}));

const { useImageJob } = await import("@/components/image/useImageJob");

const stageEvent = (stage: string, elapsed_s: number) =>
  ws.cbs.onProgress(null, "m", { extra: { pakunoda_stage: stage, elapsed_s } });

async function startJob() {
  const hook = renderHook(() => useImageJob());
  await act(async () => { await hook.result.current.start(async () => ({ task_id: "t1" }) as never); });
  return hook;
}

describe("useImageJob live clocks", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it("ticks stage seconds locally and resets on a new stage", async () => {
    const { result } = await startJob();
    act(() => stageEvent("discovery_wave", 0));
    expect(result.current.state.elapsedS).toBe(0);
    act(() => { vi.advanceTimersByTime(2000); });
    expect(result.current.state.elapsedS).toBeCloseTo(2, 1);
    expect(result.current.state.totalElapsedS).toBeCloseTo(2, 1);
    act(() => { vi.advanceTimersByTime(1000); stageEvent("next", 0.5); });
    expect(result.current.state.stage).toBe("next");
    expect(result.current.state.elapsedS).toBeCloseTo(0.5, 1);
    expect(result.current.state.totalElapsedS).toBeCloseTo(3, 1);
  });

  it("stops ticking on done and on cancel, and clears the interval", async () => {
    const { result, unmount } = await startJob();
    act(() => stageEvent("s", 0));
    act(() => ws.cbs.onDone({ extra: { ok: 1 } }));
    expect(vi.getTimerCount()).toBe(0);
    expect(result.current.state.status).toBe("done");

    const second = await startJob();
    act(() => stageEvent("s", 0));
    await act(async () => { await second.result.current.cancel(); });
    expect(second.result.current.state.status).toBe("cancelled");
    expect(vi.getTimerCount()).toBe(0);

    const third = await startJob();
    expect(vi.getTimerCount()).toBe(1);
    third.unmount();
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
