import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";

vi.mock("@/api/agent", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/agent")>();
  return {
    ...actual,
    getAgentStatus: vi.fn(async () => ({ available: true, backend: "sdk", credentials: true })),
    getAgentSettings: vi.fn(async () => { throw new Error("n/a"); }),
  };
});

import { useAgentChat } from "@/components/agent/useAgentChat";
import { useAgentStore } from "@/stores/agent-store";

beforeEach(() => {
  useAgentStore.getState().reset();
  useAgentStore.setState({ status: null, statusError: null, bundle: null });
});

function renderCounted() {
  let renders = 0;
  const hook = renderHook(() => { renders++; return useAgentChat(); });
  return { hook, renders: () => renders };
}

describe("useAgentChat", () => {
  it("does not re-render on store fields the panel never reads", async () => {
    const { renders } = renderCounted();
    await act(async () => {});
    const settled = renders();
    act(() => useAgentStore.setState({ chatId: "c9", result: { stop_reason: "end", is_error: false } }));
    expect(renders()).toBe(settled);
  });

  it("re-renders with the new transcript on a streamed token", async () => {
    const { hook, renders } = renderCounted();
    await act(async () => {});
    const settled = renders();
    act(() => useAgentStore.getState().ingest({ type: "text_delta", text: "hi" }));
    expect(renders()).toBe(settled + 1);
    expect(hook.result.current.items).toEqual([{ kind: "assistant", text: "hi", streaming: true }]);
  });

  it("keeps start stable across renders and starts the chat with the workspace scope", async () => {
    const startChat = vi.fn(async () => {});
    useAgentStore.setState({ startChat });
    const { hook } = renderCounted();
    await act(async () => {});
    const first = hook.result.current.start;
    act(() => useAgentStore.getState().ingest({ type: "text_delta", text: "x" }));
    expect(hook.result.current.start).toBe(first);
    await act(async () => { await hook.result.current.start(); });
    expect(startChat).toHaveBeenCalledWith({});
  });
});
