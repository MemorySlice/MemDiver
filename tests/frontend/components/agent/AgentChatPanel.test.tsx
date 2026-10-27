import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@/i18n";

vi.mock("@/api/agent", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/agent")>();
  return {
    ...actual,
    getAgentStatus: vi.fn(),
    getAgentSettings: vi.fn(async () => { throw new Error("n/a"); }),
    listPlaybooks: vi.fn(async () => []),
    startAgentChat: vi.fn(async () => ({ chat_id: "c1", ws_path: "/ws/agent/c1", read_tools: 3, write_tools: 1 })),
    deleteAgentChat: vi.fn(async () => {}),
  };
});

import { getAgentStatus } from "@/api/agent";
import { AgentChatPanel } from "@/components/agent/AgentChatPanel";
import { useAgentStore } from "@/stores/agent-store";

class FakeSocket {
  static last: FakeSocket;
  static OPEN = 1;
  readyState = 1;
  sent: string[] = [];
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  url: string;
  constructor(url: string) { this.url = url; FakeSocket.last = this; }
  send(d: string) { this.sent.push(d); }
  close() {}
}

const status = (s: object) => vi.mocked(getAgentStatus).mockResolvedValue({ available: true, backend: "sdk", credentials: true, ...s });
const emit = (ev: object) => act(() => { FakeSocket.last.onmessage?.({ data: JSON.stringify(ev) }); });

beforeEach(() => {
  vi.stubGlobal("WebSocket", FakeSocket);
  useAgentStore.getState().reset();
  useAgentStore.setState({ status: null, statusError: null, bundle: null });
});

describe("AgentChatPanel status banners", () => {
  it("explains a missing SDK with the install hint", async () => {
    status({ available: false, reason: "sdk missing", install_hint: 'pip install "memdiver[agent]"' });
    render(<AgentChatPanel />);
    expect(await screen.findByText('pip install "memdiver[agent]"')).toBeInTheDocument();
    expect(screen.getByText("Start chat")).toBeDisabled();
  });

  it("explains missing credentials without asking for a key", async () => {
    status({ credentials: false });
    render(<AgentChatPanel />);
    expect(await screen.findByText(/ANTHROPIC_API_KEY/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/api key/i)).toBeNull();
  });

  it("badges the scripted backend", async () => {
    status({ backend: "scripted" });
    render(<AgentChatPanel />);
    expect(await screen.findByTestId("scripted-badge")).toHaveTextContent("Demo/test backend — no model");
  });
});

describe("AgentChatPanel conversation", () => {
  it("starts, sends with Enter, streams, and answers an approval over the socket", async () => {
    status({});
    render(<AgentChatPanel />);
    const start = await screen.findByText("Start chat");
    await waitFor(() => expect(start).not.toBeDisabled());
    fireEvent.click(start);
    await waitFor(() => expect(FakeSocket.last).toBeDefined());
    expect(FakeSocket.last.url).toContain("/ws/agent/c1");
    await emit({ type: "status", state: "ready" });

    const box = screen.getByLabelText("Message");
    fireEvent.change(box, { target: { value: "hi" } });
    fireEvent.keyDown(box, { key: "Enter", shiftKey: true });
    expect(FakeSocket.last.sent).toEqual([]);
    fireEvent.keyDown(box, { key: "Enter" });
    expect(JSON.parse(FakeSocket.last.sent[0])).toEqual({ type: "user_message", text: "hi" });
    expect(screen.getByTestId("user-bubble")).toHaveTextContent("hi");

    await emit({ type: "text_delta", text: "Found [seen] it" });
    expect(screen.getByTestId("evidence-seen")).toBeInTheDocument();
    await emit({ type: "approval_request", id: "p", tool: "export", input: {}, access: "write", scopes: ["once", "chat"] });
    fireEvent.click(screen.getByText("Allow for this chat"));
    expect(JSON.parse(FakeSocket.last.sent[1])).toEqual({ type: "approval", id: "p", allow: true, scope: "chat" });

    await emit({ type: "usage", turns: 1, max_turns: 8, cost_estimate_usd: 0.02, max_budget_usd: 0.5 });
    expect(screen.getByTestId("usage-meter")).toHaveTextContent("Turns 1/8");
    fireEvent.click(screen.getByText("Interrupt"));
    expect(JSON.parse(FakeSocket.last.sent[2])).toEqual({ type: "interrupt" });
  });
});
