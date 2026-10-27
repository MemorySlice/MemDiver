import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import "@/i18n";

vi.mock("@/api/agent", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/agent")>();
  return {
    ...actual,
    getAgentStatus: vi.fn(async () => ({ available: true, backend: "scripted", credentials: true })),
    getAgentSettings: vi.fn(async () => { throw new Error("n/a"); }),
    listPlaybooks: vi.fn(async () => []),
  };
});
vi.mock("@/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/client")>();
  return {
    ...actual,
    getNotebookStatus: vi.fn(async () => ({ available: false })),
    getVasRegions: vi.fn(() => new Promise(() => {})),
    listDatasetRuns: vi.fn(() => new Promise(() => {})),
  };
});

import { Workspace } from "@/components/layout/Workspace";
import { ThemeProvider } from "@/providers/ThemeProvider";

class NoopObserver { observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } }
vi.stubGlobal("ResizeObserver", NoopObserver);
vi.stubGlobal("IntersectionObserver", NoopObserver);

describe("Workspace agent side tab", () => {
  it("registers an agent tab that opens the chat panel", async () => {
    render(<ThemeProvider><Workspace /></ThemeProvider>);
    const tab = screen.getByTestId("tab-agent");
    expect(tab).toHaveTextContent("agent");
    await act(async () => { fireEvent.click(tab); });
    expect(await screen.findByLabelText("Agent chat")).toBeInTheDocument();
  });
});
