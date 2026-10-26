import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { DisasmResultView } from "@/components/hex/DisasmSelection";
import type { DisasmResult } from "@/api/disasm";
import { ws, task } from "./helpers";

const api = vi.hoisted(() => ({ startIsfTryJob: vi.fn(), getIsfJobPayload: vi.fn() }));
vi.mock("@/api/isf", async (orig) => ({ ...(await orig<typeof import("@/api/isf")>()), ...api }));
vi.mock("@/api/image", async (orig) => ({ ...(await orig<typeof import("@/api/image")>()), cancelImageJob: vi.fn(async () => ({})) }));
vi.mock("@/api/annotations", async (orig) => ({ ...(await orig<typeof import("@/api/annotations")>()),
  listIsfTries: vi.fn(async () => ({ entries: [], count: 0 })) }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (taskId: string | null, cbs: Record<string, (...a: unknown[]) => void>) => { ws.calls.push({ taskId, cbs }); },
}));

const { TryPanel } = await import("@/components/isf/TryPanel");

const RESULT = { verdict: "pass", stage: "s", plugin: "p", implicated: [], comparison: null } as never;
const ref = { caseDir: "/c", captureId: "x" };

beforeEach(() => { ws.calls.length = 0; api.startIsfTryJob.mockResolvedValue({ task_id: "t1" }); api.getIsfJobPayload.mockResolvedValue(RESULT); });

describe("TryPanel origin binding", () => {
  it("does not show draft A's verdict as draft B's result", async () => {
    const { rerender } = render(<TryPanel imagePath="/i" draftRef={ref} draft="A" rev={0} onImplicated={() => {}} />);
    await act(async () => { fireEvent.click(screen.getByTestId("try-run")); });
    rerender(<TryPanel imagePath="/i" draftRef={ref} draft="B" rev={0} onImplicated={() => {}} />);
    await act(async () => { task("t1").onDone({ extra: null }); });
    expect(screen.queryByTestId("try-current")).toBeNull();
    rerender(<TryPanel imagePath="/i" draftRef={ref} draft="A" rev={0} onImplicated={() => {}} />);
    expect(screen.queryByTestId("try-current")).toBeNull();
  });
});

describe("disasm exact addresses", () => {
  it("prefers start_hex and shows the exact lossless gap start", () => {
    const result = { arch: "x86_64", address: "0x1", row_count: 0, max_insns: 1, truncated: false, rows: [], stops: [],
      coverage: { requested: 4, captured: 2, complete: false, gaps: [
        { start: "18446744071578845475", length: 2, reason: "r" },
        { start: "18446744071578845475", start_hex: "0xffffffff81000123", length: 2, reason: "r" }] } } as unknown as DisasmResult;
    render(<DisasmResultView answer={{ result, sentBytes: 4, selectedBytes: 4 }} />);
    const gaps = screen.getByTestId("disasm-gaps");
    expect(gaps).toHaveTextContent("Gap at 0xffffffff81000123, 2 bytes");
    expect(gaps.querySelectorAll("li")[0]).toHaveTextContent("0xffffffff81000123");
  });
});
