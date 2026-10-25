import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { YaraScanResult } from "@/api/yara";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

const api = vi.hoisted(() => ({
  checkYaraRule: vi.fn(), scanYara: vi.fn(), listYaraRules: vi.fn(), getYaraRule: vi.fn(),
  putYaraRule: vi.fn(), deleteYaraRule: vi.fn(), getYaraJobPayload: vi.fn(), cancelYaraJob: vi.fn(),
}));
vi.mock("@/api/yara", async (orig) => ({ ...(await orig<typeof import("@/api/yara")>()), ...api }));

const ws = vi.hoisted(() => ({ calls: [] as { taskId: string | null; cbs: Record<string, (...a: unknown[]) => void> }[] }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (taskId: string | null, cbs: Record<string, (...a: unknown[]) => void>) => { ws.calls.push({ taskId, cbs }); },
}));

const { YaraPanel } = await import("@/components/yara/YaraPanel");

const DUMP = "/dumps/proc.msl";
const result = (over: Partial<YaraScanResult> = {}): YaraScanResult => ({
  dump_path: DUMP, view: "va", space: "msl_va", rule_names: ["example"], matched_rules: ["example"],
  rows: [{ rule: "example", tags: [], string_id: "$a", addr: 0x40, space: "msl_va", length: 13,
    matched_hex: "53", va: 0x40, vas_offset: 0x40, region: null }],
  row_count: 1, limit: 1000, truncated: false, timed_out: false, complete: true,
  incomplete_reason: null, errors: [], warnings: [],
  coverage: { view: "va", captured_bytes: 4096, bytes_scanned: 4096, runs_scanned: 1, gaps_skipped: 0,
    gap_bytes: 0, short_reads: 0, requested_offset: 0, requested_length: null },
  ...over,
});
const callbacks = (taskId: string) => [...ws.calls].reverse().find((c) => c.taskId === taskId)!.cbs;

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  ws.calls.length = 0;
  api.checkYaraRule.mockResolvedValue({ valid: true, rule_names: ["example"], errors: [], warnings: [] });
  api.listYaraRules.mockResolvedValue({ case_dir: null, rules: [], count: 0 });
  localStorage.clear();
  useAppStore.setState({ inputMode: "file" });
  useDumpStore.getState().clearAll();
  const id = useDumpStore.getState().addDump({ path: DUMP, name: "proc.msl", size: 10, format: "msl" });
  useDumpStore.getState().setActiveDump(id);
  useHexStore.setState({
    viewMode: "va", vaSpanStart: 0, pageStatesLoaded: true, availableViews: ["raw", "vas", "va"],
    highlightedRegions: [], selection: null, fetchPageStates: vi.fn(),
  });
});

describe("a YARA scan that became a job", () => {
  it("shows the honest fraction, then the exact task payload", async () => {
    api.scanYara.mockResolvedValue({ task_id: "j1", status: "pending" });
    api.getYaraJobPayload.mockResolvedValue(result());
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-cancel");
    act(() => callbacks("j1").onProgress(0.25, "scanning"));
    expect(screen.getByTestId("yara-progress")).toHaveTextContent("scanning 25%");
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "25");
    expect(screen.queryByTestId("yara-table")).toBeNull();   // no rows before the job is done
    await act(async () => { callbacks("j1").onDone({ extra: { row_count: 1 } }); });
    await screen.findByTestId("yara-table");
    expect(api.getYaraJobPayload).toHaveBeenCalledWith("j1");
    expect(screen.queryByTestId("yara-progress")).toBeNull();
  });

  it("Cancel stops the job at the server and never shows a result", async () => {
    api.scanYara.mockResolvedValue({ task_id: "j2", status: "pending" });
    api.cancelYaraJob.mockResolvedValue({ task_id: "j2", cancelled: true });
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    fireEvent.click(await screen.findByTestId("yara-cancel"));
    await waitFor(() => expect(api.cancelYaraJob).toHaveBeenCalledWith("j2"));
    expect(await screen.findByTestId("yara-cancelled")).toHaveTextContent("no result");
    await act(async () => { callbacks("j2")?.onProgress?.(0.9, "late"); });
    expect(screen.queryByTestId("yara-progress")).toBeNull();
    expect(screen.queryByTestId("yara-summary")).toBeNull();
    expect(api.getYaraJobPayload).not.toHaveBeenCalled();
  });

  it("a finished job without a payload is an error, never a result built from the summary", async () => {
    api.scanYara.mockResolvedValue({ task_id: "j3", status: "pending" });
    api.getYaraJobPayload.mockResolvedValue(null);
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-cancel");
    await act(async () => { callbacks("j3").onDone({ extra: { row_count: 1, complete: true } }); });
    expect(await screen.findByTestId("yara-job-error")).toHaveTextContent("without a result payload");
    expect(screen.queryByTestId("yara-summary")).toBeNull();
  });

  it("a failed or cancelled-by-server job is shown as an error", async () => {
    api.scanYara.mockResolvedValue({ task_id: "j4", status: "pending" });
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-cancel");
    await act(async () => { callbacks("j4").onError("cancelled"); });
    expect(await screen.findByTestId("yara-job-error")).toHaveTextContent("cancelled");
    expect(screen.queryByTestId("yara-summary")).toBeNull();
  });

  it("an incomplete job payload keeps its not-the-whole-truth warning", async () => {
    api.scanYara.mockResolvedValue({ task_id: "j5", status: "pending" });
    api.getYaraJobPayload.mockResolvedValue(result({
      rows: [], row_count: 0, complete: false, timed_out: true, incomplete_reason: "timed_out",
    }));
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-cancel");
    await act(async () => { callbacks("j5").onDone({ extra: null }); });
    expect(await screen.findByTestId("yara-incomplete")).toBeInTheDocument();
    expect(screen.getByTestId("yara-empty")).toHaveTextContent("not proof of absence");
  });

  it("a new run clears the previous result before the answer arrives", async () => {
    api.scanYara.mockResolvedValueOnce(result());
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-table");
    api.scanYara.mockResolvedValueOnce({ task_id: "j6", status: "pending" });
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-cancel");
    expect(screen.queryByTestId("yara-table")).toBeNull();
  });

  it("sends no async flag by default (the server decides by size)", async () => {
    api.scanYara.mockResolvedValue(result());
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-table");
    expect(api.scanYara.mock.calls[0][0]).not.toHaveProperty("async");
  });
});

describe("context changes and progress", () => {
  it("clears the result and cancels an in-flight job when the dump changes", async () => {
    api.scanYara.mockResolvedValue({ task_id: "jx", status: "pending" });
    api.cancelYaraJob.mockResolvedValue({ task_id: "jx", cancelled: true });
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-cancel");
    expect(screen.getByRole("progressbar")).not.toHaveAttribute("aria-valuenow");   // indeterminate
    const id = useDumpStore.getState().addDump({ path: "/dumps/other.msl", name: "o", size: 1, format: "msl" });
    await act(async () => { useDumpStore.getState().setActiveDump(id); });
    await waitFor(() => expect(api.cancelYaraJob).toHaveBeenCalledWith("jx"));
    expect(screen.queryByTestId("yara-progress")).toBeNull();
    expect(screen.queryByTestId("yara-summary")).toBeNull();
  });
});
