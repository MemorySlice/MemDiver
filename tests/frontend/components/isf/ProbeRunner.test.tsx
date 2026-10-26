import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { ProbeResult } from "@/api/isf";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { task, ws } from "./helpers";

const api = vi.hoisted(() => ({ startIsfProbeJob: vi.fn(), getIsfJobPayload: vi.fn() }));
vi.mock("@/api/isf", async (orig) => ({ ...(await orig<typeof import("@/api/isf")>()), ...api }));
const cancelImageJob = vi.hoisted(() => vi.fn());
vi.mock("@/api/image", async (orig) => ({ ...(await orig<typeof import("@/api/image")>()), cancelImageJob }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (taskId: string | null, cbs: Record<string, (...a: unknown[]) => void>) => { ws.calls.push({ taskId, cbs }); },
}));
const viewCtx = vi.hoisted(() => ({ kind: "physical" as string | null, vaSpanStart: 0x1000, intervals: null as unknown[] | null }));
vi.mock("@/components/vol3/useViewContext", () => ({
  useViewContext: () => ({
    ctx: { kind: viewCtx.kind, pid: null, mode: "va", vaSpanStart: viewCtx.vaSpanStart, vaSize: 0x10000, pageStatesLoaded: true },
    loadIntervals: async () => viewCtx.intervals, view: null,
  }),
}));

const { ProbeRunner } = await import("@/components/isf/ProbeRunner");
const REF = { caseDir: "case1", captureId: "c" };

const RESULT: ProbeResult = {
  probe: "banner", arch: "x86_64", capture_id: "c", limit: 1,
  rows: [{ banner: "Linux version 5.15", location: { space: "physical", value: 0x1800, capture_id: "c" } }],
  counts: { banners: 3 }, truncated: true, timings: { open: 0.1, scan_banners: 4.2 },
  warnings: ["init_task disagrees"],
};

const run = async (id: string) => {
  fireEvent.click(screen.getByTestId("probe-run"));
  await waitFor(() => expect(ws.calls.some((c) => c.taskId === id)).toBe(true));
};

beforeEach(() => {
  api.startIsfProbeJob.mockReset();
  api.getIsfJobPayload.mockReset();
  cancelImageJob.mockReset();
  ws.calls.length = 0;
  viewCtx.kind = "physical";
  viewCtx.vaSpanStart = 0x1000;
  viewCtx.intervals = null;
  useDumpStore.getState().clearAll();
  useAppStore.setState({ inputMode: "file", inputPath: "/v/img.mdview" });
  useHexStore.setState({ scrollToOffset: vi.fn() });
});

describe("ProbeRunner", () => {
  it("submits the chosen probe and arch as a job and shows progress", async () => {
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p1", status: "pending" });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={["d1"]} />);
    fireEvent.change(screen.getByTestId("probe-select"), { target: { value: "banner" } });
    fireEvent.change(screen.getByTestId("probe-arch"), { target: { value: "x86_64" } });
    await run("p1");
    expect(api.startIsfProbeJob).toHaveBeenCalledWith({ imagePath: "/i.lime", probe: "banner", arch: "x86_64" });
    act(() => task("p1").onProgress(0.5, "scanning", { extra: { pakunoda_stage: "scan_banners", elapsed_s: 3 } }));
    expect(screen.getByTestId("probe-job-text")).toHaveTextContent("scan_banners");
  });

  it("states truncation, counts, timings and warnings explicitly", async () => {
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p2", status: "pending" });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={[]} />);
    await run("p2");
    api.getIsfJobPayload.mockResolvedValue(RESULT);
    act(() => task("p2").onDone({}));
    expect(await screen.findByTestId("probe-truncated")).toHaveTextContent("1 rows shown (limit 1)");
    expect(screen.getByTestId("probe-counts")).toHaveTextContent("banners: 3");
    expect(screen.getByTestId("probe-timings")).toHaveTextContent("scan_banners 4.2s");
    expect(screen.getByTestId("probe-warning")).toHaveTextContent("init_task disagrees");
    expect(screen.getAllByTestId("probe-row")).toHaveLength(1);
  });

  it("does not claim truncation when the probe was not cut", async () => {
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p3", status: "pending" });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={[]} />);
    await run("p3");
    api.getIsfJobPayload.mockResolvedValue({ ...RESULT, truncated: false });
    act(() => task("p3").onDone({}));
    await screen.findByTestId("probe-result");
    expect(screen.queryByTestId("probe-truncated")).toBeNull();
  });

  it("feeds the chosen draft only for a feedable probe", async () => {
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p4", status: "pending" });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={["d1"]} />);
    expect(screen.getByTestId("probe-feed")).toBeDisabled();
    fireEvent.change(screen.getByTestId("probe-select"), { target: { value: "kallsyms" } });
    fireEvent.change(screen.getByTestId("probe-feed"), { target: { value: "d1" } });
    await run("p4");
    expect(api.startIsfProbeJob).toHaveBeenCalledWith(expect.objectContaining({ probe: "kallsyms", caseDir: "case1", draft: "d1" }));
  });

  it("cancels a running probe", async () => {
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p5", status: "pending" });
    cancelImageJob.mockResolvedValue({ task_id: "p5", cancelled: true });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={[]} />);
    await run("p5");
    fireEvent.click(await screen.findByTestId("probe-job-cancel"));
    await waitFor(() => expect(cancelImageJob).toHaveBeenCalledWith("p5"));
    expect(await screen.findByTestId("probe-cancelled")).toBeInTheDocument();
  });

  it("navigates the hex view to a physical location of a matching open view", async () => {
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p6", status: "pending" });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={[]} />);
    await run("p6");
    api.getIsfJobPayload.mockResolvedValue(RESULT);
    act(() => task("p6").onDone({}));
    fireEvent.click(await screen.findByTestId("probe-location"));
    await waitFor(() => expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x800));
  });

  it("explains why a kernel location cannot be placed in a physical view", async () => {
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p7", status: "pending" });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={[]} />);
    await run("p7");
    api.getIsfJobPayload.mockResolvedValue({ ...RESULT, rows: [{ location: { space: "kernel_va", value: 0x1800, capture_id: "c" } }] });
    act(() => task("p7").onDone({}));
    fireEvent.click(await screen.findByTestId("probe-location"));
    expect(await screen.findByTestId("probe-hint")).toHaveTextContent("kernel_va");
    expect(useHexStore.getState().scrollToOffset).not.toHaveBeenCalled();
  });

  it("places a kernel VA above 2^53 exactly, through the vas view, never a rounded address", async () => {
    viewCtx.kind = "kernel";
    viewCtx.vaSpanStart = 1.8446744073709552e19;
    viewCtx.intervals = [{ va: "18446744071578845184", length: 4096, state: "CAPTURED", page_count: 1, vas_offset: 0x2000 }];
    const showView = vi.fn();
    useHexStore.setState({ showView });
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p9", status: "pending" });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={[]} />);
    await run("p9");
    api.getIsfJobPayload.mockResolvedValue({ ...RESULT, rows: [{ location: { space: "kernel_va", value: "18446744071578845475", capture_id: "c" } }] });
    act(() => task("p9").onDone({}));
    const button = await screen.findByTestId("probe-location");
    expect(button).toHaveTextContent("0xffffffff81000123");
    fireEvent.click(button);
    await waitFor(() => expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x2000 + 0x123));
    expect(showView).toHaveBeenCalledWith("vas");
  });

  it("reports a job whose stored result cannot be read as an error, not as done", async () => {
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p10", status: "pending" });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={[]} />);
    await run("p10");
    api.getIsfJobPayload.mockResolvedValue(null);
    act(() => task("p10").onDone({}));
    expect(await screen.findByTestId("image-error")).toHaveTextContent("stored result");
    expect(screen.queryByTestId("probe-result")).toBeNull();
  });

  it("says why there is no navigation without a matching open view", async () => {
    api.startIsfProbeJob.mockResolvedValue({ task_id: "p8", status: "pending" });
    render(<ProbeRunner imagePath="/i.lime" draftRef={REF} drafts={[]} />);
    await run("p8");
    api.getIsfJobPayload.mockResolvedValue(RESULT);
    act(() => task("p8").onDone({}));
    await screen.findByTestId("probe-location");
    act(() => useAppStore.setState({ inputPath: "/v/flat.raw" }));
    fireEvent.click(screen.getByTestId("probe-location"));
    await waitFor(() => expect(screen.getByTestId("probe-hint")).toHaveTextContent("Open a matching image view"));
  });
});
