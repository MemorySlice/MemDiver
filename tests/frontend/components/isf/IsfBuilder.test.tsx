import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { TryResult } from "@/api/isf";
import { useImageStore } from "@/stores/image-store";
import { CAPTURE, draftAnswer, prov, task, ws } from "./helpers";

const api = vi.hoisted(() => ({
  listIsfDrafts: vi.fn(), createIsfDraft: vi.fn(), getIsfDraft: vi.fn(), getIsfDraftVersions: vi.fn(), getIsfJobPayload: vi.fn(),
  setIsfDraft: vi.fn(), retractIsfEntry: vi.fn(), diffIsfDraft: vi.fn(), validateIsfDraft: vi.fn(),
  startIsfTryJob: vi.fn(), startIsfProbeJob: vi.fn(),
}));
vi.mock("@/api/isf", async (orig) => ({ ...(await orig<typeof import("@/api/isf")>()), ...api }));
const tries = vi.hoisted(() => ({ listIsfTries: vi.fn() }));
vi.mock("@/api/annotations", async (orig) => ({ ...(await orig<typeof import("@/api/annotations")>()), ...tries }));
const cancelImageJob = vi.hoisted(() => vi.fn());
vi.mock("@/api/image", async (orig) => ({ ...(await orig<typeof import("@/api/image")>()), cancelImageJob }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (taskId: string | null, cbs: Record<string, (...a: unknown[]) => void>) => { ws.calls.push({ taskId, cbs }); },
}));

const { IsfBuilder } = await import("@/components/isf/IsfBuilder");

const SYMBOLS = Array.from({ length: 450 }, (_, i) => `sym_${String(i).padStart(3, "0")}`);
const DRAFT_ROW = { name: "d1", arch: "x86_64", created: "t", version: "v", applied: 3,
  counts: { symbols: 450, user_types: 1, base_types: 0, enums: 0 } };
const TASK_STRUCT = { task_struct: { kind: "struct", size: 9000, untyped_fields: 1, fields: {
  tasks: { offset: 0x3a0, type: { kind: "base", name: "list_head" } },
  pid: { offset: 0x4a0, type: { kind: "base", name: "int" } } } } };

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  cancelImageJob.mockReset();
  ws.calls.length = 0;
  useImageStore.getState().reset();
  useImageStore.setState({ imagePath: CAPTURE, caseDir: "case1" });
  api.listIsfDrafts.mockResolvedValue({ capture_id: "c", drafts: [DRAFT_ROW], count: 1 });
  api.getIsfDraftVersions.mockResolvedValue({ draft: "d1", versions: [], total: 0, truncated: false });
  tries.listIsfTries.mockReset();
  tries.listIsfTries.mockResolvedValue({ entries: [], count: 0 });
  api.getIsfDraft.mockImplementation(async (_ref, _name, opts: { only: Record<string, string[]>; limit: number; offset?: number; search?: string }) => {
    const [section] = Object.keys(opts.only);
    if (section === "user_types") {
      return draftAnswer("user_types", ["task_struct"], { limit: opts.limit }, TASK_STRUCT, {
        "task_struct.tasks": { entry_id: "f1", op: "set_field", provenance: prov("exact"), untyped: false },
        "task_struct.pid": { entry_id: "f2", op: "set_field", provenance: prov("bound"), untyped: true } });
    }
    const needle = (opts.search ?? "").toLowerCase();
    const names = SYMBOLS.filter((n) => n.includes(needle));
    return draftAnswer("symbols", names, { offset: opts.offset, limit: opts.limit, total: 450 });
  });
});

const openDraft = async () => {
  render(<IsfBuilder />);
  fireEvent.click(await screen.findByTestId("isf-draft"));
  await screen.findAllByTestId("isf-row");
};

describe("IsfBuilder drafts", () => {
  it("lists the capture's drafts, keyed by the case dir and the image", async () => {
    render(<IsfBuilder />);
    expect(await screen.findByTestId("isf-draft")).toHaveTextContent("d1");
    expect(api.listIsfDrafts).toHaveBeenCalledWith({ caseDir: "case1", captureId: CAPTURE });
  });

  it("asks for a case directory before anything else", () => {
    useImageStore.setState({ caseDir: "" });
    render(<IsfBuilder />);
    expect(screen.getByTestId("isf-needs-case")).toBeInTheDocument();
    expect(screen.getByTestId("isf-create")).toBeDisabled();
    expect(api.listIsfDrafts).not.toHaveBeenCalled();
  });

  it("creates a draft with name and arch and selects it", async () => {
    api.createIsfDraft.mockResolvedValue({ draft: "fresh" });
    render(<IsfBuilder />);
    await screen.findByTestId("isf-draft");
    api.listIsfDrafts.mockResolvedValue({ capture_id: "c", drafts: [DRAFT_ROW, { ...DRAFT_ROW, name: "fresh", arch: "aarch64" }], count: 2 });
    fireEvent.change(screen.getByTestId("isf-new-name"), { target: { value: "fresh" } });
    fireEvent.change(screen.getByTestId("isf-new-arch"), { target: { value: "aarch64" } });
    fireEvent.click(screen.getByTestId("isf-create"));
    await waitFor(() => expect(api.createIsfDraft).toHaveBeenCalledWith({ caseDir: "case1", captureId: CAPTURE }, "fresh", "aarch64"));
    await waitFor(() => expect(screen.getAllByTestId("isf-draft")).toHaveLength(2));
  });

  it("refuses a name that is not a slug", async () => {
    render(<IsfBuilder />);
    await screen.findByTestId("isf-draft");
    fireEvent.change(screen.getByTestId("isf-new-name"), { target: { value: "bad name" } });
    expect(screen.getByTestId("isf-create")).toBeDisabled();
  });
});

describe("IsfBuilder tree", () => {
  it("pages a 450-symbol section by server offset, 200 rows at a time", async () => {
    await openDraft();
    expect(screen.getAllByTestId("isf-row")).toHaveLength(200);
    expect(screen.getByTestId("isf-tree-count")).toHaveTextContent("1–200 of 450");
    expect(screen.getByTestId("isf-page-prev")).toBeDisabled();
    fireEvent.click(screen.getByTestId("isf-page-next"));
    await waitFor(() => expect(screen.getByTestId("isf-tree-count")).toHaveTextContent("201–400 of 450"));
    expect(api.getIsfDraft).toHaveBeenCalledWith(expect.anything(), "d1", expect.objectContaining({ offset: 200, limit: 200 }));
    expect(screen.getAllByTestId("isf-row")[0]).toHaveAttribute("data-name", "sym_200");
    fireEvent.click(screen.getByTestId("isf-page-next"));
    await waitFor(() => expect(screen.getByTestId("isf-tree-count")).toHaveTextContent("401–450 of 450"));
    expect(screen.getAllByTestId("isf-row")).toHaveLength(50);
    expect(screen.getByTestId("isf-page-next")).toBeDisabled();
  });

  it("searches on the server and returns to the first page", async () => {
    await openDraft();
    fireEvent.click(screen.getByTestId("isf-page-next"));
    await waitFor(() => expect(screen.getByTestId("isf-tree-count")).toHaveTextContent("201–400"));
    fireEvent.change(screen.getByTestId("isf-search"), { target: { value: "SYM_01" } });
    await waitFor(() => expect(api.getIsfDraft).toHaveBeenCalledWith(
      expect.anything(), "d1", expect.objectContaining({ search: "SYM_01", offset: 0 })));
    await waitFor(() => expect(screen.getAllByTestId("isf-row")).toHaveLength(10));
    expect(screen.getByTestId("isf-tree-count")).toHaveTextContent("1–10 of 10");
  });

  it("says so when the search matches nothing", async () => {
    await openDraft();
    fireEvent.change(screen.getByTestId("isf-search"), { target: { value: "nope" } });
    await waitFor(() => expect(screen.getByTestId("isf-tree-count")).toHaveTextContent("No matching entries"));
  });

  it("shows untyped offsets as not exported, with a count per struct", async () => {
    await openDraft();
    fireEvent.click(screen.getByTestId("isf-section-user_types"));
    expect(await screen.findByTestId("isf-untyped-count")).toHaveTextContent("1 untyped — not exported");
    fireEvent.click(screen.getByLabelText("Toggle fields of task_struct"));
    const rows = await screen.findAllByTestId("isf-field-row");
    const pid = rows.find((r) => r.getAttribute("data-field") === "task_struct.pid")!;
    const tasks = rows.find((r) => r.getAttribute("data-field") === "task_struct.tasks")!;
    expect(within(pid).getByTestId("isf-untyped")).toHaveTextContent("untyped — not exported");
    expect(within(pid).getByTestId("provenance-badge")).toHaveAttribute("data-tier", "bound");
    expect(within(tasks).queryByTestId("isf-untyped")).toBeNull();
    expect(within(tasks).getByTestId("provenance-badge")).toHaveAttribute("data-tier", "exact");
  });

  it("shows the provenance tier of each entry", async () => {
    await openDraft();
    const badge = within(screen.getAllByTestId("isf-row")[0]).getByTestId("provenance-badge");
    expect(badge).toHaveAttribute("data-tier", "probe");
  });

  it("removes an entry only after confirmation", async () => {
    api.setIsfDraft.mockResolvedValue({ draft: "d1", op: "remove", entry: { entry_id: "e" } });
    await openDraft();
    fireEvent.click(within(screen.getAllByTestId("isf-row")[0]).getByTestId("isf-remove"));
    expect(api.setIsfDraft).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId("isf-remove-confirm"));
    await waitFor(() => expect(api.setIsfDraft).toHaveBeenCalledWith(
      expect.anything(), "d1", expect.objectContaining({ op: "remove", args: { key: ["symbol", "sym_000"] } })));
  });
});

describe("IsfBuilder try", () => {
  const FAIL: TryResult = {
    plugin: "linux.pslist", verdict: "fail", stage: "done", version: "v9",
    comparison: { expected: 20, returned: 18, matched: 15, recall: 0.75, precision: 0.8333, missing: [3, 4], extra: [99],
      duplicates: [], mismatches: [{ pid: 7, column: "COMM", expected: "sshd", got: "ssh" }], mismatch_count: 1, truncated: false },
    implicated: [{ item: "task_struct.tasks", reason: "0 rows" }],
  };

  it("runs the try as a job and renders verdict, numbers, mismatches and implicated chips", async () => {
    api.startIsfTryJob.mockResolvedValue({ task_id: "t1", status: "pending" });
    await openDraft();
    fireEvent.change(screen.getByTestId("try-truth"), { target: { value: "/gt.txt" } });
    fireEvent.click(screen.getByTestId("try-run"));
    await waitFor(() => expect(api.startIsfTryJob).toHaveBeenCalledWith({
      imagePath: CAPTURE, caseDir: "case1", draft: "d1", plugin: "linux.pslist", groundTruth: "/gt.txt" }));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "t1")).toBe(true));
    act(() => task("t1").onProgress(0.4, "running plugin", { extra: { pakunoda_stage: "run", elapsed_s: 2 } }));
    expect(screen.getByTestId("try-job")).toBeInTheDocument();
    api.getIsfJobPayload.mockResolvedValue(FAIL);
    act(() => task("t1").onDone({}));
    expect(await screen.findByTestId("try-verdict")).toHaveAttribute("data-verdict", "fail");
    expect(screen.getByTestId("try-cmp-expected")).toHaveTextContent("20");
    expect(screen.getByTestId("try-cmp-matched")).toHaveTextContent("15");
    expect(screen.getByTestId("try-cmp-recall")).toHaveTextContent("75.0%");
    expect(screen.getByTestId("try-cmp-precision")).toHaveTextContent("83.3%");
    expect(screen.getByTestId("try-pids")).toHaveTextContent("3, 4");
    expect(screen.getAllByTestId("try-mismatch-row")).toHaveLength(1);
    expect(screen.getByTestId("try-mismatches")).toHaveTextContent("sshd");
  });

  it("selects the implicated entry in the tree when its chip is clicked", async () => {
    api.startIsfTryJob.mockResolvedValue({ task_id: "t2", status: "pending" });
    await openDraft();
    fireEvent.click(screen.getByTestId("try-run"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "t2")).toBe(true));
    api.getIsfJobPayload.mockResolvedValue({ ...FAIL, implicated: [{ item: "task_struct.tasks" }] });
    act(() => task("t2").onDone({}));
    fireEvent.click(await screen.findByTestId("try-implicated-chip"));
    await waitFor(() => expect(api.getIsfDraft).toHaveBeenCalledWith(
      expect.anything(), "d1", expect.objectContaining({ only: { user_types: [] }, search: "task_struct" })));
    const rows = await screen.findAllByTestId("isf-field-row");
    const selected = rows.filter((r) => r.getAttribute("data-selected") === "true");
    expect(selected.map((r) => r.getAttribute("data-field"))).toEqual(["task_struct.tasks"]);
    expect(screen.getByTestId("isf-section-user_types")).toHaveAttribute("aria-selected", "true");
  });

  it("shows an unverified try as unverified, never as a pass", async () => {
    api.startIsfTryJob.mockResolvedValue({ task_id: "t3", status: "pending" });
    await openDraft();
    fireEvent.click(screen.getByTestId("try-run"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "t3")).toBe(true));
    api.getIsfJobPayload.mockResolvedValue({ plugin: "linux.pslist", verdict: "unverified", stage: "done", implicated: [] });
    act(() => task("t3").onDone({}));
    expect(await screen.findByTestId("try-verdict")).toHaveAttribute("data-verdict", "unverified");
    expect(screen.queryByTestId("try-comparison")).toBeNull();
  });

  it("cancels a running try", async () => {
    api.startIsfTryJob.mockResolvedValue({ task_id: "t4", status: "pending" });
    cancelImageJob.mockResolvedValue({ task_id: "t4", cancelled: true });
    await openDraft();
    fireEvent.click(screen.getByTestId("try-run"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "t4")).toBe(true));
    fireEvent.click(await screen.findByTestId("try-job-cancel"));
    await waitFor(() => expect(cancelImageJob).toHaveBeenCalledWith("t4"));
    expect(await screen.findByTestId("try-cancelled")).toBeInTheDocument();
  });

  it("reads the try result from the stored task payload", async () => {
    api.startIsfTryJob.mockResolvedValue({ task_id: "t5", status: "pending" });
    await openDraft();
    fireEvent.click(screen.getByTestId("try-run"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "t5")).toBe(true));
    api.getIsfJobPayload.mockResolvedValue({ plugin: "linux.pslist", verdict: "pass", stage: "done", implicated: [] });
    act(() => task("t5").onDone({ extra: { verdict: "ignored" } }));
    expect(await screen.findByTestId("try-verdict")).toHaveAttribute("data-verdict", "pass");
    expect(api.getIsfJobPayload).toHaveBeenCalledWith("t5");
  });

  it("lists the draft's earlier tries from the analysis record, for this draft only", async () => {
    tries.listIsfTries.mockResolvedValue({ count: 3, entries: [
      { id: "a", kind: "isf_try", created: "2026-10-24T10:00:00", locations: [], payload: { draft: "d1", version: "v1", state_id: "s1", plugin: "linux.pslist", verdict: "fail", implicated: [{ item: "x" }, { item: "y" }] } },
      { id: "b", kind: "isf_try", created: "2026-10-25T10:00:00", locations: [], payload: { draft: "d1", version: "v2", state_id: "s2", plugin: "linux.pslist", verdict: "pass", implicated: [] } },
      { id: "c", kind: "isf_try", created: "t", locations: [], payload: { draft: "other", verdict: "pass" } },
    ] });
    await openDraft();
    const items = await screen.findAllByTestId("try-past-item");
    expect(items).toHaveLength(2);
    expect(tries.listIsfTries).toHaveBeenCalledWith("case1", CAPTURE);
    expect(items[0]).toHaveAttribute("data-verdict", "pass");
    expect(items[1]).toHaveTextContent("state s1, 2 implicated");
    expect(items[1]).toHaveTextContent("version v1");
  });

  it("says when there are no earlier tries", async () => {
    await openDraft();
    expect(await screen.findByTestId("try-past-empty")).toBeInTheDocument();
  });
});

void prov;
