import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { stubVirtualizerLayout } from "../../helpers/virtualizer";
import type { Vol3RunResult } from "@/api/vol3";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useImageStore } from "@/stores/image-store";

const api = vi.hoisted(() => ({
  listVol3Plugins: vi.fn(), describeVol3Plugin: vi.fn(), runVol3Plugin: vi.fn(),
  annotateVol3Run: vi.fn(), cancelVol3Job: vi.fn(),
}));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));

const client = vi.hoisted(() => ({ previewImport: vi.fn(), getPageStates: vi.fn() }));
vi.mock("@/api/client", async (orig) => ({ ...(await orig<typeof import("@/api/client")>()), ...client }));

const ws = vi.hoisted(() => ({ calls: [] as { taskId: string | null; cbs: Record<string, (...a: unknown[]) => void> }[] }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (taskId: string | null, cbs: Record<string, (...a: unknown[]) => void>) => { ws.calls.push({ taskId, cbs }); },
}));

vi.mock("@/utils/apply-hits", async (orig) => {
  const actual = await orig<typeof import("@/utils/apply-hits")>();
  return { ...actual, applyAnnotations: vi.fn(actual.applyAnnotations) };
});
const { applyAnnotations } = await import("@/utils/apply-hits");
const { Vol3Panel } = await import("@/components/vol3/Vol3Panel");

const SPAN = 0xffff888000000000n;
const VIEW = "/case/kernel.mdview";
const PSLIST = "linux.pslist.PsList";

const result = (over: Partial<Vol3RunResult> = {}): Vol3RunResult => ({
  plugin: PSLIST, capture_id: "c",
  columns: [
    { name: "PID", type: "int", space: null },
    { name: "COMM", type: "str", space: null },
    { name: "OFFSET", type: "hex", space: "kernel_va" },
  ],
  rows: [
    { depth: 0, values: [1, "systemd", (SPAN + 0x1000n).toString()], absent: {} },
    { depth: 1, values: [2, "kthreadd", null], absent: { OFFSET: "Unreadable" } },
  ],
  row_count: 2, rows_returned: 2, truncated: false, stop_reason: null, elapsed_s: 0.5,
  diagnostics: [], files: [], defaults_applied: {}, args: {}, table: null, run_id: null,
  ...over,
});

const task = (id: string) => [...ws.calls].reverse().find((c) => c.taskId === id)!.cbs;

async function openPanel(viewKind: "kernel" | "process" | "physical" = "kernel", active = true) {
  if (active) {
    useAppStore.setState({ inputMode: "file" });
    const id = useDumpStore.getState().addDump({ path: VIEW, name: "kernel.mdview", size: 10, format: "raw" });
    useDumpStore.getState().setActiveDump(id);
  }
  client.previewImport.mockResolvedValue({ view_kind: viewKind });
  render(<Vol3Panel />);
  await screen.findAllByTestId("plugin-option");
  if (active) await waitFor(() => expect(client.previewImport).toHaveBeenCalled());
}

async function runPlugin() {
  fireEvent.click((await screen.findAllByTestId("plugin-option"))[0]);
  await screen.findByTestId("args-form");
  await waitFor(() => expect(screen.getByTestId("vol3-run")).toBeEnabled());
  fireEvent.click(screen.getByTestId("vol3-run"));
}

beforeEach(() => {
  stubVirtualizerLayout(900, 240);
  [...Object.values(api), ...Object.values(client)].forEach((m) => m.mockReset());
  ws.calls.length = 0;
  vi.mocked(applyAnnotations).mockClear();
  useDumpStore.getState().clearAll();
  useImageStore.getState().reset();
  useHexStore.setState({
    viewMode: "va", vaSpanStart: Number(SPAN), vaSize: 1 << 20, pageStatesLoaded: true,
    highlightedRegions: [], scrollToOffset: vi.fn(),
  });
  api.listVol3Plugins.mockResolvedValue({ os_family: "linux", count: 2, plugins: [
    { name: PSLIST, description: "Lists the processes", version: "1.0" },
    { name: "linux.lsmod.Lsmod", description: "Lists loaded modules", version: "1.0" },
  ] });
  api.describeVol3Plugin.mockResolvedValue({
    name: PSLIST, description: "", version: "1", satisfied_by_context: [],
    requirements: [{ name: "pid", type: "array", items: { type: "integer" }, requirement: "ListRequirement",
      description: "", optional: true, default: null }],
  });
});

describe("Vol3Panel", () => {
  it("filters the plugin list by name or description", async () => {
    await openPanel();
    fireEvent.change(screen.getByLabelText("Search plugins"), { target: { value: "modules" } });
    expect(screen.getAllByTestId("plugin-option")).toHaveLength(1);
    expect(screen.getByTestId("plugin-option")).toHaveTextContent("lsmod");
  });

  it("disables Run with a reason when the active dump is not an image view", async () => {
    await openPanel("kernel", false);
    fireEvent.click(screen.getAllByTestId("plugin-option")[0]);
    await screen.findByTestId("args-form");
    expect(screen.getByTestId("vol3-run")).toBeDisabled();
    expect(screen.getByTestId("needs-view")).toBeInTheDocument();
  });

  it("runs inline and renders the table with tree indent and an absent marker", async () => {
    api.runVol3Plugin.mockResolvedValue(result({ defaults_applied: { pid: [1] } }));
    await openPanel();
    await runPlugin();
    await screen.findAllByTestId("vol3-row");
    expect(api.runVol3Plugin).toHaveBeenCalledWith(expect.objectContaining({
      view_path: VIEW, plugin: PSLIST, args: {} }));
    const rows = screen.getAllByTestId("vol3-row");
    expect(within(rows[0]).getByTestId("address-cell")).toHaveTextContent(`0x${(SPAN + 0x1000n).toString(16)}`);
    expect(within(rows[0]).getByTestId("space-badge")).toHaveTextContent("kva");
    const absent = within(rows[1]).getByTestId("absent-cell");
    expect(absent).toHaveAttribute("title", "Unreadable");
    expect(absent).not.toHaveTextContent(/^0$/);
    expect(rows[1].children[0]).toHaveStyle({ paddingLeft: "12px" });
    expect(screen.getByTestId("defaults-applied")).toHaveTextContent('pid=[1]');
    expect(screen.queryByTestId("truncated-banner")).toBeNull();
  });

  it("makes a truncated run look truncated and lists diagnostics", async () => {
    api.runVol3Plugin.mockResolvedValue(result({
      truncated: true, stop_reason: "timeout", diagnostics: ["layer fault at 0x10"] }));
    await openPanel();
    await runPlugin();
    expect(await screen.findByTestId("truncated-banner")).toHaveTextContent(/NOT the complete result.*|timeout reached/s);
    expect(screen.getByTestId("truncated-banner")).toHaveTextContent("timeout reached");
    expect(screen.getByTestId("diagnostics")).toHaveTextContent("layer fault at 0x10");
  });

  it("runs as a job: progress, then the done payload; cancel stops it", async () => {
    api.runVol3Plugin.mockResolvedValue({ task_id: "job1", status: "pending" });
    await openPanel();
    await runPlugin();
    await screen.findByTestId("vol3-cancel");
    act(() => task("job1").onProgress(0.4, "scanning", {}));
    expect(screen.getByTestId("vol3-progress")).toHaveTextContent("scanning (40%)");
    act(() => task("job1").onDone({ extra: result() }));
    expect(await screen.findAllByTestId("vol3-row")).toHaveLength(2);
    expect(screen.queryByTestId("vol3-cancel")).toBeNull();

    api.runVol3Plugin.mockResolvedValue({ task_id: "job2", status: "pending" });
    api.cancelVol3Job.mockResolvedValue({ cancelled: true });
    fireEvent.click(screen.getByTestId("vol3-run"));
    fireEvent.click(await screen.findByTestId("vol3-cancel"));
    await waitFor(() => expect(api.cancelVol3Job).toHaveBeenCalledWith("job2"));
    expect(await screen.findByTestId("vol3-cancelled")).toBeInTheDocument();
  });

  it("jumps to the row's address when its space matches the view", async () => {
    api.runVol3Plugin.mockResolvedValue(result());
    await openPanel("kernel");
    await runPlugin();
    fireEvent.click((await screen.findAllByTestId("vol3-row"))[0]);
    await waitFor(() => expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x1000));
    expect(screen.queryByTestId("vol3-nav-hint")).toBeNull();
  });

  it("explains, without navigating, when the space does not match", async () => {
    api.runVol3Plugin.mockResolvedValue(result());
    await openPanel("physical");
    await runPlugin();
    fireEvent.click((await screen.findAllByTestId("vol3-row"))[0]);
    expect(await screen.findByTestId("vol3-nav-hint")).toHaveTextContent("kernel_va address");
    expect(useHexStore.getState().scrollToOffset).not.toHaveBeenCalled();
  });

  it("only navigates a process address when the pid matches the view's pid", async () => {
    const proc = result({
      columns: [{ name: "PID", type: "int", space: null }, { name: "VA", type: "hex", space: "process_va" }],
      rows: [{ depth: 0, values: [7, "5000"], absent: {} }, { depth: 0, values: [8, "5000"], absent: {} }],
      defaults_applied: { pid: [7] },
    });
    api.runVol3Plugin.mockResolvedValue(proc);
    useHexStore.setState({ vaSpanStart: 0 });
    await openPanel("process");
    await runPlugin();
    const rows = await screen.findAllByTestId("vol3-row");
    fireEvent.click(rows[1]);
    expect(await screen.findByTestId("vol3-nav-hint")).toHaveTextContent("pid 8");
    expect(useHexStore.getState().scrollToOffset).not.toHaveBeenCalled();
    fireEvent.click(rows[0]);
    await waitFor(() => expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(5000));
  });

  it("highlights a column through applyAnnotations with kind vol3:<plugin>", async () => {
    api.runVol3Plugin.mockResolvedValue(result());
    await openPanel("kernel");
    await runPlugin();
    await screen.findAllByTestId("vol3-row");
    fireEvent.click(screen.getByTestId("highlight-column"));
    await waitFor(() => expect(applyAnnotations).toHaveBeenCalled());
    const [entries, opts] = vi.mocked(applyAnnotations).mock.calls[0];
    expect(entries).toHaveLength(1);
    expect(entries[0].kind).toBe(`vol3:${PSLIST}`);
    expect(opts.space).toBe("kernel_va");
    const regions = useHexStore.getState().highlightedRegions;
    expect(regions).toHaveLength(1);
    expect(regions[0]).toMatchObject({ kind: `vol3:${PSLIST}`, offset: 0x1000, view: "va", dumpPath: VIEW });
  });

  it("keeps Save-as-annotations disabled without a case, and files them with one", async () => {
    api.runVol3Plugin.mockResolvedValue(result());
    await openPanel();
    await runPlugin();
    await screen.findAllByTestId("vol3-row");
    expect(screen.getByTestId("annotate-save")).toBeDisabled();
    expect(screen.getByTestId("annotate-disabled-hint")).toBeInTheDocument();

    api.runVol3Plugin.mockResolvedValue(result({ run_id: "r1", table: { name: "vol3__linux_pslist" } }));
    api.annotateVol3Run.mockResolvedValue({ created: 1 });
    fireEvent.change(screen.getByTestId("vol3-case-dir"), { target: { value: "/case" } });
    fireEvent.click(screen.getByTestId("vol3-run"));
    await waitFor(() => expect(screen.getByTestId("annotate-save")).toBeEnabled());
    fireEvent.change(screen.getByTestId("annotate-label"), { target: { value: "COMM" } });
    fireEvent.click(screen.getByTestId("annotate-save"));
    await waitFor(() => expect(api.annotateVol3Run).toHaveBeenCalledWith({
      case_dir: "/case", table: "vol3__linux_pslist", run_id: "r1", column: "OFFSET", label_column: "COMM" }));
    expect(await screen.findByTestId("annotate-note")).toHaveTextContent("Filed 1");
  });

  it("sends a column reinterpretation as column_map on the next run", async () => {
    api.runVol3Plugin.mockResolvedValue(result());
    await openPanel();
    await runPlugin();
    await screen.findAllByTestId("vol3-row");
    fireEvent.change(screen.getByTestId("space-select-OFFSET"), { target: { value: "physical" } });
    expect(screen.getByTestId("override-hint")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("vol3-run"));
    await waitFor(() => expect(api.runVol3Plugin).toHaveBeenCalledTimes(2));
    expect(api.runVol3Plugin.mock.calls[1][0].column_map).toEqual({ OFFSET: "physical" });
  });

  it("shows a backend failure as text", async () => {
    api.runVol3Plugin.mockRejectedValue(new Error(JSON.stringify({ error: "volatility3 is not installed" })));
    await openPanel();
    await runPlugin();
    expect(await screen.findByTestId("vol3-error")).toHaveTextContent("volatility3 is not installed");
  });
});
