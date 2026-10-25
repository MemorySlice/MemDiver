import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { stubVirtualizerLayout } from "../../helpers/virtualizer";
import type { Vol3Column, Vol3RunResult } from "@/api/vol3";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useImageStore } from "@/stores/image-store";
import { useSelectionStore } from "@/stores/selection-store";

const api = vi.hoisted(() => ({
  listVol3Plugins: vi.fn(), describeVol3Plugin: vi.fn(), runVol3Plugin: vi.fn(),
  annotateVol3Run: vi.fn(), cancelVol3Job: vi.fn(), listVol3SavedQueries: vi.fn(), runVol3Query: vi.fn(),
}));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));
const rec = vi.hoisted(() => ({ listAnnotations: vi.fn(), addAnnotation: vi.fn(), retractAnnotation: vi.fn() }));
vi.mock("@/api/annotations", () => rec);
const client = vi.hoisted(() => ({ previewImport: vi.fn(), getPageStates: vi.fn() }));
vi.mock("@/api/client", async (orig) => ({ ...(await orig<typeof import("@/api/client")>()), ...client }));
vi.mock("@/hooks/useTaskProgress", () => ({ useTaskProgress: () => undefined }));

const { Vol3Panel } = await import("@/components/vol3/Vol3Panel");

const SPAN = 0xffff888000000000n;
const VIEW = "/case/kernel.mdview";
const col = (name: string, space: string | null = null): Vol3Column => ({ name, type: space ? "hex" : "str", space });
const base = (over: Partial<Vol3RunResult>): Vol3RunResult => ({
  plugin: "linux.pslist.PsList", capture_id: "cap", columns: [], rows: [], row_count: 0, rows_returned: 0,
  truncated: false, stop_reason: null, elapsed_s: 0, diagnostics: [], files: [], defaults_applied: {},
  args: {}, table: null, run_id: null, ...over,
});
const psRows = [[1, 0, "systemd"], [2, 1, "kthreadd"], [3, 1, "sshd"]].map((values) => ({ depth: 0, values, absent: {} }));
const pslist = (over: Partial<Vol3RunResult> = {}) => base({
  columns: [col("PID"), col("PPID"), col("COMM"), col("OFFSET", "kernel_va")],
  rows: psRows.map((r, i) => ({ ...r, values: [...r.values, (SPAN + BigInt(0x1000 * (i + 1))).toString()] })),
  row_count: 3, rows_returned: 3, ...over,
});

async function open(kind: "kernel" | "process" = "kernel", view: object | null = { kind, pid: kind === "process" ? 7 : null, capture_id: "cap", view_path: VIEW }) {
  useAppStore.setState({ inputMode: "file" });
  const id = useDumpStore.getState().addDump({ path: VIEW, name: "kernel.mdview", size: 10, format: "raw" });
  useDumpStore.getState().setActiveDump(id);
  client.previewImport.mockResolvedValue({ view_kind: kind, ...(view ? { view } : {}) });
  render(<Vol3Panel />);
  await screen.findAllByTestId("plugin-option");
  await waitFor(() => expect(client.previewImport).toHaveBeenCalled());
}

async function runFirstPlugin() {
  fireEvent.click((await screen.findAllByTestId("plugin-option"))[0]);
  await screen.findByTestId("args-form");
  await waitFor(() => expect(screen.getByTestId("vol3-run")).toBeEnabled());
  fireEvent.click(screen.getByTestId("vol3-run"));
}
const setCase = (dir: string) => fireEvent.change(screen.getByTestId("vol3-case-dir"), { target: { value: dir } });

beforeEach(() => {
  stubVirtualizerLayout(900, 240);
  [...Object.values(api), ...Object.values(client), ...Object.values(rec)].forEach((m) => m.mockReset());
  useDumpStore.getState().clearAll();
  useImageStore.getState().reset();
  useSelectionStore.getState().clear();
  useHexStore.setState({ viewMode: "va", vaSpanStart: Number(SPAN), vaSize: 1 << 20, pageStatesLoaded: true,
    highlightedRegions: [], scrollToOffset: vi.fn() });
  api.listVol3Plugins.mockResolvedValue({ os_family: "linux", count: 1,
    plugins: [{ name: "linux.pslist.PsList", description: "", version: "1" }] });
  api.describeVol3Plugin.mockResolvedValue({ name: "linux.pslist.PsList", description: "", version: "1", satisfied_by_context: [],
    requirements: [{ name: "pid", type: "array", items: { type: "integer" }, requirement: "ListRequirement",
      description: "", optional: true, default: null }] });
  api.listVol3SavedQueries.mockResolvedValue({ saved_queries: [], count: 0 });
  rec.listAnnotations.mockResolvedValue({ entries: [], count: 0 });
  rec.addAnnotation.mockResolvedValue({});
  rec.retractAnnotation.mockResolvedValue({});
});

describe("process-address navigation from the view block", () => {
  const proc = (pid: number) => base({
    columns: [col("PID"), col("ADDR", "process_va")], row_count: 1, rows_returned: 1,
    rows: [{ depth: 0, values: [pid, (SPAN + 0x2000n).toString()], absent: {} }],
    view: { kind: "process", pid: 7, capture_id: "cap", view_path: VIEW },
  });

  it("uses view.pid (no defaults_applied) so a row of that pid scrolls to its offset", async () => {
    api.runVol3Plugin.mockResolvedValue(proc(7));
    await open("process", null); // preview carries no view: the run's view block must do it
    await runFirstPlugin();
    fireEvent.click((await screen.findAllByTestId("vol3-row"))[0]);
    await waitFor(() => expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x2000));
  });

  it("refuses a row of another pid and says which pid the view is", async () => {
    api.runVol3Plugin.mockResolvedValue(proc(8));
    await open("process");
    await runFirstPlugin();
    fireEvent.click((await screen.findAllByTestId("vol3-row"))[0]);
    expect(await screen.findByTestId("vol3-nav-hint")).toHaveTextContent(/pid 8.*pid 7/);
    expect(useHexStore.getState().scrollToOffset).not.toHaveBeenCalled();
  });

  it("takes the pid from the import preview's view block before any run", async () => {
    api.runVol3Plugin.mockResolvedValue({ ...proc(7), view: undefined });
    await open("process");
    await runFirstPlugin();
    fireEvent.click((await screen.findAllByTestId("vol3-row"))[0]);
    await waitFor(() => expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x2000));
  });
});

describe("selection-linked results", () => {
  it("filters rows to the selected pid and still navigates by ORIGINAL row", async () => {
    api.runVol3Plugin.mockResolvedValue(pslist());
    await open();
    await runFirstPlugin();
    await screen.findAllByTestId("vol3-row");
    expect(screen.getByTestId("pid-filter-toggle")).toBeDisabled();
    useSelectionStore.getState().setPid(3);
    await waitFor(() => expect(screen.getByTestId("pid-filter-toggle")).toBeEnabled());
    fireEvent.click(screen.getByTestId("pid-filter-toggle"));
    const rows = screen.getAllByTestId("vol3-row");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("sshd");
    fireEvent.click(rows[0]);
    await waitFor(() => expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x3000));
    fireEvent.click(screen.getByTestId("pid-filter-toggle"));
    expect(screen.getAllByTestId("vol3-row")).toHaveLength(3);
  });

  it("prefills the pid argument from the selection, visibly, and sends it", async () => {
    api.runVol3Plugin.mockResolvedValue(pslist());
    useSelectionStore.getState().setPid(2);
    await open();
    fireEvent.click((await screen.findAllByTestId("plugin-option"))[0]);
    await screen.findByTestId("args-form");
    await waitFor(() => expect(screen.getByLabelText(/pid/)).toHaveValue("2"));
    expect(screen.getByTestId("pid-selected-hint")).toHaveTextContent("pid 2");
    fireEvent.click(screen.getByTestId("vol3-run"));
    await waitFor(() => expect(api.runVol3Plugin).toHaveBeenCalledWith(expect.objectContaining({ args: { pid: [2] } })));
  });

  it("does not overwrite a pid the user typed", async () => {
    await open();
    fireEvent.click((await screen.findAllByTestId("plugin-option"))[0]);
    await screen.findByTestId("args-form");
    fireEvent.change(screen.getByLabelText(/pid/), { target: { value: "99" } });
    useSelectionStore.getState().setPid(2);
    await waitFor(() => expect(screen.getByLabelText(/pid/)).toHaveValue("99"));
  });

  it("leaves a process view's pid to the view (no prefill)", async () => {
    useSelectionStore.getState().setPid(2);
    await open("process");
    fireEvent.click((await screen.findAllByTestId("plugin-option"))[0]);
    await screen.findByTestId("args-form");
    expect(screen.getByLabelText(/pid/)).toHaveValue("");
  });
});

describe("process tree mode", () => {
  it("loads linux.pstree, shows the tree and selecting a node sets the pid", async () => {
    api.runVol3Plugin.mockResolvedValue(pslist({ plugin: "linux.pstree.PsTree" }));
    await open();
    fireEvent.click(screen.getByTestId("vol3-mode-processes"));
    expect(screen.getByTestId("tree-empty")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("load-process-tree"));
    expect(api.runVol3Plugin).toHaveBeenCalledWith(expect.objectContaining({ view_path: VIEW, plugin: "linux.pstree.PsTree" }));
    const nodes = await screen.findAllByTestId("tree-node");
    expect(nodes).toHaveLength(3);
    fireEvent.click(within(nodes[2]).getByTestId("tree-select"));
    expect(useSelectionStore.getState().pid).toBe(3);
    expect(screen.getAllByTestId("tree-node")[2]).toHaveAttribute("aria-selected", "true");
  });

  it("collapses a subtree and searches", async () => {
    api.runVol3Plugin.mockResolvedValue(pslist());
    await open();
    await runFirstPlugin();
    await screen.findAllByTestId("vol3-row");
    fireEvent.click(screen.getByTestId("vol3-mode-processes"));
    expect(screen.getAllByTestId("tree-node")).toHaveLength(3);
    fireEvent.click(screen.getAllByTestId("tree-toggle")[0]);
    expect(screen.getAllByTestId("tree-node")).toHaveLength(1);
    fireEvent.change(screen.getByTestId("tree-search"), { target: { value: "ssh" } });
    expect(screen.getAllByTestId("tree-node")).toHaveLength(2);
  });
});

describe("highlight rules in the table", () => {
  const maps = (flags: string, path: string | null) => base({
    plugin: "linux.proc.Maps", columns: [col("Start", "process_va"), col("Flags"), col("File Path")],
    rows: [{ depth: 0, values: [4096, flags, path], absent: {} }], row_count: 1, rows_returned: 1,
  });

  it("marks a w+x mapping with a glyph and a label, not just colour", async () => {
    api.runVol3Plugin.mockResolvedValue(maps("rwxp", "/x"));
    await open();
    await runFirstPlugin();
    const row = (await screen.findAllByTestId("vol3-row"))[0];
    expect(row).toHaveAttribute("data-rule-style", "danger");
    expect(within(row).getByTestId("rule-marker")).toHaveAttribute("aria-label", "Danger");
    expect(within(row).getByTestId("rule-marker")).toHaveTextContent("✖");
  });

  it("leaves a benign mapping unmarked", async () => {
    api.runVol3Plugin.mockResolvedValue(maps("r--p", "/lib"));
    await open();
    await runFirstPlugin();
    const row = (await screen.findAllByTestId("vol3-row"))[0];
    expect(row).not.toHaveAttribute("data-rule-style");
  });

  it("loads stored rules on open and applies them", async () => {
    rec.listAnnotations.mockResolvedValue({ count: 1, entries: [{ id: "e1", kind: "table_rule", locations: [],
      payload: { id: "u", table: "proc.Maps", column: "File Path", op: "contains", value: "/tmp", style: "warn" } }] });
    api.runVol3Plugin.mockResolvedValue(maps("r--p", "/tmp/evil"));
    await open();
    setCase("/case");
    await waitFor(() => expect(rec.listAnnotations).toHaveBeenCalledWith("/case", "cap", "table_rule"));
    await runFirstPlugin();
    const row = (await screen.findAllByTestId("vol3-row"))[0];
    await waitFor(() => expect(row).toHaveAttribute("data-rule-style", "warn"));
  });

  it("adds a rule through the editor and disables a stored one (retract)", async () => {
    rec.listAnnotations.mockResolvedValue({ count: 1, entries: [{ id: "e1", kind: "table_rule", locations: [],
      payload: { id: "u", table: "lsof", column: "Path", op: "eq", value: "x", style: "ok" } }] });
    await open();
    setCase("/case");
    fireEvent.click(screen.getByText("Highlight rules"));
    await screen.findAllByTestId("rule-item");
    fireEvent.change(screen.getByTestId("rule-table"), { target: { value: "pslist" } });
    fireEvent.change(screen.getByTestId("rule-column"), { target: { value: "COMM" } });
    fireEvent.change(screen.getByTestId("rule-op"), { target: { value: "in" } });
    fireEvent.change(screen.getByTestId("rule-value"), { target: { value: "a, b" } });
    fireEvent.change(screen.getByTestId("rule-style"), { target: { value: "danger" } });
    fireEvent.click(screen.getByTestId("rule-add"));
    await waitFor(() => expect(rec.addAnnotation).toHaveBeenCalledWith(expect.objectContaining({
      case_dir: "/case", capture_id: "cap", kind: "table_rule",
      payload: expect.objectContaining({ table: "pslist", column: "COMM", op: "in", value: ["a", "b"], style: "danger" }) })));
    fireEvent.click(screen.getByTestId("rule-disable"));
    await waitFor(() => expect(rec.retractAnnotation).toHaveBeenCalledWith(expect.objectContaining({ entry_id: "e1" })));
  });

  it("refuses an invalid regex without calling the API", async () => {
    await open();
    setCase("/case");
    fireEvent.click(screen.getByText("Highlight rules"));
    await waitFor(() => expect(screen.getByTestId("rule-add")).toBeEnabled());
    fireEvent.change(screen.getByTestId("rule-table"), { target: { value: "pslist" } });
    fireEvent.change(screen.getByTestId("rule-column"), { target: { value: "COMM" } });
    fireEvent.change(screen.getByTestId("rule-op"), { target: { value: "regex" } });
    fireEvent.change(screen.getByTestId("rule-value"), { target: { value: "(" } });
    fireEvent.click(screen.getByTestId("rule-add"));
    expect(screen.getByTestId("rule-invalid")).toBeInTheDocument();
    expect(rec.addAnnotation).not.toHaveBeenCalled();
  });
});

describe("query box", () => {
  const q = (over: object = {}) => ({ columns: ["addr", "space", "pid"], row_count: 2, limit: 10, elapsed_s: 0, truncated: false,
    rows: [[(SPAN + 0x1000n).toString(), "kernel_va", null], [(SPAN + 0x5000n).toString(), "physical", null]], ...over });

  async function toQuery() {
    api.listVol3SavedQueries.mockResolvedValue({ count: 1, saved_queries: [
      { name: "wx_maps", description: "d", sql: "SELECT addr, space, pid FROM maps" }] });
    await open();
    setCase("/case");
    fireEvent.click(screen.getByTestId("vol3-mode-query"));
  }

  it("lists saved queries, fills the SQL from one and runs it", async () => {
    api.runVol3Query.mockResolvedValue(q());
    await toQuery();
    await waitFor(() => expect(api.listVol3SavedQueries).toHaveBeenCalledWith("/case"));
    await screen.findByRole("option", { name: "wx_maps" });
    fireEvent.change(screen.getByTestId("query-saved"), { target: { value: "wx_maps" } });
    expect(screen.getByTestId("query-sql")).toHaveValue("SELECT addr, space, pid FROM maps");
    fireEvent.click(screen.getByTestId("query-run"));
    await waitFor(() => expect(api.runVol3Query).toHaveBeenCalledWith("/case", { saved: "wx_maps" }));
    expect(await screen.findAllByTestId("query-row")).toHaveLength(2);
  });

  it("shows a query error and keeps Run off for empty SQL", async () => {
    api.runVol3Query.mockRejectedValue(new Error("bad sql"));
    await toQuery();
    expect(screen.getByTestId("query-run")).toBeDisabled();
    fireEvent.change(screen.getByTestId("query-sql"), { target: { value: "DROP" } });
    fireEvent.click(screen.getByTestId("query-run"));
    expect(await screen.findByTestId("query-error")).toBeInTheDocument();
  });

  it("sends addr+space rows to highlights as vol3:query, skipping rows the view cannot place", async () => {
    api.runVol3Query.mockResolvedValue(q());
    await toQuery();
    fireEvent.change(screen.getByTestId("query-sql"), { target: { value: "SELECT 1" } });
    fireEvent.click(screen.getByTestId("query-run"));
    fireEvent.click(await screen.findByTestId("query-send"));
    await waitFor(() => expect(screen.getByTestId("query-note")).toBeInTheDocument());
    const regions = useHexStore.getState().highlightedRegions;
    expect(regions).toHaveLength(1);
    expect(regions[0]).toMatchObject({ kind: "vol3:query", offset: 0x1000 });
    expect(screen.getByTestId("query-note")).toHaveTextContent(/1 rows.*1 could not/);
  });

  it("offers no send button when the result has no addr/space columns", async () => {
    api.runVol3Query.mockResolvedValue(q({ columns: ["n"], rows: [[1]] }));
    await toQuery();
    fireEvent.change(screen.getByTestId("query-sql"), { target: { value: "SELECT 1" } });
    fireEvent.click(screen.getByTestId("query-run"));
    await screen.findAllByTestId("query-row");
    expect(screen.queryByTestId("query-send")).toBeNull();
  });
});
