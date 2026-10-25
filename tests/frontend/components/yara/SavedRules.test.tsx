import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { YaraRuleMeta } from "@/api/yara";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useImageStore } from "@/stores/image-store";

const api = vi.hoisted(() => ({
  checkYaraRule: vi.fn(), scanYara: vi.fn(), listYaraRules: vi.fn(), getYaraRule: vi.fn(),
  putYaraRule: vi.fn(), deleteYaraRule: vi.fn(), getYaraJobPayload: vi.fn(), cancelYaraJob: vi.fn(),
}));
vi.mock("@/api/yara", async (orig) => ({ ...(await orig<typeof import("@/api/yara")>()), ...api }));
vi.mock("@/hooks/useTaskProgress", () => ({ useTaskProgress: () => undefined }));

const { YaraPanel } = await import("@/components/yara/YaraPanel");

const DUMP = "/dumps/proc.msl";
const meta = (over: Partial<YaraRuleMeta> = {}): YaraRuleMeta => ({
  name: "keylog", scope: "library", version: 2, sha256: "ab", size: 10, compiles: true, errors: [],
  rule_names: ["keylog"], modified_externally: false, updated: null, shadows: false, shadowed: false,
  ...over,
});
const listed = (...rules: YaraRuleMeta[]) =>
  api.listYaraRules.mockResolvedValue({ case_dir: null, rules, count: rules.length });
const stored = (over: Record<string, unknown> = {}) => ({ ...meta(), ...over });
const scan = () => ({
  dump_path: DUMP, view: "va", space: "msl_va", rule_names: ["keylog"], matched_rules: [], rows: [],
  row_count: 0, limit: 1000, truncated: false, timed_out: false, complete: true,
  incomplete_reason: null, errors: [], warnings: [], rule_name: "keylog", scope: "library",
  coverage: { view: "va", captured_bytes: 1, bytes_scanned: 1, runs_scanned: 1, gaps_skipped: 0,
    gap_bytes: 0, short_reads: 0, requested_offset: 0, requested_length: null },
});

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.checkYaraRule.mockResolvedValue({ valid: true, rule_names: ["keylog"], errors: [], warnings: [] });
  listed();
  localStorage.clear();
  useImageStore.setState({ caseDir: "" });
  useAppStore.setState({ inputMode: "file" });
  useDumpStore.getState().clearAll();
  const id = useDumpStore.getState().addDump({ path: DUMP, name: "proc.msl", size: 10, format: "msl" });
  useDumpStore.getState().setActiveDump(id);
  useHexStore.setState({
    viewMode: "va", vaSpanStart: 0, pageStatesLoaded: true, availableViews: ["raw", "vas", "va"],
    highlightedRegions: [], selection: null, fetchPageStates: vi.fn(),
  });
});

afterEach(() => { localStorage.clear(); });

describe("stored rules from the backend", () => {
  it("lists them with scope, version and health markers", async () => {
    listed(
      meta(),
      meta({ name: "broken", compiles: false, modified_externally: true, version: 1 }),
      meta({ name: "both", scope: "case", shadows: true }),
      meta({ name: "both", shadowed: true }),
    );
    render(<YaraPanel />);
    const rows = await screen.findAllByTestId("yara-rule-row");
    expect(rows).toHaveLength(4);
    expect(within(rows[0]).getByTestId("yara-rule-scope")).toHaveTextContent("Library");
    expect(rows[0]).toHaveTextContent("v2");
    expect(within(rows[1]).getByTestId("yara-rule-broken")).toBeInTheDocument();
    expect(within(rows[1]).getByTestId("yara-rule-external")).toBeInTheDocument();
    expect(within(rows[2]).getByTestId("yara-rule-shadows")).toBeInTheDocument();
    expect(within(rows[3]).getByTestId("yara-rule-shadowed")).toBeInTheDocument();
    expect(within(rows[3]).getByTestId("yara-rule-load")).toBeDisabled();
    expect(screen.queryByText(/this browser only/i)).toBeNull();
  });

  it("asks the backend for the case's rules once a case directory is set", async () => {
    render(<YaraPanel />);
    await waitFor(() => expect(api.listYaraRules).toHaveBeenCalledWith(undefined));
    fireEvent.change(screen.getByTestId("yara-case-dir"), { target: { value: "/cases/a" } });
    await waitFor(() => expect(api.listYaraRules).toHaveBeenCalledWith("/cases/a"));
  });

  it("saves to the library, then lists it and reports the version", async () => {
    api.putYaraRule.mockResolvedValue({ stored: stored({ version: 1 }), check: { valid: true } });
    render(<YaraPanel />);
    fireEvent.change(screen.getByTestId("yara-name"), { target: { value: "keylog" } });
    fireEvent.click(screen.getByTestId("yara-save"));
    await waitFor(() => expect(api.putYaraRule).toHaveBeenCalledWith(
      "keylog", expect.stringContaining("SSLKEYLOGFILE"), "library", undefined));
    expect(await screen.findByTestId("yara-note")).toHaveTextContent("Saved keylog to the Library (version 1)");
    expect(api.listYaraRules.mock.calls.length).toBeGreaterThan(1);
  });

  it("saves to a case and needs a case directory for that", async () => {
    api.putYaraRule.mockResolvedValue({ stored: stored({ scope: "case", version: 3 }), check: { valid: true } });
    render(<YaraPanel />);
    fireEvent.change(screen.getByTestId("yara-name"), { target: { value: "keylog" } });
    fireEvent.change(screen.getByTestId("yara-scope"), { target: { value: "case" } });
    expect(screen.getByTestId("yara-save")).toBeDisabled();
    expect(screen.getByTestId("yara-case-needed")).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("yara-case-dir"), { target: { value: "/cases/a" } });
    fireEvent.click(screen.getByTestId("yara-save"));
    await waitFor(() => expect(api.putYaraRule).toHaveBeenCalledWith(
      "keylog", expect.any(String), "case", "/cases/a"));
    expect(await screen.findByTestId("yara-note")).toHaveTextContent("to the Case (version 3)");
  });

  it("flags a saved draft that does not compile and reports a refused write", async () => {
    api.putYaraRule.mockResolvedValueOnce({ stored: stored({ compiles: false }), check: { valid: false } });
    render(<YaraPanel />);
    fireEvent.change(screen.getByTestId("yara-name"), { target: { value: "draft" } });
    fireEvent.click(screen.getByTestId("yara-save"));
    expect(await screen.findByTestId("yara-note")).toHaveTextContent("does not compile");
    api.putYaraRule.mockRejectedValueOnce(new Error("disk full"));
    fireEvent.click(screen.getByTestId("yara-save"));
    await waitFor(() => expect(screen.getByTestId("yara-note")).toHaveTextContent("was not saved"));
  });

  it("loads a rule (per scope) into the editor and warns about an external edit", async () => {
    listed(meta({ name: "cr", scope: "case" }), meta());
    api.getYaraRule.mockResolvedValue({ ...stored({ name: "cr", scope: "case", modified_externally: true }),
      source: "rule cr { condition: true }" });
    fireEvent.change(await (async () => { render(<YaraPanel />); return screen.findByTestId("yara-case-dir"); })(),
      { target: { value: "/cases/a" } });
    const row = (await screen.findAllByTestId("yara-rule-row"))[0];
    fireEvent.click(within(row).getByTestId("yara-rule-load"));
    await waitFor(() => expect((screen.getByTestId("editor-textarea") as HTMLTextAreaElement).value)
      .toBe("rule cr { condition: true }"));
    expect(api.getYaraRule).toHaveBeenCalledWith("cr", "/cases/a");
    expect(screen.getByTestId("yara-note")).toHaveTextContent("changed outside MemDiver");
    expect((screen.getByTestId("yara-name") as HTMLInputElement).value).toBe("cr");
    expect((screen.getByTestId("yara-scope") as HTMLSelectElement).value).toBe("case");
  });

  it("loads a library rule without sending the case directory", async () => {
    listed(meta());
    api.getYaraRule.mockResolvedValue({ ...stored(), source: "rule keylog { condition: true }" });
    render(<YaraPanel />);
    fireEvent.change(screen.getByTestId("yara-case-dir"), { target: { value: "/cases/a" } });
    fireEvent.click(await screen.findByTestId("yara-rule-load"));
    await waitFor(() => expect(api.getYaraRule).toHaveBeenCalledWith("keylog", undefined));
  });

  it("deletes only after a confirmation", async () => {
    listed(meta());
    api.deleteYaraRule.mockResolvedValue({ name: "keylog", deleted: true, scope: "library" });
    render(<YaraPanel />);
    fireEvent.click(await screen.findByTestId("yara-rule-delete"));
    expect(api.deleteYaraRule).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId("yara-rule-confirm-no"));
    expect(screen.queryByTestId("yara-rule-confirm")).toBeNull();
    fireEvent.click(screen.getByTestId("yara-rule-delete"));
    fireEvent.click(screen.getByTestId("yara-rule-confirm-yes"));
    await waitFor(() => expect(api.deleteYaraRule).toHaveBeenCalledWith("keylog", "library", undefined));
    expect(await screen.findByTestId("yara-note")).toHaveTextContent("Deleted keylog");
  });

  it("scans a saved, unchanged rule by name, and by text once it is edited", async () => {
    listed(meta());
    api.getYaraRule.mockResolvedValue({ ...stored(), source: "rule keylog { condition: true }" });
    api.scanYara.mockResolvedValue(scan());
    render(<YaraPanel />);
    fireEvent.click(await screen.findByTestId("yara-rule-load"));
    await waitFor(() => expect((screen.getByTestId("yara-name") as HTMLInputElement).value).toBe("keylog"));
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-by-name");
    expect(api.scanYara.mock.calls[0][0]).toMatchObject({ dump_path: DUMP, rule_name: "keylog" });
    expect(api.scanYara.mock.calls[0][0]).not.toHaveProperty("rule_source");
    expect(api.scanYara.mock.calls[0][0]).not.toHaveProperty("case_dir");
    fireEvent.change(screen.getByTestId("editor-textarea"), { target: { value: "rule keylog { condition: false }" } });
    fireEvent.click(screen.getByTestId("yara-run"));
    await waitFor(() => expect(api.scanYara).toHaveBeenCalledTimes(2));
    expect(api.scanYara.mock.calls[1][0]).toMatchObject({ rule_source: "rule keylog { condition: false }" });
    expect(api.scanYara.mock.calls[1][0]).not.toHaveProperty("rule_name");
  });

  it("scans a loaded case rule by name with its case directory", async () => {
    listed(meta({ scope: "case" }));
    api.getYaraRule.mockResolvedValue({ ...stored({ scope: "case" }), source: "rule keylog { condition: true }" });
    api.scanYara.mockResolvedValue(scan());
    render(<YaraPanel />);
    fireEvent.change(screen.getByTestId("yara-case-dir"), { target: { value: "/cases/a" } });
    fireEvent.click(await screen.findByTestId("yara-rule-load"));
    await waitFor(() => expect((screen.getByTestId("yara-name") as HTMLInputElement).value).toBe("keylog"));
    fireEvent.click(screen.getByTestId("yara-run"));
    await waitFor(() => expect(api.scanYara).toHaveBeenCalled());
    expect(api.scanYara.mock.calls[0][0]).toMatchObject({ rule_name: "keylog", case_dir: "/cases/a" });
  });

  it("shows a backend listing failure instead of an empty list", async () => {
    api.listYaraRules.mockRejectedValue(new Error("down"));
    render(<YaraPanel />);
    expect(await screen.findByTestId("yara-rules-error")).toHaveTextContent("Could not list");
  });
});

describe("one-time import of browser-saved rules", () => {
  const seed = (rules: Record<string, string>) =>
    localStorage.setItem("memdiver.yara.rules", JSON.stringify(rules));

  it("imports into the library once, skips stored names and never overwrites", async () => {
    seed({ keylog: "rule keylog {condition: true}", fresh: "rule fresh {condition: true}" });
    listed(meta({ name: "keylog" }));
    api.putYaraRule.mockResolvedValue({ stored: stored({ name: "fresh" }), check: { valid: true } });
    render(<YaraPanel />);
    const report = await screen.findByTestId("yara-import-report");
    expect(api.putYaraRule).toHaveBeenCalledTimes(1);
    expect(api.putYaraRule).toHaveBeenCalledWith("fresh", "rule fresh {condition: true}", "library");
    expect(report).toHaveTextContent("Imported 1 rules");
    expect(report).toHaveTextContent("Skipped 1 already stored (not overwritten): keylog");
    expect(localStorage.getItem("memdiver.yara.rules.imported")).toBe("1");
    expect(localStorage.getItem("memdiver.yara.rules")).not.toBeNull();   // the old copy is kept

    // A second mount (a reload) imports nothing.
    api.putYaraRule.mockClear();
    render(<YaraPanel />);
    await act(async () => { await Promise.resolve(); });
    expect(api.putYaraRule).not.toHaveBeenCalled();
  });

  it("stays open for a retry when a write failed", async () => {
    seed({ a: "rule a {condition: true}" });
    api.putYaraRule.mockRejectedValue(new Error("nope"));
    render(<YaraPanel />);
    expect(await screen.findByTestId("yara-import-report")).toHaveTextContent("Could not import a");
    expect(localStorage.getItem("memdiver.yara.rules.imported")).toBeNull();
  });

  it("does nothing, and does not throw, when storage is blocked", async () => {
    const get = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("denied"); });
    const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("denied"); });
    render(<YaraPanel />);
    await act(async () => { await Promise.resolve(); });
    expect(api.putYaraRule).not.toHaveBeenCalled();
    expect(screen.queryByTestId("yara-import-report")).toBeNull();
    get.mockRestore();
    set.mockRestore();
  });

  it("marks an empty legacy store as done without asking the backend", async () => {
    render(<YaraPanel />);
    await waitFor(() => expect(localStorage.getItem("memdiver.yara.rules.imported")).toBe("1"));
    expect(api.putYaraRule).not.toHaveBeenCalled();
  });
});

describe("editor-vs-scan identity, import retries, case errors", () => {
  const loadCaseRule = async () => {
    listed(meta({ name: "cr", scope: "case" }));
    api.getYaraRule.mockResolvedValue({ ...stored({ name: "cr", scope: "case" }),
      source: "rule cr { condition: true }" });
    render(<YaraPanel />);
    fireEvent.change(await screen.findByTestId("yara-case-dir"), { target: { value: "/cases/a" } });
    const row = (await screen.findAllByTestId("yara-rule-row"))[0];
    fireEvent.click(within(row).getByTestId("yara-rule-load"));
    await waitFor(() => expect(api.getYaraRule).toHaveBeenCalled());
  };

  it("scans a case rule by name only while the case directory is the one it was loaded from", async () => {
    await loadCaseRule();
    api.scanYara.mockResolvedValue({ ...scan(), rule_name: "cr", scope: "case" });
    await waitFor(() => expect((screen.getByTestId("yara-name") as HTMLInputElement).value).toBe("cr"));
    fireEvent.click(screen.getByTestId("yara-run"));
    await waitFor(() => expect(api.scanYara).toHaveBeenCalledTimes(1));
    expect(api.scanYara.mock.calls[0][0]).toMatchObject({ rule_name: "cr", case_dir: "/cases/a" });

    fireEvent.change(screen.getByTestId("yara-case-dir"), { target: { value: "/cases/b" } });
    fireEvent.click(screen.getByTestId("yara-run"));
    await waitFor(() => expect(api.scanYara).toHaveBeenCalledTimes(2));
    const second = api.scanYara.mock.calls[1][0];
    expect(second.rule_name).toBeUndefined();
    expect(second.rule_source).toBe("rule cr { condition: true }");
  });

  it("reports an invalid-name or empty legacy rule once and marks the import done", async () => {
    localStorage.setItem("memdiver.yara.rules", JSON.stringify({
      "bad name!": "rule x {condition: true}", empty: "  ", good: "rule good {condition: true}" }));
    api.putYaraRule.mockResolvedValue({ stored: stored({ name: "good" }), check: { valid: true } });
    render(<YaraPanel />);
    const report = await screen.findByTestId("yara-import-report");
    expect(screen.getByTestId("yara-import-invalid")).toHaveTextContent("bad name!, empty");
    expect(report).toHaveTextContent("Imported 1 rules");
    expect(api.putYaraRule).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem("memdiver.yara.rules.imported")).toBe("1");
  });

  it("typing a case directory neither re-runs the import nor lists on every keystroke", async () => {
    localStorage.setItem("memdiver.yara.rules", JSON.stringify({ a: "rule a {condition: true}" }));
    api.putYaraRule.mockRejectedValue(new TypeError("network"));
    render(<YaraPanel />);
    await screen.findByTestId("yara-import-report");
    api.putYaraRule.mockClear();
    api.listYaraRules.mockClear();
    const input = screen.getByTestId("yara-case-dir");
    for (const v of ["/c", "/ca", "/cas", "/case"]) fireEvent.change(input, { target: { value: v } });
    await waitFor(() => expect(api.listYaraRules).toHaveBeenCalledTimes(1));
    expect(api.listYaraRules).toHaveBeenCalledWith("/case");
    expect(api.putYaraRule).not.toHaveBeenCalled();
  });

  it("keeps the library rows and shows case_error inline for a missing case directory", async () => {
    api.listYaraRules.mockResolvedValue({ case_dir: "/nope", case_error: "case dir not found",
      rules: [meta()], count: 1 });
    render(<YaraPanel />);
    fireEvent.change(await screen.findByTestId("yara-case-dir"), { target: { value: "/nope" } });
    expect(await screen.findByTestId("yara-case-error")).toHaveTextContent("case dir not found");
    expect(screen.getAllByTestId("yara-rule-row")).toHaveLength(1);
  });

  it("a refused (403) case directory shows its message and still lists the library", async () => {
    const { ApiError } = await import("@/api/client");
    api.listYaraRules.mockImplementation((c?: string) => c
      ? Promise.reject(new ApiError(403, "case_dir must be inside the upload dir or ~/.memdiver"))
      : Promise.resolve({ case_dir: null, rules: [meta()], count: 1 }));
    render(<YaraPanel />);
    fireEvent.change(await screen.findByTestId("yara-case-dir"), { target: { value: "/etc" } });
    expect(await screen.findByTestId("yara-case-error")).toHaveTextContent("inside the upload dir");
    expect(screen.getAllByTestId("yara-rule-row")).toHaveLength(1);
    expect(screen.queryByTestId("yara-rules-error")).toBeNull();
  });
});
