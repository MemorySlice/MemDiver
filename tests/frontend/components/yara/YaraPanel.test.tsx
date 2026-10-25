import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { YaraCheckResult, YaraHitRow, YaraScanResult } from "@/api/yara";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useYaraStore } from "@/stores/yara-store";

const api = vi.hoisted(() => ({
  checkYaraRule: vi.fn(), scanYara: vi.fn(), listYaraRules: vi.fn(), getYaraRule: vi.fn(),
  putYaraRule: vi.fn(), deleteYaraRule: vi.fn(), getYaraJobPayload: vi.fn(), cancelYaraJob: vi.fn(),
}));
vi.mock("@/api/yara", async (orig) => ({ ...(await orig<typeof import("@/api/yara")>()), ...api }));

const { YaraPanel } = await import("@/components/yara/YaraPanel");
const { HexLegend } = await import("@/components/hex/HexLegend");

const SPAN = 0x1000;
const DUMP = "/dumps/proc.msl";
const hexState = useHexStore.getState();
const originalScroll = hexState.scrollToOffset;
const originalFetchPageStates = hexState.fetchPageStates;

const OK: YaraCheckResult = { valid: true, rule_names: ["example"], errors: [], warnings: [] };

const row = (over: Partial<YaraHitRow> = {}): YaraHitRow => ({
  rule: "example", tags: [], string_id: "$a", addr: SPAN + 0x40, space: "msl_va", length: 13,
  matched_hex: "53534c4b45594c4f4746494c45", va: SPAN + 0x40, vas_offset: 0x40, region: null, ...over,
});

const scan = (over: Partial<YaraScanResult> = {}): YaraScanResult => ({
  dump_path: DUMP, view: "va", space: "msl_va", rule_names: ["example"], matched_rules: ["example"],
  rows: [row()], row_count: 1, limit: 1000, truncated: false, timed_out: false, complete: true,
  incomplete_reason: null, errors: [], warnings: [],
  coverage: {
    view: "va", captured_bytes: 4096, bytes_scanned: 4096, runs_scanned: 2, gaps_skipped: 1,
    gap_bytes: 8192, short_reads: 0, requested_offset: 0, requested_length: null,
  },
  ...over,
});

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.checkYaraRule.mockResolvedValue(OK);
  api.listYaraRules.mockResolvedValue({ case_dir: null, rules: [], count: 0 });
  localStorage.clear();
  useAppStore.setState({ inputMode: "file" });
  useDumpStore.getState().clearAll();
  const id = useDumpStore.getState().addDump({ path: DUMP, name: "proc.msl", size: 10, format: "msl" });
  useDumpStore.getState().setActiveDump(id);
  useHexStore.setState({
    viewMode: "va", vaSpanStart: SPAN, pageStatesLoaded: true, availableViews: ["raw", "vas", "va"],
    highlightedRegions: [], selection: null, scrollToOffset: vi.fn(), fetchPageStates: vi.fn(),
  });
  useYaraStore.setState({ painted: [] });
});

afterEach(() => {
  useHexStore.setState({
    scrollToOffset: originalScroll, fetchPageStates: originalFetchPageStates, selection: null,
    highlightedRegions: [],
  });
});

describe("YaraPanel", () => {
  it("marks the line libyara names and shows the message", async () => {
    api.checkYaraRule.mockResolvedValue({
      valid: false, rule_names: [], warnings: [],
      errors: [{ line: 3, message: 'undefined string "$b"' }],
    });
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-compile"));
    const error = await screen.findByTestId("yara-check-error");
    expect(error).toHaveTextContent("line 3");
    expect(error).toHaveTextContent('undefined string "$b"');
    const gutter = screen.getAllByTestId("gutter-line");
    expect(gutter[2]).toHaveAttribute("data-error", "true");
    expect(gutter.filter((g) => g.hasAttribute("data-error"))).toHaveLength(1);
  });

  it("marks the PRECISE line (not libyara's), with column, rule and hint in the message", async () => {
    api.checkYaraRule.mockResolvedValue({
      valid: false, rule_names: [], warnings: [],
      errors: [{
        line: 2, column: 11, end_column: 13, reported_line: 5, relocated: true, rule: "keylog",
        message: 'undefined string "$b"', hint: "define $b in the strings section",
      }],
    });
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-compile"));
    const error = await screen.findByTestId("yara-check-error");
    expect(error).toHaveTextContent("line 2, column 11");
    expect(error).toHaveTextContent("keylog");
    expect(screen.getByTestId("yara-check-hint")).toHaveTextContent("define $b");
    const gutter = screen.getAllByTestId("gutter-line");
    expect(gutter[1]).toHaveAttribute("data-error", "true");
    expect(gutter[4]).not.toHaveAttribute("data-error");
  });

  it("falls back to libyara's reported line when none was located", async () => {
    api.checkYaraRule.mockResolvedValue({
      valid: false, rule_names: [], warnings: [],
      errors: [{ line: null, reported_line: 3, message: "boom" }],
    });
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-compile"));
    await screen.findByTestId("yara-check-error");
    expect(screen.getAllByTestId("gutter-line")[2]).toHaveAttribute("data-error", "true");
  });

  it("retires the error marker as soon as the source is edited", async () => {
    api.checkYaraRule.mockResolvedValue({
      valid: false, rule_names: [], warnings: [], errors: [{ line: 2, message: "boom" }],
    });
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-compile"));
    await screen.findByTestId("yara-check-error");
    fireEvent.change(screen.getByTestId("editor-textarea"), { target: { value: "rule a { condition: true }" } });
    expect(screen.queryByTestId("yara-check-error")).toBeNull();
  });

  it("shows the rule names of a rule that compiles", async () => {
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-compile"));
    expect(await screen.findByTestId("yara-check-ok")).toHaveTextContent("example");
  });

  it("runs the rule, renders rows and paints them as yara_hit regions in the view's offsets", async () => {
    api.scanYara.mockResolvedValue(scan());
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-table");
    expect(api.scanYara).toHaveBeenCalledWith(expect.objectContaining({ dump_path: DUMP, view: "va" }));
    expect(api.scanYara.mock.calls[0][0].rule_source).toContain("SSLKEYLOGFILE");
    const cells = within(screen.getByTestId("yara-row")).getAllByRole("cell");
    expect(cells.map((c) => c.textContent)).toEqual(
      ["example", "$a", "0x1040", "13", "53534c4b45594c4f…"]);
    expect(useHexStore.getState().highlightedRegions).toHaveLength(1);
    expect(useHexStore.getState().highlightedRegions[0])
      .toMatchObject({ kind: "yara_hit", offset: 0x40, length: 13, view: "va" });
    expect(screen.getByTestId("yara-coverage")).toHaveTextContent("1 capture gaps were skipped");
  });

  it("does not scan a rule that does not compile", async () => {
    api.checkYaraRule.mockResolvedValue({
      valid: false, rule_names: [], warnings: [], errors: [{ line: 1, message: "bad" }],
    });
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-check-error");
    expect(api.scanYara).not.toHaveBeenCalled();
  });

  it("navigates to a hit and selects the matched bytes when its row is clicked", async () => {
    api.scanYara.mockResolvedValue(scan({ rows: [row(), row({ addr: SPAN + 0x800, vas_offset: 0x800, va: SPAN + 0x800 })], row_count: 2 }));
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-table");
    fireEvent.click(screen.getAllByTestId("yara-row")[1]);
    expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x800);
    expect(useHexStore.getState().selection).toEqual({ anchor: 0x800, active: 0x800 + 12 });
    expect(screen.getAllByTestId("yara-row")[1]).toHaveAttribute("aria-selected", "true");
  });

  it("scopes the scan to the hex selection in the scan view's coordinates", async () => {
    api.scanYara.mockResolvedValue(scan({ rows: [], row_count: 0 }));
    useHexStore.setState({ selection: { anchor: 0x10, active: 0x1f } });
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-region-selection"));
    fireEvent.click(screen.getByTestId("yara-run"));
    await screen.findByTestId("yara-empty");
    expect(api.scanYara).toHaveBeenCalledWith(expect.objectContaining({
      view: "va", offset: SPAN + 0x10, length: 0x10,
    }));
  });

  it("says when the result is truncated and that a truncated empty list is no proof", async () => {
    api.scanYara.mockResolvedValue(scan({
      truncated: true, complete: false, incomplete_reason: "truncated", limit: 1,
    }));
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    expect(await screen.findByTestId("yara-truncated")).toHaveTextContent("first 1 hits");
  });

  it("does not call an incomplete empty scan a clean one", async () => {
    api.scanYara.mockResolvedValue(scan({
      rows: [], row_count: 0, complete: false, timed_out: true, incomplete_reason: "timed_out",
      errors: ["window at 0x1000 timed out after 30s; its 4096 bytes are unscanned"],
    }));
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    expect(await screen.findByTestId("yara-empty")).toHaveTextContent("not proof of absence");
    expect(screen.getByTestId("yara-scan-error")).toHaveTextContent("unscanned");
  });

  it("flags a dead wildcard rule instead of reporting an absence", async () => {
    api.scanYara.mockResolvedValue(scan({
      rows: [], row_count: 0,
      warnings: [{ code: "yara.pattern_over_scan_limit", severity: "warning", message: "too wide" }],
    }));
    render(<YaraPanel />);
    fireEvent.click(screen.getByTestId("yara-run"));
    expect(await screen.findByTestId("yara-scan-warning")).toHaveTextContent("too wide");
    expect(screen.getByTestId("yara-empty")).toHaveTextContent("not proof of absence");
  });

  it("mounts the fixture-verdict badge for the current rule source", () => {
    render(<YaraPanel />);
    expect(screen.getByTestId("detector-fixture-badge")).toBeInTheDocument();
    expect(screen.getByTestId("detector-fixtures-run")).toBeEnabled();
  });

  it("disables Run until a dump is open", () => {
    useDumpStore.getState().clearAll();
    render(<YaraPanel />);
    expect(screen.getByTestId("yara-no-dump")).toBeInTheDocument();
    expect(screen.getByTestId("yara-run")).toBeDisabled();
  });
});

describe("HexLegend yara entry", () => {
  it("lists yara hits under their own legend entry with the count", () => {
    useHexStore.setState({
      highlightedRegions: [{ offset: 0, length: 4, type: "pattern", label: "x", kind: "yara_hit" }],
    });
    render(<HexLegend />);
    expect(screen.getByTestId("hex-legend-yara-hit")).toHaveTextContent("YARA rule hits");
    expect(screen.getByTestId("hex-legend-yara-hit")).toHaveTextContent("(1)");
  });
});
