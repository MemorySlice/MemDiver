import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { stubVirtualizerLayout } from "../../helpers/virtualizer";
import type { StringsTable as Table, StringsTableRow } from "@/api/strings";
import { useHexStore } from "@/stores/hex-store";
import {
  gotoOffset, highlightParts, searchRows, viewForHex,
} from "@/components/strings/strings-table-utils";

const api = vi.hoisted(() => ({
  getStringsTable: vi.fn(), getStringsJobPayload: vi.fn(), cancelStringsJob: vi.fn(),
}));
vi.mock("@/api/strings", async (orig) => ({ ...(await orig<object>()), ...api }));

const ws = vi.hoisted(() => ({ calls: [] as { taskId: string | null; cbs: Record<string, (...a: unknown[]) => void> }[] }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (taskId: string | null, cbs: Record<string, (...a: unknown[]) => void>) => { ws.calls.push({ taskId, cbs }); },
}));

const { StringsTable } = await import("@/components/strings/StringsTable");

const row = (addr: number, value: string, iocs: string[] = []): StringsTableRow => ({
  addr, space: "msl_va", encoding: "ascii", length: value.length, byte_length: value.length,
  value, value_truncated: false, iocs, va: addr, vas_offset: addr, region: null,
});
const table = (rows: StringsTableRow[], extra: Partial<Table> = {}): Table => ({
  view: "va", space: "msl_va", rows, row_count: rows.length, limit: 50000, truncated: false,
  complete: true, coverage: { captured_bytes: 1, bytes_scanned: 1, gaps_skipped: 0 }, ...extra,
});

beforeEach(() => {
  stubVirtualizerLayout(800, 240);
  api.getStringsTable.mockReset();
  api.getStringsJobPayload.mockReset();
  api.cancelStringsJob.mockReset();
  api.cancelStringsJob.mockResolvedValue({ task_id: "t", cancelled: true });
  ws.calls.length = 0;
  useHexStore.setState({
    viewMode: "va", availableViews: ["va", "vas"], vaSpanStart: 0x1000, fileSize: 4096, vasSize: 4096,
  });
});

describe("strings-table-utils", () => {
  it("asks for the view the hex viewer shows, raw for a flat file", () => {
    expect(viewForHex("va", ["va", "vas"])).toBe("va");
    expect(viewForHex("vas", ["va", "vas"])).toBe("vas");
    expect(viewForHex("raw", ["va", "vas"])).toBe("va");
    expect(viewForHex("raw", ["raw"])).toBe("raw");
  });

  it("maps an address to a hex offset only when the views agree", () => {
    const r = row(0x1040, "x");
    expect(gotoOffset(r, "va", "va", 0x1000)).toEqual({ ok: true, offset: 0x40 });
    expect(gotoOffset(r, "vas", "vas", 0x1000)).toEqual({ ok: true, offset: 0x1040 });
    expect(gotoOffset(r, "raw", "raw", 0)).toEqual({ ok: true, offset: 0x1040 });
    expect(gotoOffset(r, "va", "raw", 0x1000)).toEqual({ ok: false, hint: "strings.table.viewMismatch" });
    expect(gotoOffset(row(0x10, "x"), "va", "va", 0x1000)).toEqual({ ok: false, hint: "strings.table.outOfView" });
  });

  it("searches case-insensitively and splits the match for highlighting", () => {
    const rows = [row(1, "Hello World"), row(2, "nothing")];
    expect(searchRows(rows, "WORLD")).toEqual([rows[0]]);
    expect(searchRows(rows, "")).toEqual(rows);
    expect(highlightParts("aXbxc", "x")).toEqual([
      { text: "a", match: false }, { text: "X", match: true },
      { text: "b", match: false }, { text: "x", match: true }, { text: "c", match: false },
    ]);
  });
});

describe("StringsTable", () => {
  it("renders rows with address, encoding, value and IOC badges", async () => {
    api.getStringsTable.mockResolvedValue(table([
      row(0x1040, "see https://a.example/x", ["urls", "unix_paths"]), row(0x1100, "plain text"),
    ]));
    render(<StringsTable dumpPath="/d.msl" />);
    const rows = await screen.findAllByTestId("strings-table-row");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("0x00001040");
    expect(screen.getAllByTestId("ioc-badge").map((b) => b.textContent)).toEqual(["URL", "path"]);
    expect(api.getStringsTable.mock.calls[0][0]).toMatchObject({ dump_path: "/d.msl", view: "va" });
  });

  it("highlights search matches and filters the rest out", async () => {
    api.getStringsTable.mockResolvedValue(table([row(1, "alpha beta"), row(2, "gamma")]));
    render(<StringsTable dumpPath="/d.msl" />);
    await screen.findAllByTestId("strings-table-row");
    fireEvent.change(screen.getByLabelText("Search strings"), { target: { value: "BET" } });
    await waitFor(() => expect(screen.getAllByTestId("strings-table-row")).toHaveLength(1));
    expect(screen.getByTestId("strings-hit")).toHaveTextContent("bet");
  });

  it("filters to rows with IOCs", async () => {
    api.getStringsTable.mockResolvedValue(table([row(1, "a", ["ipv4"]), row(2, "b")]));
    render(<StringsTable dumpPath="/d.msl" />);
    await screen.findAllByTestId("strings-table-row");
    fireEvent.click(screen.getByLabelText("Only IOCs"));
    await waitFor(() => expect(screen.getAllByTestId("strings-table-row")).toHaveLength(1));
  });

  it("clicking a row scrolls the hex view to its offset", async () => {
    const scroll = vi.fn();
    useHexStore.setState({ scrollToOffset: scroll });
    api.getStringsTable.mockResolvedValue(table([row(0x1040, "target")]));
    render(<StringsTable dumpPath="/d.msl" />);
    fireEvent.click(await screen.findByTestId("strings-table-row"));
    expect(scroll).toHaveBeenCalledWith(0x40);
  });

  it("renders and navigates a kernel-VA string by its exact address", async () => {
    const scroll = vi.fn();
    useHexStore.setState({ scrollToOffset: scroll, vaSpanStart: 18446744071578845184 });
    const kernel = { ...row(1, "kernel banner"), addr: "18446744071578845249", va: "18446744071578845249", vas_offset: 0x41 };
    api.getStringsTable.mockResolvedValue(table([kernel]));
    render(<StringsTable dumpPath="/d.msl" />);
    const el = await screen.findByTestId("strings-table-row");
    expect(el).toHaveTextContent("0xFFFFFFFF81000041");
    fireEvent.click(el);
    expect(useHexStore.getState().viewMode).toBe("vas");
    expect(scroll).toHaveBeenCalledWith(0x41);
  });

  it("explains a view mismatch instead of jumping to a wrong byte", async () => {
    const scroll = vi.fn();
    useHexStore.setState({ scrollToOffset: scroll });
    api.getStringsTable.mockResolvedValue(table([row(0x1040, "target")]));
    render(<StringsTable dumpPath="/d.msl" />);
    await screen.findByTestId("strings-table-row");
    useHexStore.setState({ viewMode: "vas" });
    // the va rows are dropped at once; the reloaded table (still va-keyed here) mismatches the viewer
    fireEvent.click(await screen.findByTestId("strings-table-row"));
    expect(scroll).not.toHaveBeenCalled();
    expect(await screen.findByText(/different view/)).toBeInTheDocument();
  });

  it("says when the result was truncated", async () => {
    api.getStringsTable.mockResolvedValue(table([row(1, "a")], { truncated: true, limit: 1 }));
    render(<StringsTable dumpPath="/d.msl" />);
    expect(await screen.findByText(/truncated at 1/)).toBeInTheDocument();
  });

  it("drops the previous dump's rows at once and ignores its late answer", async () => {
    let resolveOld: (t: Table) => void = () => undefined;
    api.getStringsTable.mockImplementationOnce(() => new Promise<Table>((r) => { resolveOld = r; }));
    const { rerender } = render(<StringsTable dumpPath="/a.msl" />);
    resolveOld(table([row(0x1040, "from-a")]));
    expect(await screen.findByText("from-a")).toBeInTheDocument();

    api.getStringsTable.mockImplementationOnce(() => new Promise<Table>((r) => { resolveOld = r; }));
    rerender(<StringsTable dumpPath="/b.msl" />);
    await waitFor(() => expect(screen.queryByText("from-a")).not.toBeInTheDocument());
    expect(screen.queryByTestId("strings-table-row")).not.toBeInTheDocument();

    // a slow answer for /b arrives after /c was requested: it must not be shown
    api.getStringsTable.mockResolvedValueOnce(table([row(0x1100, "from-c")]));
    rerender(<StringsTable dumpPath="/c.msl" />);
    expect(await screen.findByText("from-c")).toBeInTheDocument();
    await act(async () => { resolveOld(table([row(0x1200, "from-b")])); });
    expect(screen.queryByText("from-b")).not.toBeInTheDocument();
  });

  it("does not auto-submit a job for a large dump: it waits for an explicit Scan", async () => {
    useHexStore.setState({ fileSize: 200 * 1024 * 1024, vasSize: 200 * 1024 * 1024 });
    render(<StringsTable dumpPath="/big.msl" />);
    expect(await screen.findByTestId("strings-table-scan-gate")).toBeInTheDocument();
    expect(api.getStringsTable).not.toHaveBeenCalled();
  });

  it("follows the job after Scan: progress, then the payload; Cancel stops it", async () => {
    useHexStore.setState({ fileSize: 200 * 1024 * 1024, vasSize: 200 * 1024 * 1024 });
    api.getStringsTable.mockResolvedValue({ task_id: "t1", status: "pending" });
    api.getStringsJobPayload.mockResolvedValue(table([row(0x1040, "from-job")]));
    render(<StringsTable dumpPath="/big.msl" />);
    fireEvent.click(await screen.findByTestId("strings-table-scan"));
    await screen.findByTestId("strings-table-cancel");
    const cbs = () => [...ws.calls].reverse().find((c) => c.taskId === "t1")!.cbs;
    act(() => cbs().onProgress(0.5, "scanning"));
    expect(await screen.findByText(/scanning 50%/)).toBeInTheDocument();
    await act(async () => { cbs().onDone({}); });
    expect(await screen.findByText("from-job")).toBeInTheDocument();
    expect(api.getStringsJobPayload).toHaveBeenCalledWith("t1");
  });

  it("cancels a running job", async () => {
    useHexStore.setState({ fileSize: 200 * 1024 * 1024, vasSize: 200 * 1024 * 1024 });
    api.getStringsTable.mockResolvedValue({ task_id: "t2", status: "pending" });
    render(<StringsTable dumpPath="/big.msl" />);
    fireEvent.click(await screen.findByTestId("strings-table-scan"));
    fireEvent.click(await screen.findByTestId("strings-table-cancel"));
    await waitFor(() => expect(api.cancelStringsJob).toHaveBeenCalledWith("t2"));
    expect(await screen.findByTestId("strings-table-scan-gate")).toBeInTheDocument();
  });

  it("shows a failure", async () => {
    api.getStringsTable.mockRejectedValue(new Error("boom"));
    render(<StringsTable dumpPath="/d.msl" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("boom");
  });
});
