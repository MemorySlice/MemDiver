import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { KeyFindersResult, KeyHitRow } from "@/api/keyfinders";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useKeyFinderStore } from "@/stores/keyfinder-store";
import { useVerificationStore } from "@/stores/verification-store";

const api = vi.hoisted(() => ({
  listKeyFinders: vi.fn(), scanKeyFinders: vi.fn(),
  getKeyFindersJobPayload: vi.fn(), cancelKeyFindersJob: vi.fn(),
}));
vi.mock("@/api/keyfinders", async (orig) => ({ ...(await orig<typeof import("@/api/keyfinders")>()), ...api }));

const ws = vi.hoisted(() => ({ calls: [] as { taskId: string | null; cbs: Record<string, (...a: unknown[]) => void> }[] }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (taskId: string | null, cbs: Record<string, (...a: unknown[]) => void>) => { ws.calls.push({ taskId, cbs }); },
}));

const { KeyFindersPanel } = await import("@/components/keyfinders/KeyFindersPanel");

const SPAN = 0x1000;
const DUMP = "/dumps/proc.msl";
const hexState = useHexStore.getState();
const originalScroll = hexState.scrollToOffset;
const originalFetchPageStates = hexState.fetchPageStates;

const row = (over: Partial<KeyHitRow> = {}): KeyHitRow => ({
  finder: "aes_schedule", label: "AES-128 schedule", addr: SPAN + 0x40, space: "msl_va", length: 176,
  confidence: 0.97, va: SPAN + 0x40, vas_offset: 0x40,
  metadata: { key_hex: "00112233445566778899aabbccddeeff", key_bits: 128, key_offset: SPAN + 0x40 },
  heap: { chunk_va: SPAN + 0x30, chunk_size: 208, state: "allocated", role: "user_data" },
  region: { perms: "rw-" },
  ...over,
});

const result = (over: Partial<KeyFindersResult> = {}): KeyFindersResult => ({
  dump_path: DUMP, view: "va", space: "msl_va", finders: ["aes_schedule"], heap_policy: "annotate",
  heap: { policy: "annotate", status: "ok", masked_out: 0 },
  rows: [row()], row_count: 1, limit: 10000, truncated: false, complete: true,
  coverage: {}, candidates: [], ...over,
});

const FINDERS = ["aes_schedule", "rsa_der", "rsa_factor", "pem_scan", "entropy_window"].map((name) => ({
  name, description: `backend ${name}`, mode: "window", module: "m", parameters: [],
}));

async function openPanel() {
  render(<KeyFindersPanel />);
  await screen.findByTestId("keyfinders-finder-aes_schedule");
}

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  ws.calls.length = 0;
  useAppStore.setState({ inputMode: "file" });
  useDumpStore.getState().clearAll();
  const id = useDumpStore.getState().addDump({ path: DUMP, name: "proc.msl", size: 10, format: "msl" });
  useDumpStore.getState().setActiveDump(id);
  useHexStore.setState({
    viewMode: "va", vaSpanStart: SPAN, pageStatesLoaded: true, availableViews: ["raw", "vas", "va"], highlightedRegions: [],
    selection: null, scrollToOffset: vi.fn(),
  });
  useKeyFinderStore.setState({ painted: [], verifyRequestSeq: 0 });
  useVerificationStore.getState().reset();
  api.listKeyFinders.mockResolvedValue({
    finders: FINDERS, count: 5, default_finders: ["aes_schedule"], heap_policies: ["off", "annotate", "mask"],
  });
});

afterEach(() => {
  useHexStore.setState({ scrollToOffset: originalScroll, fetchPageStates: originalFetchPageStates, selection: null, highlightedRegions: [] });
});

describe("KeyFindersPanel", () => {
  it("renders the finder list with i18n labels and the default checked", async () => {
    await openPanel();
    expect(screen.getByText("AES key schedule")).toBeInTheDocument();
    expect(screen.getByTestId("keyfinders-finder-aes_schedule")).toBeChecked();
    expect(screen.getByTestId("keyfinders-finder-pem_scan")).not.toBeChecked();
  });

  it("falls back to the backend description for an unknown finder", async () => {
    api.listKeyFinders.mockResolvedValue({
      finders: [{ name: "novel", description: "from the backend", mode: "w", module: "m", parameters: [] }],
      count: 1, default_finders: [], heap_policies: [],
    });
    render(<KeyFindersPanel />);
    expect(await screen.findByText("from the backend")).toBeInTheDocument();
    expect(screen.getByText("novel")).toBeInTheDocument();
  });

  it("runs a sync scan and renders rows with heap role, perms and a truncated key", async () => {
    api.scanKeyFinders.mockResolvedValue(result());
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-heap-mask"));
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    await screen.findByTestId("keyfinders-table");
    expect(api.scanKeyFinders).toHaveBeenCalledWith(expect.objectContaining({
      dump_path: DUMP, finders: ["aes_schedule"], heap_policy: "mask", view: "va",
    }));
    expect(screen.getByTestId("keyfinders-heap")).toHaveTextContent("user data");
    expect(screen.getByTestId("keyfinders-region")).toHaveTextContent("rw-");
    expect(screen.getByTestId("keyfinders-key")).toHaveTextContent("0011223344556677…");
    expect(screen.getByTestId("keyfinders-key")).not.toHaveTextContent("ccddeeff");
    // all hits are painted as key_hit regions, rebased from VA to the view's offset
    const painted = useHexStore.getState().highlightedRegions;
    expect(painted).toHaveLength(1);
    expect(painted[0]).toMatchObject({ kind: "key_hit", offset: 0x40, length: 176, view: "va" });
  });

  it("omits the view when a packed dump is shown raw (raw is not a scannable space)", async () => {
    api.scanKeyFinders.mockResolvedValue(result({ rows: [], row_count: 0 }));
    useHexStore.setState({ viewMode: "raw" });
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    await screen.findByTestId("keyfinders-empty");
    expect(api.scanKeyFinders.mock.calls[0][0]).not.toHaveProperty("view");
  });

  it("refuses to place a hit before the address map is loaded, then repaints when it lands", async () => {
    api.scanKeyFinders.mockResolvedValue(result());
    const fetchPageStates = vi.fn();
    useHexStore.setState({ vaSpanStart: 0, pageStatesLoaded: false, fetchPageStates });
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    await screen.findByTestId("keyfinders-table");
    expect(fetchPageStates).toHaveBeenCalledTimes(1); // Run asks for the address map
    fireEvent.click(screen.getAllByTestId("keyfinders-row")[0]);
    expect(fetchPageStates).toHaveBeenCalledTimes(2); // so does a premature click
    expect(screen.getByTestId("keyfinders-note")).toHaveTextContent("still loading");
    act(() => { useHexStore.setState({ vaSpanStart: SPAN, pageStatesLoaded: true }); });
    expect(useHexStore.getState().highlightedRegions[0]).toMatchObject({ offset: 0x40 });
  });

  it("scopes the scan to the hex selection, in the scan view's coordinates", async () => {
    api.scanKeyFinders.mockResolvedValue(result({ rows: [], row_count: 0 }));
    useHexStore.setState({ selection: { anchor: 0x10, active: 0x2f } });
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-region-selection"));
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    await screen.findByTestId("keyfinders-empty");
    expect(api.scanKeyFinders).toHaveBeenCalledWith(expect.objectContaining({ offset: SPAN + 0x10, length: 0x20 }));
  });

  it("marks truncated results", async () => {
    api.scanKeyFinders.mockResolvedValue(result({ truncated: true, complete: false }));
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    expect(await screen.findByTestId("keyfinders-truncated")).toBeInTheDocument();
  });

  it("localises a scan error", async () => {
    api.scanKeyFinders.mockRejectedValue(new Error("boom"));
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    expect(await screen.findByTestId("keyfinders-error")).toHaveTextContent("The scan failed:");
  });

  it("clicking a row navigates the viewer and selects the hit bytes", async () => {
    api.scanKeyFinders.mockResolvedValue(result());
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    fireEvent.click((await screen.findAllByTestId("keyfinders-row"))[0]);
    expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x40);
    expect(useHexStore.getState().selection).toEqual({ anchor: 0x40, active: 0x40 + 176 - 1 });
  });

  it("renders and navigates a kernel-VA hit exactly (no skipped note)", async () => {
    const KVA = "18446744071578845249"; // 0xffffffff81000041, past 2^53 (lossless decimal string)
    api.scanKeyFinders.mockResolvedValue(result({
      rows: [row({ addr: KVA, va: KVA, vas_offset: 0x41, heap: null,
        metadata: { key_hex: "00", key_bits: 128, key_offset: "18446744071578845257" } })],
    }));
    useHexStore.setState({ vaSpanStart: 18446744071578845184 }); // a rounded Number: never used
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    const tr = (await screen.findAllByTestId("keyfinders-row"))[0];
    expect(tr).toHaveTextContent("0xffffffff81000041");
    expect(screen.queryByText(/skipped|not placed/i)).toBeNull();
    expect(useHexStore.getState().highlightedRegions[0]).toMatchObject({ offset: 0x41, view: "vas" });
    fireEvent.click(tr);
    expect(useHexStore.getState().viewMode).toBe("vas");
    expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x41);
    expect(useHexStore.getState().selection).toEqual({ anchor: 0x41, active: 0x41 + 176 - 1 });
    fireEvent.click(screen.getByTestId("keyfinders-verify"));
    expect(useHexStore.getState().scrollToOffset).toHaveBeenLastCalledWith(0x49); // key_offset = addr + 8
  });

  it("verify hands the key's bytes and cipher to the verification flow", async () => {
    api.scanKeyFinders.mockResolvedValue(result());
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    fireEvent.click(await screen.findByTestId("keyfinders-verify"));
    expect(useHexStore.getState().scrollToOffset).toHaveBeenCalledWith(0x40);
    expect(useHexStore.getState().selection).toEqual({ anchor: 0x40, active: 0x40 + 16 - 1 });
    expect(useVerificationStore.getState().cipher).toBe("AES-128-CBC");
    expect(useKeyFinderStore.getState().verifyRequestSeq).toBe(1);
  });

  it("follows a job: progress, then the task payload; Cancel stops it", async () => {
    api.scanKeyFinders.mockResolvedValue({ task_id: "t1", status: "pending" });
    api.getKeyFindersJobPayload.mockResolvedValue(result());
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    await screen.findByTestId("keyfinders-cancel");
    const cbs = () => [...ws.calls].reverse().find((c) => c.taskId === "t1")!.cbs;
    act(() => cbs().onProgress(0.5, "window 3"));
    expect(screen.getByTestId("keyfinders-progress")).toHaveTextContent("window 3 50%");
    await act(async () => { cbs().onDone({ extra: null }); });
    await screen.findByTestId("keyfinders-table");
    expect(api.getKeyFindersJobPayload).toHaveBeenCalledWith("t1");

    api.cancelKeyFindersJob.mockResolvedValue({ task_id: "t2", cancelled: true });
    api.scanKeyFinders.mockResolvedValue({ task_id: "t2", status: "pending" });
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    fireEvent.click(await screen.findByTestId("keyfinders-cancel"));
    await waitFor(() => expect(api.cancelKeyFindersJob).toHaveBeenCalledWith("t2"));
    expect(await screen.findByTestId("keyfinders-cancelled")).toBeInTheDocument();
  });

  it("localises the missing-payload error of a finished job", async () => {
    api.scanKeyFinders.mockResolvedValue({ task_id: "t3", status: "pending" });
    api.getKeyFindersJobPayload.mockResolvedValue(null);
    await openPanel();
    fireEvent.click(screen.getByTestId("keyfinders-run"));
    await screen.findByTestId("keyfinders-cancel");
    const cbs = [...ws.calls].reverse().find((c) => c.taskId === "t3")!.cbs;
    await act(async () => { cbs.onDone({ extra: null }); });
    expect(await screen.findByTestId("keyfinders-error"))
      .toHaveTextContent("The job finished without a result payload.");
    const { default: i18n } = await import("@/i18n");
    expect(i18n.exists("keyfinders:run.noPayload")).toBe(true);
  });
});
