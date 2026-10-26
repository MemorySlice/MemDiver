import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { stubVirtualizerLayout } from "../../helpers/virtualizer";
import type { ProcessRow } from "@/api/image";
import { useDumpStore } from "@/stores/dump-store";
import { useImageStore } from "@/stores/image-store";

const api = vi.hoisted(() => ({
  probeImage: vi.fn(),
  startProfileJob: vi.fn(),
  cancelImageJob: vi.fn(),
  startOpenViewJob: vi.fn(),
  startExtractProcessJob: vi.fn(),
  listImageProcesses: vi.fn(),
}));
vi.mock("@/api/image", () => api);
vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(async () => ({ file_size: 123 })),
  readableFailure: (e: unknown) => {
    const raw = e instanceof Error ? e.message : String(e);
    try { return (JSON.parse(raw) as { error: string }).error; } catch { return raw; }
  },
}));

// Capture each job's callbacks so the test can play the WebSocket.
type TaskCallbacks = Record<string, (...args: unknown[]) => void>;
const ws = vi.hoisted(() => ({ calls: [] as { taskId: string | null; cbs: TaskCallbacks }[] }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (taskId: string | null, cbs: TaskCallbacks) => { ws.calls.push({ taskId, cbs }); },
}));

const { ImagePanel } = await import("@/components/image/ImagePanel");

const row = (pid: number, comm: string): ProcessRow => ({
  pid, ppid: 1, comm, uid: 0, has_mm: true, task_offset: pid * 16,
  location: { space: "kernel_va", value: pid * 16, capture_id: "c" },
});
const PROBE = {
  image: "/img.lime", size: 2 * 1024 ** 3, physical_layer_chain: ["LimeLayer"],
  image_sha256: null, profile: { status: "missing" }, versions: { volatility3: "2.5", pakunoda: null },
};

/** Fire the callbacks of the latest render that is subscribed to `taskId`. */
const task = (taskId: string) =>
  [...ws.calls].reverse().find((c) => c.taskId === taskId)!.cbs;

beforeEach(() => {
  stubVirtualizerLayout(400, 240);
  Object.values(api).forEach((m) => m.mockReset());
  ws.calls.length = 0;
  useDumpStore.getState().clearAll();
  useImageStore.getState().reset();
  useImageStore.setState({ imagePath: "/img.lime" });
  api.probeImage.mockResolvedValue(PROBE);
  api.listImageProcesses.mockResolvedValue({ processes: [row(30, "sshd"), row(2, "kthreadd"), row(1, "systemd")] });
});

// What the backend's ViewDescriptor.to_dict() sends: `profile` only when the view has one.
const PROFILED = { image: "/img.lime", image_sha256: "c", view: "kernel",
  profile: { isf: "/x.isf.json", sha256: null, origin: "explicit" } };
const PROFILE_LESS = { image: "/img.lime", image_sha256: "c", view: "kernel",
  paging: { pgd_phys: 44089344, arch: "x86_64", va_bits: 48, page_size: 4096 } };

describe("ImagePanel", () => {
  it("renders the probe card", async () => {
    render(<ImagePanel />);
    expect(await screen.findByTestId("probe-format")).toHaveTextContent("LimeLayer");
    expect(screen.getByTestId("probe-size")).toHaveTextContent("2.0 GiB");
    expect(screen.getByTestId("probe-sha")).toHaveTextContent("not hashed yet");
    expect(screen.getByTestId("probe-profile")).toHaveTextContent("No kernel profile found");
    expect(api.probeImage).toHaveBeenCalledWith("/img.lime", false, undefined);
  });

  it("keeps scanned banners when the ISF changes and the image is re-probed", async () => {
    const BANNER = "Linux version 5.14.0 (builder) #1 SMP";
    api.probeImage.mockImplementation(async (_p: string, banners: boolean) =>
      (banners ? { ...PROBE, banners: [BANNER] } : PROBE));
    render(<ImagePanel />);
    await screen.findByTestId("probe-format");
    fireEvent.click(screen.getByRole("button", { name: "Scan banners" }));
    await waitFor(() => expect(screen.getByTestId("probe-banner")).toHaveTextContent(BANNER));
    act(() => { useImageStore.setState({ isfPath: "/k.isf.json" }); });
    await waitFor(() => expect(api.probeImage).toHaveBeenLastCalledWith("/img.lime", false, "/k.isf.json"));
    expect(screen.getByTestId("probe-banner")).toHaveTextContent(BANNER);
  });

  it("shows the scanned banner again when the panel is unmounted and reopened", async () => {
    const BANNER = "Linux version 5.14.0 (builder) #1 SMP";
    api.probeImage.mockImplementation(async (_p: string, banners: boolean) =>
      (banners ? { ...PROBE, banners: [BANNER] } : PROBE));
    const first = render(<ImagePanel />);
    await screen.findByTestId("probe-format");
    fireEvent.click(screen.getByRole("button", { name: "Scan banners" }));
    await waitFor(() => expect(screen.getByTestId("probe-banner")).toHaveTextContent(BANNER));
    first.unmount();
    render(<ImagePanel />);
    expect(screen.getByTestId("probe-banner")).toHaveTextContent(BANNER);
    await waitFor(() => expect(api.probeImage).toHaveBeenCalledTimes(3));
    expect(screen.getByTestId("probe-banner")).toHaveTextContent(BANNER);
    expect(useImageStore.getState().probes["/img.lime"]?.banners).toEqual([BANNER]);
  });

  it("renders a backend CapabilityError as text with the install hint", async () => {
    api.probeImage.mockRejectedValue(new Error(JSON.stringify({ error: "volatility3 is not installed", code: "x" })));
    render(<ImagePanel />);
    const alert = await screen.findByTestId("image-error");
    expect(alert).toHaveTextContent("volatility3 is not installed");
    expect(alert).toHaveTextContent("memdiver[image]");
    expect(alert.textContent).not.toContain("{");
  });

  it("shows profile progress and the resulting ISF", async () => {
    api.startProfileJob.mockResolvedValue({ task_id: "tp", status: "pending" });
    render(<ImagePanel />);
    await screen.findByTestId("probe-format");
    fireEvent.click(screen.getByText("Extract profile with pakunoda"));
    await waitFor(() => expect(screen.getByTestId("profile-progress")).toBeInTheDocument());
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "tp")).toBe(true));
    act(() => task("tp").onProgress(0.5, "mapping", {}));
    expect(screen.getByTestId("profile-progress")).toHaveTextContent("mapping 50%");
    act(() => task("tp").onDone({ extra: { isf: "/cache/k.json", image: "/img.lime", image_sha256: "s" } }));
    expect(await screen.findByTestId("profile-done")).toHaveTextContent("/cache/k.json");
  });

  it("shows the pakunoda stage and elapsed time on an indeterminate bar", async () => {
    api.startProfileJob.mockResolvedValue({ task_id: "ts", status: "pending" });
    render(<ImagePanel />);
    await screen.findByTestId("probe-format");
    fireEvent.click(screen.getByText("Extract profile with pakunoda"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "ts")).toBe(true));
    act(() => task("ts").onProgress(0, "symbols", { extra: { pakunoda_stage: "symbols", elapsed_s: 4.26 } }));
    expect(screen.getByTestId("profile-progress-text")).toHaveTextContent("Stage: symbols · 4.3 s");
    const bar = screen.getByRole("progressbar", { name: "Extracting profile..." });
    expect(bar).toHaveAttribute("aria-busy", "true");
    expect(bar).not.toHaveAttribute("aria-valuenow");
  });

  it("cancels the profile job and shows the cancelled state", async () => {
    api.startProfileJob.mockResolvedValue({ task_id: "tc", status: "pending" });
    api.cancelImageJob.mockResolvedValue({ task_id: "tc", cancelled: true });
    render(<ImagePanel />);
    await screen.findByTestId("probe-format");
    fireEvent.click(screen.getByText("Extract profile with pakunoda"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "tc")).toBe(true));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    await waitFor(() => expect(api.cancelImageJob).toHaveBeenCalledWith("tc"));
    expect(await screen.findByTestId("profile-cancelled")).toHaveTextContent("Profile extraction cancelled");
    expect(screen.queryByTestId("image-error")).toBeNull();
    expect(screen.getByText("Extract profile with pakunoda")).toBeEnabled();
  });

  it("treats a terminal 'cancelled' error event as cancelled, not failed", async () => {
    api.startProfileJob.mockResolvedValue({ task_id: "te", status: "pending" });
    render(<ImagePanel />);
    await screen.findByTestId("probe-format");
    fireEvent.click(screen.getByText("Extract profile with pakunoda"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "te")).toBe(true));
    act(() => task("te").onError("cancelled", {}));
    expect(await screen.findByTestId("profile-cancelled")).toBeInTheDocument();
    expect(screen.queryByTestId("image-error")).toBeNull();
  });

  it("opens the kernel view in the workspace and lists processes, filter + sort", async () => {
    api.startOpenViewJob.mockResolvedValue({ task_id: "tk", status: "pending" });
    useImageStore.setState({ caseDir: "mycase" });
    render(<ImagePanel />);
    fireEvent.click(screen.getByText("Open kernel view"));
    await waitFor(() => expect(api.startOpenViewJob).toHaveBeenCalledWith(
      { image_path: "/img.lime", view: "kernel", pid: undefined, isf: undefined, case_dir: "mycase" }));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "tk")).toBe(true));
    act(() => task("tk").onDone({ extra: { view_path: "/cases/k.mdview", capture_id: "c", descriptor: PROFILED } }));

    await waitFor(() => expect(useDumpStore.getState().dumps.map((d) => d.path)).toEqual(["/cases/k.mdview"]));
    expect(useDumpStore.getState().dumps[0].format).toBe("raw");
    await waitFor(() => expect(api.listImageProcesses).toHaveBeenCalledWith("/cases/k.mdview"));

    const pids = () => screen.getAllByTestId("process-row").map((r) => within(r).getAllByText(/./)[0].textContent);
    await waitFor(() => expect(pids()).toEqual(["1", "2", "30"]));
    fireEvent.click(screen.getByTestId("sort-comm"));
    expect(pids()).toEqual(["2", "30", "1"]); // kthreadd, sshd, systemd
    fireEvent.click(screen.getByTestId("sort-pid"));
    fireEvent.change(screen.getByLabelText("Filter by pid or name"), { target: { value: "ssh" } });
    expect(pids()).toEqual(["30"]);
  });

  it("process row opens a process view and registers the descriptor", async () => {
    api.probeImage.mockResolvedValue({ ...PROBE, profile: { status: "found" } });
    useImageStore.setState({ kernelViewPath: "/cases/k.mdview" });
    api.startOpenViewJob.mockResolvedValue({ task_id: "tv", status: "pending" });
    render(<ImagePanel />);
    await screen.findAllByTestId("process-row");
    fireEvent.click(screen.getByLabelText("Open process view 30"));
    await waitFor(() => expect(api.startOpenViewJob).toHaveBeenCalledWith(
      expect.objectContaining({ view: "process", pid: 30 })));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "tv")).toBe(true));
    act(() => task("tv").onDone({ extra: { view_path: "/cases/p30.mdview", capture_id: "c", descriptor: PROFILED } }));
    await waitFor(() => expect(useDumpStore.getState().dumps[0]?.path).toBe("/cases/p30.mdview"));
    expect(useDumpStore.getState().activeDumpId).toBe(useDumpStore.getState().dumps[0].id);
  });

  it("extract chains open-view into extract-process and shows the result", async () => {
    api.probeImage.mockResolvedValue({ ...PROBE, profile: { status: "found" } });
    useImageStore.setState({ kernelViewPath: "/cases/k.mdview" });
    api.startOpenViewJob.mockResolvedValue({ task_id: "tv", status: "pending" });
    api.startExtractProcessJob.mockResolvedValue({ task_id: "tx", status: "pending" });
    render(<ImagePanel />);
    await screen.findAllByTestId("process-row");
    fireEvent.click(screen.getByLabelText("Extract to .msl 30"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "tv")).toBe(true));
    act(() => task("tv").onDone({ extra: { view_path: "/cases/p30.mdview", capture_id: "c", descriptor: PROFILED } }));
    await waitFor(() => expect(api.startExtractProcessJob).toHaveBeenCalledWith("/cases/p30.mdview", "/cases/p30.msl"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "tx")).toBe(true));
    act(() => task("tx").onProgress(0.25, null, {}));
    expect(screen.getByTestId("extract-progress")).toHaveTextContent("25%");
    act(() => task("tx").onDone({ extra: { view_path: "/cases/p30.mdview", output_path: "/cases/p30.msl", pid: 30, regions_written: 12, captured_bytes: 1 } }));
    const result = await screen.findByTestId("extract-result");
    expect(result).toHaveTextContent("Extracted 12 regions to /cases/p30.msl");
    fireEvent.click(within(result).getByText("Open"));
    await waitFor(() => expect(useDumpStore.getState().dumps.at(-1)?.format).toBe("msl"));
    expect(useDumpStore.getState().dumps.some((d) => d.path === "/cases/p30.mdview")).toBe(false);
  });

  it("shows a failed job as a readable error", async () => {
    api.startOpenViewJob.mockRejectedValue(new Error(JSON.stringify({ error: "image not found: /img.lime" })));
    render(<ImagePanel />);
    await screen.findByTestId("probe-format");
    fireEvent.click(screen.getByText("Open physical view"));
    expect(await screen.findByTestId("image-error")).toHaveTextContent("image not found: /img.lime");
  });

  it("a profile-less view (descriptor WITHOUT a profile key, as the backend sends it) lists no processes", async () => {
    api.listImageProcesses.mockClear();
    api.startOpenViewJob.mockResolvedValue({ task_id: "tn", status: "pending" });
    useImageStore.setState({ caseDir: "mycase" });
    render(<ImagePanel />);
    fireEvent.click(screen.getByText("Open kernel view"));
    await waitFor(() => expect(ws.calls.some((c) => c.taskId === "tn")).toBe(true));
    act(() => task("tn").onDone({ extra: { view_path: "/cases/n.mdview", capture_id: "c", descriptor: PROFILE_LESS } }));
    await waitFor(() => expect(useDumpStore.getState().dumps.map((d) => d.path)).toEqual(["/cases/n.mdview"]));
    expect(await screen.findByTestId("processes-need-profile")).toBeInTheDocument();
    expect(api.listImageProcesses).not.toHaveBeenCalledWith("/cases/n.mdview");
  });
});
