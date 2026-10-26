import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useDumpStore } from "@/stores/dump-store";
import { useImageStore } from "@/stores/image-store";

const api = vi.hoisted(() => ({
  probeImage: vi.fn(), startProfileJob: vi.fn(), cancelImageJob: vi.fn(),
  startOpenViewJob: vi.fn(), startExtractProcessJob: vi.fn(), listImageProcesses: vi.fn(),
}));
vi.mock("@/api/image", () => api);
vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(async () => ({ file_size: 1 })),
  readableFailure: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}));
type Cbs = Record<string, (...args: unknown[]) => void>;
const ws = vi.hoisted(() => ({ calls: [] as { taskId: string | null; cbs: Cbs }[] }));
vi.mock("@/hooks/useTaskProgress", () => ({
  useTaskProgress: (taskId: string | null, cbs: Cbs) => { ws.calls.push({ taskId, cbs }); },
}));

const { ImagePanel } = await import("@/components/image/ImagePanel");
const change = (id: string, value: string) => fireEvent.change(screen.getByTestId(id), { target: { value } });

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  ws.calls.length = 0;
  useDumpStore.getState().clearAll();
  useImageStore.getState().reset();
  useImageStore.setState({ imagePath: "/img.lime", caseDir: "/cases/a" });
  api.probeImage.mockResolvedValue({
    image: "/img.lime", size: 1, physical_layer_chain: ["LimeLayer"], image_sha256: null,
    profile: { status: "missing" }, versions: { volatility3: "2.5", pakunoda: null } });
  api.listImageProcesses.mockResolvedValue({ processes: [] });
  api.startOpenViewJob.mockResolvedValue({ task_id: "t1" });
});

describe("kernel view variants", () => {
  it("opens without a profile and auto-finds paging when nothing is entered", async () => {
    render(<ImagePanel />);
    fireEvent.click(screen.getByTestId("open-noprofile"));
    await waitFor(() => expect(api.startOpenViewJob).toHaveBeenCalled());
    const args = api.startOpenViewJob.mock.calls[0][0];
    expect(args).toMatchObject({ view: "kernel", no_profile: true, case_dir: "/cases/a" });
    expect(args.paging).toBeUndefined();
    expect(await screen.findByTestId("view-progress")).toBeInTheDocument();
  });

  it("sends manual paging fields and rejects a non-hex PGD", async () => {
    render(<ImagePanel />);
    change("paging-pgd", "zz");
    fireEvent.click(screen.getByTestId("open-noprofile"));
    expect(screen.getByTestId("variants-error")).toBeInTheDocument();
    expect(api.startOpenViewJob).not.toHaveBeenCalled();
    change("paging-pgd", "0x1a2b3000");
    change("paging-arch", "aarch64");
    change("paging-vabits", "39");
    fireEvent.click(screen.getByTestId("open-noprofile"));
    await waitFor(() => expect(api.startOpenViewJob).toHaveBeenCalled());
    expect(api.startOpenViewJob.mock.calls[0][0].paging).toEqual({
      pgd_phys: 0x1a2b3000, arch: "aarch64", va_bits: 39, page_size: 4096 });
  });

  it("shows the backend error inline", async () => {
    api.startOpenViewJob.mockRejectedValue(new Error("paging_root_not_found"));
    render(<ImagePanel />);
    fireEvent.click(screen.getByTestId("open-noprofile"));
    expect(await screen.findByText(/paging_root_not_found/)).toBeInTheDocument();
  });

  it("opens with an ISF draft and optional version", async () => {
    render(<ImagePanel />);
    expect(screen.getByTestId("open-draft")).toBeDisabled();
    change("draft-name", "d1");
    change("draft-version", "v7");
    fireEvent.click(screen.getByTestId("open-draft"));
    await waitFor(() => expect(api.startOpenViewJob).toHaveBeenCalled());
    expect(api.startOpenViewJob.mock.calls[0][0]).toMatchObject({
      view: "kernel", draft: "d1", draft_version: "v7", case_dir: "/cases/a" });
  });
});
