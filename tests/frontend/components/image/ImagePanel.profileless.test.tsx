import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
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
  readableFailure: (e: unknown) => {
    const raw = e instanceof Error ? e.message : String(e);
    try { return (JSON.parse(raw) as { error: string }).error; } catch { return raw; }
  },
}));
vi.mock("@/hooks/useTaskProgress", () => ({ useTaskProgress: () => {} }));

const { ImagePanel } = await import("@/components/image/ImagePanel");

const probe = (status: string) => ({
  image: "/img.lime", size: 1, physical_layer_chain: ["LimeLayer"], image_sha256: null,
  profile: { status }, versions: {},
});

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  useDumpStore.getState().clearAll();
  useImageStore.getState().reset();
  useImageStore.setState({ imagePath: "/img.lime", kernelViewPath: "/c/views/k.mdview" });
});

describe("ImagePanel profile-less kernel view", () => {
  it("does not request the process list and explains why", async () => {
    useImageStore.getState().setViewHasProfile("/c/views/k.mdview", false);
    api.probeImage.mockResolvedValue(probe("found"));
    render(<ImagePanel />);
    expect(await screen.findByTestId("processes-need-profile")).toHaveTextContent("needs a kernel profile");
    expect(api.listImageProcesses).not.toHaveBeenCalled();
  });

  it("gates on the view, not the probe: a missing probe profile still lists a profiled view", async () => {
    useImageStore.getState().setViewHasProfile("/c/views/k.mdview", true);
    api.probeImage.mockResolvedValue(probe("missing"));
    api.listImageProcesses.mockResolvedValue({ processes: [] });
    render(<ImagePanel />);
    await waitFor(() => expect(api.listImageProcesses).toHaveBeenCalledWith("/c/views/k.mdview"));
  });

  it("turns a kernel_view_required answer into the note, not an error", async () => {
    api.probeImage.mockResolvedValue(probe("found"));
    api.listImageProcesses.mockRejectedValue(new Error(JSON.stringify({ error: "x", code: "kernel_view_required" })));
    render(<ImagePanel />);
    expect(await screen.findByTestId("processes-need-profile")).toBeInTheDocument();
    expect(screen.queryByTestId("image-error")).toBeNull();
  });

  it("lists the implicated items of a profile_build_failed open", async () => {
    api.probeImage.mockResolvedValue(probe("found"));
    api.listImageProcesses.mockResolvedValue({ processes: [] });
    api.startOpenViewJob.mockRejectedValue(new Error(JSON.stringify({
      error: "profile could not be built", code: "profile_build_failed",
      details: { implicated: [{ item: "type:cred", reason: "missing field" }, { item: "symbol:init_task" }] } })));
    render(<ImagePanel />);
    await waitFor(() => expect(api.probeImage).toHaveBeenCalled());
    const btn = await screen.findByText("Open kernel view");
    await act(async () => { btn.click(); });
    const box = await screen.findByTestId("image-error-implicated");
    expect(box).toHaveTextContent("type:cred");
    expect(box).toHaveTextContent("missing field");
    expect(box).toHaveTextContent("symbol:init_task");
    expect(screen.getByTestId("image-error")).toHaveTextContent("profile could not be built");
  });
});
