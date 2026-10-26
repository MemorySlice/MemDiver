import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { ImportPreview } from "@/api/types";
import { invalidateImageViewFacts } from "@/hooks/useImageViewFacts";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useImageStore } from "@/stores/image-store";

const api = vi.hoisted(() => ({
  probeImage: vi.fn(), startProfileJob: vi.fn(), cancelImageJob: vi.fn(),
  startOpenViewJob: vi.fn(), startExtractProcessJob: vi.fn(), listImageProcesses: vi.fn(),
}));
const client = vi.hoisted(() => ({ previewImport: vi.fn() }));
vi.mock("@/api/image", () => api);
vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(async () => ({ file_size: 1 })),
  previewImport: client.previewImport,
  readableFailure: (e: unknown) => {
    const raw = e instanceof Error ? e.message : String(e);
    try { return (JSON.parse(raw) as { error: string }).error; } catch { return raw; }
  },
}));
vi.mock("@/hooks/useTaskProgress", () => ({ useTaskProgress: () => {} }));

const { ImagePanel } = await import("@/components/image/ImagePanel");

const VIEW = "/c/views/opened-elsewhere.mdview";
const SHA = "ab".repeat(32);

/** The exact shape `app/image_preview.py::view_block` sends inside `POST /api/dumps/preview`. */
const preview = (kind: "physical" | "kernel" | "process", withProfile: boolean): ImportPreview => ({
  format: "image_view", is_msl: false, regions: [], totals: {}, notes: [],
  summary: { included_count: 0, excluded_count: 0, included_bytes: 0, excluded_bytes: 0 },
  view_kind: kind, selection_applicable: false,
  view: {
    kind, pid: kind === "process" ? 7 : null, capture_id: SHA, view_path: VIEW,
    has_profile: withProfile,
    profile: withProfile ? { origin: "explicit", sha256: null, isf_name: "p.json" } : null,
    paging: null, image_path: "/c/img.lime", image_sha256: SHA,
  },
} as unknown as ImportPreview);

/** A `.mdview` added the way the wizard / file browser / session restore add it, not via the panel. */
const addMdviewDump = () => {
  useAppStore.setState({ inputMode: "file", inputPath: VIEW });
  useDumpStore.getState().addDump({ path: VIEW, name: "v.mdview", size: 1, format: "raw" });
};

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  client.previewImport.mockReset();
  invalidateImageViewFacts();
  useDumpStore.getState().clearAll();
  useImageStore.getState().reset();
  api.probeImage.mockResolvedValue({ image: "/c/img.lime", size: 1, physical_layer_chain: [],
    image_sha256: null, profile: { status: "found" }, versions: {} });
  api.listImageProcesses.mockResolvedValue({ processes: [] });
});

describe("ImagePanel process list gated by the view facts", () => {
  it("a profile-less view opened elsewhere: no request, the profile note", async () => {
    client.previewImport.mockResolvedValue(preview("kernel", false));
    addMdviewDump();
    render(<ImagePanel />);
    expect(await screen.findByTestId("processes-need-profile")).toBeInTheDocument();
    expect(client.previewImport).toHaveBeenCalledWith(VIEW);
    expect(api.listImageProcesses).not.toHaveBeenCalled();
  });

  it("a physical view: no request, the kernel-view note", async () => {
    client.previewImport.mockResolvedValue(preview("physical", false));
    addMdviewDump();
    render(<ImagePanel />);
    expect(await screen.findByTestId("processes-need-kernel-view")).toBeInTheDocument();
    expect(api.listImageProcesses).not.toHaveBeenCalled();
  });

  it("a profiled kernel view lists processes", async () => {
    client.previewImport.mockResolvedValue(preview("kernel", true));
    addMdviewDump();
    render(<ImagePanel />);
    await waitFor(() => expect(api.listImageProcesses).toHaveBeenCalledWith(VIEW));
  });

  it("a profiled process view lists processes", async () => {
    client.previewImport.mockResolvedValue(preview("process", true));
    addMdviewDump();
    render(<ImagePanel />);
    await waitFor(() => expect(api.listImageProcesses).toHaveBeenCalledWith(VIEW));
  });

  it("while the facts load nothing is requested and a quiet status shows", async () => {
    let settle!: (p: ImportPreview) => void;
    client.previewImport.mockReturnValue(new Promise<ImportPreview>((r) => { settle = r; }));
    addMdviewDump();
    render(<ImagePanel />);
    await waitFor(() => expect(client.previewImport).toHaveBeenCalled());
    expect(screen.getByText("Listing processes...")).toBeInTheDocument();
    expect(api.listImageProcesses).not.toHaveBeenCalled();
    await act(async () => { settle(preview("kernel", true)); });
    await waitFor(() => expect(api.listImageProcesses).toHaveBeenCalledTimes(1));
  });

  it("a failed facts request falls back to asking, and kernel_view_required becomes the note", async () => {
    client.previewImport.mockRejectedValue(new Error("offline"));
    api.listImageProcesses.mockRejectedValue(
      new Error(JSON.stringify({ error: "x", code: "kernel_view_required" })));
    addMdviewDump();
    render(<ImagePanel />);
    await waitFor(() => expect(api.listImageProcesses).toHaveBeenCalledWith(VIEW));
    expect(await screen.findByTestId("processes-need-profile")).toBeInTheDocument();
    expect(screen.queryByTestId("image-error")).toBeNull();
  });

  it("the panel-primed flag is a fast path that skips the wait", async () => {
    client.previewImport.mockReturnValue(new Promise(() => {}));
    useImageStore.setState({ kernelViewPath: VIEW });
    useImageStore.getState().setViewHasProfile(VIEW, true);
    render(<ImagePanel />);
    await waitFor(() => expect(api.listImageProcesses).toHaveBeenCalledWith(VIEW));
  });
});
