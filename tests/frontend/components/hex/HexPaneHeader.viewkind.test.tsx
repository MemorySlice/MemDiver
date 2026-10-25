import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { clearImageViewBadges } from "@/hooks/useImageViewBadge";
import type { DumpEntry } from "@/stores/dump-store";

const api = vi.hoisted(() => ({ previewImport: vi.fn() }));
vi.mock("@/api/client", () => api);

const { HexPaneHeader } = await import("@/components/hex/HexPaneHeader");

const dump = (path: string): DumpEntry => ({
  id: "d1", path, name: path.split("/").pop()!, size: 4096, format: "raw", sameProcess: true,
});
const header = (d: DumpEntry) => (
  <HexPaneHeader dump={d} isOrigin={false} isFocused={false} widthPx={300} onFocus={() => {}} onCollapse={() => {}} />
);

beforeEach(() => { clearImageViewBadges(); api.previewImport.mockReset(); });

describe("HexPaneHeader image view kind", () => {
  it("shows the process view's pid instead of RAW", async () => {
    api.previewImport.mockResolvedValue({ view_kind: "process", view: { kind: "process", pid: 22176 } });
    render(header(dump("/c/sshd.mdview")));
    await waitFor(() => expect(screen.getByTestId("hex-pane-format-d1")).toHaveTextContent("Process 22176"));
  });

  it("shows Kernel / Physical for the other kinds", async () => {
    api.previewImport.mockResolvedValue({ view_kind: "kernel", view: null });
    render(header(dump("/c/k.mdview")));
    await waitFor(() => expect(screen.getByTestId("hex-pane-format-d1")).toHaveTextContent("Kernel"));
  });

  it("keeps the file format for non-view dumps and never probes them", () => {
    render(header(dump("/c/a.dump")));
    expect(screen.getByTestId("hex-pane-format-d1")).toHaveTextContent("raw");
    expect(api.previewImport).not.toHaveBeenCalled();
  });

  it("falls back to the file format when the preview fails", async () => {
    api.previewImport.mockRejectedValue(new Error("x"));
    render(header(dump("/c/bad.mdview")));
    await waitFor(() => expect(api.previewImport).toHaveBeenCalled());
    expect(screen.getByTestId("hex-pane-format-d1")).toHaveTextContent("raw");
  });
});
