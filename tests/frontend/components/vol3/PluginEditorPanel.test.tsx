import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { stubVirtualizerLayout } from "../../helpers/virtualizer";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useImageStore } from "@/stores/image-store";

const api = vi.hoisted(() => ({
  listVol3Plugins: vi.fn(), describeVol3Plugin: vi.fn(), runVol3Plugin: vi.fn(),
  annotateVol3Run: vi.fn(), cancelVol3Job: vi.fn(), putVol3Source: vi.fn(),
  listVol3Sources: vi.fn(), listVol3Fixtures: vi.fn(),
}));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));
const client = vi.hoisted(() => ({ previewImport: vi.fn(), getPageStates: vi.fn() }));
vi.mock("@/api/client", async (orig) => ({ ...(await orig<typeof import("@/api/client")>()), ...client }));
vi.mock("@/hooks/useTaskProgress", () => ({ useTaskProgress: () => undefined }));

const { Vol3Panel } = await import("@/components/vol3/Vol3Panel");
const VIEW = "/case/kernel.mdview";

beforeEach(() => {
  stubVirtualizerLayout(400, 240);
  Object.values(api).forEach((m) => m.mockReset());
  useImageStore.getState().reset();
  useImageStore.setState({ caseDir: "/case" });
  useAppStore.setState({ inputMode: "file" });
  useDumpStore.getState().clearAll();
  const id = useDumpStore.getState().addDump({ path: VIEW, name: "kernel.mdview", size: 10, format: "raw" });
  useDumpStore.getState().setActiveDump(id);
  client.previewImport.mockResolvedValue({ view_kind: "kernel" });
  api.listVol3Plugins.mockResolvedValue({ os_family: "linux", plugins: [], count: 0 });
  api.listVol3Sources.mockResolvedValue({ sources: [], count: 0 });
  api.listVol3Fixtures.mockResolvedValue({ fixtures: [], count: 0 });
});

describe("Vol3Panel editor mode", () => {
  it("runs the saved source by name and shows rows in the shared results table", async () => {
    api.putVol3Source.mockResolvedValue({ stored: { name: "mine", version: 1 },
      check: { ok: true, plugin: { name: "Mine", description: "", version: "1", requirements: [], satisfied_by_context: [] } } });
    api.runVol3Plugin.mockResolvedValue({
      plugin: "Mine", capture_id: "c", columns: [{ name: "PID", type: "int", space: null }],
      rows: [{ depth: 0, values: [42], absent: {} }], row_count: 1, rows_returned: 1, truncated: false,
      stop_reason: null, elapsed_s: 0.1, diagnostics: [], files: [], defaults_applied: {}, args: {}, table: null, run_id: null });
    render(<Vol3Panel />);
    fireEvent.click(screen.getByTestId("vol3-mode-editor"));
    fireEvent.change(screen.getByTestId("editor-name"), { target: { value: "mine" } });
    fireEvent.change(screen.getByTestId("editor-textarea"), { target: { value: "class Mine: pass" } });
    await waitFor(() => expect(screen.getByTestId("editor-run")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("editor-save"));
    await screen.findByTestId("check-ok");
    fireEvent.click(screen.getByTestId("editor-run"));
    await waitFor(() => expect(api.runVol3Plugin).toHaveBeenCalledWith(
      expect.objectContaining({ view_path: VIEW, source_name: "mine", case_dir: "/case" })));
    expect(await screen.findByTestId("run-summary")).toBeInTheDocument();
  });

  it("keeps the edited source when switching back to Run and again to Editor", () => {
    render(<Vol3Panel />);
    fireEvent.click(screen.getByTestId("vol3-mode-editor"));
    fireEvent.change(screen.getByTestId("editor-textarea"), { target: { value: "keep me" } });
    fireEvent.click(screen.getByTestId("vol3-mode-run"));
    fireEvent.click(screen.getByTestId("vol3-mode-editor"));
    expect((screen.getByTestId("editor-textarea") as HTMLTextAreaElement).value).toBe("keep me");
  });
});
