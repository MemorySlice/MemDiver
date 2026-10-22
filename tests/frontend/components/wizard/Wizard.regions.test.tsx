import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { ImportPreview, PathInfo } from "@/api/types";

const getPathInfo = vi.fn();
const previewImport = vi.fn();
const importDumpPath = vi.fn();
vi.mock("@/api/client", () => ({
  getPathInfo: (...a: unknown[]) => getPathInfo(...a),
  previewImport: (...a: unknown[]) => previewImport(...a),
  listDatasetRuns: vi.fn(() => Promise.resolve({ runs: [], total: 0, offset: 0, limit: 1 })),
  readableFailure: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}));
vi.mock("@/api/algorithms", () => ({
  getAlgorithmAvailability: vi.fn(() => new Promise(() => {})),
}));
vi.mock("@/api/dump-import", () => ({
  importDumpPath: (...a: unknown[]) => importDumpPath(...a),
}));

const { Wizard } = await import("@/components/wizard/Wizard");
const { ThemeProvider } = await import("@/providers/ThemeProvider");
const { useAppStore } = await import("@/stores/app-store");
const { useRegionSelectionStore } = await import("@/stores/region-selection-store");

function fileInfo(ext: string): PathInfo {
  return {
    exists: true, is_file: true, is_directory: false, file_size: 4096, extension: ext,
    has_keylog: false, dump_count: 1, detected_mode: "single_file",
  };
}

function preview(isMsl: boolean): ImportPreview {
  return {
    format: isMsl ? "msl" : "elf_core",
    is_msl: isMsl,
    regions: [],
    totals: { heap: { count: 1, bytes: 4096 }, stack: { count: 1, bytes: 4096 }, image_code: { count: 2, bytes: 8192 } },
    summary: { included_count: 4, included_bytes: 16384, excluded_count: 0, excluded_bytes: 0 },
    notes: [],
  };
}

async function reachRegions(path: string, ext: string, isMsl: boolean) {
  getPathInfo.mockResolvedValue(fileInfo(ext));
  previewImport.mockResolvedValue(preview(isMsl));
  render(<ThemeProvider><Wizard /></ThemeProvider>);
  fireEvent.change(screen.getByPlaceholderText(/path/i), { target: { value: path } });
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await screen.findByTestId("region-select-step");
  await screen.findByTestId("region-summary");
}

beforeEach(() => {
  vi.clearAllMocks();
  act(() => {
    useAppStore.getState().resetWizard();
    useAppStore.getState().setAppView("wizard");
  });
});

describe("Wizard Regions step", () => {
  it("follows Select Data, with the defaults checked", async () => {
    await reachRegions("/d/a.core", ".core", false);
    expect(screen.getByText("Regions")).toBeInTheDocument();
    expect(screen.getByTestId("region-category-heap")).toBeChecked();
    expect(screen.getByTestId("region-category-stack")).toBeChecked();
    expect(screen.getByTestId("region-category-unclassified")).toBeChecked();
    expect(screen.getByTestId("region-category-image_code")).not.toBeChecked();
    expect(screen.queryByTestId("region-materialize")).not.toBeInTheDocument();
  });

  it("keeps the selection in the store and blocks Next when empty", async () => {
    await reachRegions("/d/a.core", ".core", false);
    fireEvent.click(screen.getByTestId("region-category-stack"));
    expect(useRegionSelectionStore.getState().wizardCategories).toEqual(["heap", "unclassified"]);

    fireEvent.click(screen.getByTestId("region-category-heap"));
    fireEvent.click(screen.getByTestId("region-category-unclassified"));
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  it("sets the session filter for an .msl without rewriting it", async () => {
    await reachRegions("/d/a.msl", ".msl", true);
    expect(screen.getByTestId("region-materialize")).not.toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(await screen.findByRole("button", { name: "Start Analysis" }));

    await waitFor(() => expect(useAppStore.getState().appView).toBe("workspace"));
    expect(useRegionSelectionStore.getState().regionFilter).toBe("heap,stack,unclassified");
    expect(importDumpPath).not.toHaveBeenCalled();
    expect(useAppStore.getState().inputPath).toBe("/d/a.msl");
  });

  it("imports a filtered copy when materialize is chosen for an .msl", async () => {
    importDumpPath.mockResolvedValue({ id: "n", path: "/imports/a-1.msl", name: "a-1.msl", size: 1, regionsWritten: 2 });
    await reachRegions("/d/a.msl", ".msl", true);
    fireEvent.click(screen.getByTestId("region-materialize"));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(await screen.findByRole("button", { name: "Start Analysis" }));

    await waitFor(() => expect(useAppStore.getState().appView).toBe("workspace"));
    expect(importDumpPath).toHaveBeenCalledWith("/d/a.msl", { regions: "heap,stack,unclassified", materialize: true });
    expect(useAppStore.getState().inputPath).toBe("/imports/a-1.msl");
    expect(useRegionSelectionStore.getState().regionFilter).toBeNull();
  });

  it("converts a non-.msl input with the selection and reports failures in place", async () => {
    importDumpPath.mockRejectedValue(new Error("disk full"));
    await reachRegions("/d/a.core", ".core", false);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(await screen.findByRole("button", { name: "Start Analysis" }));

    expect(await screen.findByText(/Could not apply the region selection: disk full/)).toBeInTheDocument();
    expect(importDumpPath).toHaveBeenCalledWith("/d/a.core", { regions: "heap,stack,unclassified" });
    expect(useAppStore.getState().appView).toBe("wizard");
  });
});
