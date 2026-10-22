import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { ImportPreview, RegionCategory } from "@/api/types";

const previewImport = vi.fn();
vi.mock("@/api/client", () => ({
  previewImport: (...args: unknown[]) => previewImport(...args),
  readableFailure: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}));
// The real picker browses `/api/path/browse`; a stub that "picks" a fixed file.
vi.mock("@/components/wizard/FileBrowser", () => ({
  FileBrowser: ({ onSelect, allFiles }: { onSelect: (p: string) => void; allFiles?: boolean }) => (
    <button type="button" data-testid="stub-file-browser" data-all-files={String(allFiles)}
      onClick={() => onSelect("/maps/picked.maps")}>
      pick
    </button>
  ),
}));

const { RegionSelectStep } = await import("@/components/import/RegionSelectStep");
const { DEFAULT_REGION_CATEGORIES } = await import("@/components/import/region-categories");

const RAW_NONE: ImportPreview = {
  format: "raw", is_msl: false, layout: "none", maps_path: null,
  regions: [{ base_addr: 0, size: 64, protection: 0, region_type: 0, category: "unclassified", module_path: null, captured_bytes: 64 }],
  totals: { unclassified: { count: 1, bytes: 64 } },
  summary: { included_count: 1, included_bytes: 64, excluded_count: 0, excluded_bytes: 0 },
  notes: [],
};

function rawMaps(mapsPath: string): ImportPreview {
  return {
    ...RAW_NONE, layout: "maps", maps_path: mapsPath,
    regions: [
      { base_addr: 0x1000, size: 32, protection: 3, region_type: 1, category: "heap", module_path: null, captured_bytes: 32 },
      { base_addr: 0x2000, size: 32, protection: 5, region_type: 3, category: "image_code", module_path: "/bin/x", captured_bytes: 32 },
    ],
    totals: { heap: { count: 1, bytes: 32 }, image_code: { count: 1, bytes: 32 } },
  };
}

function Host({ allowMapsFile = true, onMaps }: { allowMapsFile?: boolean; onMaps?: (p: string | null) => void }) {
  const [selected, setSelected] = useState<RegionCategory[]>([...DEFAULT_REGION_CATEGORIES]);
  const [mapsPath, setMapsPath] = useState<string | null>(null);
  return (
    <RegionSelectStep
      paths={["/dumps/a.dump"]}
      selected={selected}
      onSelectedChange={setSelected}
      materialize={false}
      onMaterializeChange={() => {}}
      allowMapsFile={allowMapsFile}
      mapsPath={mapsPath}
      onMapsPathChange={(p) => { setMapsPath(p); onMaps?.(p); }}
    />
  );
}

afterEach(() => previewImport.mockReset());

describe("RegionSelectStep memory-map picker", () => {
  it("offers a .maps input when the raw dump has no layout", async () => {
    previewImport.mockResolvedValue(RAW_NONE);
    render(<Host />);
    expect(await screen.findByTestId("region-maps-input")).toBeInTheDocument();
    expect(screen.getByLabelText("Memory map (.maps) file")).toBeInTheDocument();
    expect(screen.getByTestId("region-maps-apply")).toBeDisabled();
  });

  it("is not offered when the caller does not allow it (directory input)", async () => {
    previewImport.mockResolvedValue(RAW_NONE);
    render(<Host allowMapsFile={false} />);
    await screen.findByTestId("region-no-layout-info");
    expect(screen.queryByTestId("region-maps-form")).not.toBeInTheDocument();
  });

  it("is not offered for native layouts", async () => {
    previewImport.mockResolvedValue({ ...rawMaps("x"), format: "elf_core", layout: "native", maps_path: null });
    render(<Host />);
    await screen.findByTestId("region-summary");
    expect(screen.queryByTestId("region-maps-form")).not.toBeInTheDocument();
    expect(screen.queryByTestId("region-maps-active")).not.toBeInTheDocument();
  });

  it("Apply re-runs the preview with the typed map and enables the categories", async () => {
    previewImport.mockResolvedValueOnce(RAW_NONE).mockResolvedValueOnce(rawMaps("/maps/other.maps"));
    const onMaps = vi.fn();
    render(<Host onMaps={onMaps} />);
    fireEvent.change(await screen.findByTestId("region-maps-input"), { target: { value: " /maps/other.maps " } });
    fireEvent.click(screen.getByTestId("region-maps-apply"));

    await waitFor(() =>
      expect(previewImport).toHaveBeenLastCalledWith("/dumps/a.dump", undefined, undefined, undefined, { mapsPath: "/maps/other.maps" }));
    expect(onMaps).toHaveBeenCalledWith("/maps/other.maps");
    expect(await screen.findByTestId("region-maps-active")).toHaveTextContent("other.maps (selected)");
    expect(screen.queryByTestId("region-no-layout-info")).not.toBeInTheDocument();
    expect(screen.getByTestId("region-all")).toBeEnabled();
    // The "all" pin of the layout-less preview gives way to the defaults; the
    // switch lands in an effect after the new preview renders, so wait for it.
    await waitFor(() => {
      expect(screen.getByTestId("region-category-heap")).toBeChecked();
      expect(screen.getByTestId("region-category-image_code")).not.toBeChecked();
    });
  });

  it("Browse fills the input from the file browser (all files listed)", async () => {
    previewImport.mockResolvedValue(RAW_NONE);
    render(<Host />);
    fireEvent.click(await screen.findByTestId("region-maps-browse"));
    const stub = screen.getByTestId("stub-file-browser");
    expect(stub).toHaveAttribute("data-all-files", "true");
    fireEvent.click(stub);
    expect(screen.getByTestId("region-maps-input")).toHaveValue("/maps/picked.maps");
    expect(screen.queryByTestId("stub-file-browser")).not.toBeInTheDocument();
  });

  it("names an auto-detected sidecar and lets the user change it", async () => {
    previewImport.mockResolvedValueOnce(rawMaps("/dumps/a.maps")).mockResolvedValueOnce(rawMaps("/maps/b.maps"));
    render(<Host />);
    expect(await screen.findByTestId("region-maps-active")).toHaveTextContent("a.maps (auto-detected)");

    fireEvent.click(screen.getByTestId("region-maps-change"));
    const input = screen.getByTestId("region-maps-input");
    expect(input).toHaveValue("/dumps/a.maps");
    fireEvent.click(screen.getByTestId("region-maps-cancel"));
    expect(screen.getByTestId("region-maps-active")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("region-maps-change"));
    fireEvent.change(screen.getByTestId("region-maps-input"), { target: { value: "/maps/b.maps" } });
    fireEvent.keyDown(screen.getByTestId("region-maps-input"), { key: "Enter" });
    expect(await screen.findByText(/b\.maps \(selected\)/)).toBeInTheDocument();
    expect(previewImport).toHaveBeenCalledTimes(2);
  });

  it("keeps the picker (prefilled) when a chosen map makes the preview fail", async () => {
    previewImport.mockResolvedValueOnce(RAW_NONE).mockRejectedValueOnce(new Error("Maps file not found: /nope.maps"));
    render(<Host />);
    fireEvent.change(await screen.findByTestId("region-maps-input"), { target: { value: "/nope.maps" } });
    fireEvent.click(screen.getByTestId("region-maps-apply"));
    expect(await screen.findByTestId("region-preview-error")).toHaveTextContent("Maps file not found");
    expect(screen.getByTestId("region-maps-input")).toHaveValue("/nope.maps");
  });

  it("surfaces a fallback warning note when the map is unusable", async () => {
    const fallback = { ...RAW_NONE, notes: ["maps file bad.maps unusable (no regions); falling back to a flat dump"] };
    previewImport.mockResolvedValueOnce(RAW_NONE).mockResolvedValueOnce(fallback);
    render(<Host />);
    fireEvent.change(await screen.findByTestId("region-maps-input"), { target: { value: "/bad.maps" } });
    fireEvent.click(screen.getByTestId("region-maps-apply"));
    expect(await screen.findByText(/falling back to a flat dump/)).toBeInTheDocument();
    expect(screen.getByTestId("region-maps-input")).toHaveValue("/bad.maps");
  });
});
