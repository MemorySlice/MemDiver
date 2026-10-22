import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { ImportPreview, RegionCategory } from "@/api/types";

const previewImport = vi.fn();
vi.mock("@/api/client", () => ({
  previewImport: (...args: unknown[]) => previewImport(...args),
  readableFailure: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}));

const { RegionSelectStep } = await import("@/components/import/RegionSelectStep");
const { DEFAULT_REGION_CATEGORIES } = await import("@/components/import/region-categories");

function preview(overrides: Partial<ImportPreview> = {}): ImportPreview {
  return {
    format: "elf_core",
    is_msl: false,
    regions: [
      { base_addr: 0x1000, size: 4096, protection: 3, region_type: 1, category: "heap", module_path: null, captured_bytes: 4096 },
      { base_addr: 0x7f0000, size: 8192, protection: 3, region_type: 2, category: "stack", module_path: null, captured_bytes: 8192 },
      { base_addr: 0x400000, size: 2048, protection: 5, region_type: 3, category: "image_code", module_path: "/usr/bin/app", captured_bytes: 2048 },
    ],
    totals: {
      heap: { count: 1, bytes: 4096 },
      stack: { count: 1, bytes: 8192 },
      image_code: { count: 1, bytes: 2048 },
    },
    summary: { included_count: 3, included_bytes: 14336, excluded_count: 0, excluded_bytes: 0 },
    notes: [],
    ...overrides,
  };
}

/** Stateful host so toggles flow back into the component like in the wizard. */
function Host({ paths = ["/dumps/a.core"], dumpCount }: { paths?: string[]; dumpCount?: number | null }) {
  const [selected, setSelected] = useState<RegionCategory[]>([...DEFAULT_REGION_CATEGORIES]);
  const [materialize, setMaterialize] = useState(false);
  return (
    <RegionSelectStep
      paths={paths}
      dumpCount={dumpCount}
      selected={selected}
      onSelectedChange={setSelected}
      materialize={materialize}
      onMaterializeChange={setMaterialize}
    />
  );
}

afterEach(() => {
  previewImport.mockReset();
});

describe("RegionSelectStep", () => {
  it("shows a loading state, then per-category counts and bytes", async () => {
    previewImport.mockResolvedValue(preview());
    render(<Host />);

    expect(screen.getByTestId("region-preview-loading")).toBeInTheDocument();
    expect(await screen.findByTestId("region-stats-heap")).toHaveTextContent("1 region · 4.0 KiB");
    expect(screen.getByTestId("region-stats-image_code")).toHaveTextContent("2.0 KiB");
    expect(screen.getByTestId("region-stats-shared")).toHaveTextContent("none in this dump");
    expect(previewImport).toHaveBeenCalledWith("/dumps/a.core");
  });

  it("preselects heap, stack and unclassified", async () => {
    previewImport.mockResolvedValue(preview());
    render(<Host />);
    await screen.findByTestId("region-summary");

    for (const c of ["heap", "stack", "unclassified"]) {
      expect(screen.getByTestId(`region-category-${c}`)).toBeChecked();
    }
    for (const c of ["image_code", "image_data", "mapped_file", "shared", "runtime"]) {
      expect(screen.getByTestId(`region-category-${c}`)).not.toBeChecked();
    }
  });

  it("updates the included/excluded totals live as categories toggle", async () => {
    previewImport.mockResolvedValue(preview());
    render(<Host />);
    const summary = await screen.findByTestId("region-summary");
    expect(summary).toHaveTextContent("Keeping 2 regions (12.0 KiB) · excluding 1 region (2.0 KiB)");

    fireEvent.click(screen.getByTestId("region-category-stack"));
    expect(summary).toHaveTextContent("Keeping 1 region (4.0 KiB) · excluding 2 regions (10.0 KiB)");

    fireEvent.click(screen.getByTestId("region-all"));
    expect(summary).toHaveTextContent("Keeping 3 regions (14.0 KiB) · excluding 0 regions (0 B)");

    fireEvent.click(screen.getByTestId("region-defaults"));
    expect(summary).toHaveTextContent("Keeping 2 regions");
  });

  it("uses singular wording for a single region", async () => {
    previewImport.mockResolvedValue(preview({
      regions: [preview().regions[0]],
      totals: { heap: { count: 1, bytes: 4096 } },
    }));
    render(<Host />);
    const summary = await screen.findByTestId("region-summary");
    expect(summary).toHaveTextContent("Keeping 1 region (4.0 KiB) · excluding 0 regions (0 B)");
    expect(summary).not.toHaveTextContent("1 regions");
    expect(screen.getByTestId("region-table-toggle")).toHaveTextContent("Show 1 region");
    expect(screen.getByTestId("region-table-toggle")).not.toHaveTextContent("1 regions");
  });

  it("warns when no category is selected", async () => {
    previewImport.mockResolvedValue(preview());
    render(<Host />);
    await screen.findByTestId("region-summary");
    for (const c of ["heap", "stack", "unclassified"]) {
      fireEvent.click(screen.getByTestId(`region-category-${c}`));
    }
    expect(screen.getByRole("alert")).toHaveTextContent("Select at least one category.");
  });

  it("expands a per-region table with hex base, rwx and module", async () => {
    previewImport.mockResolvedValue(preview());
    render(<Host />);
    const toggle = await screen.findByTestId("region-table-toggle");
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const table = screen.getByTestId("region-table");
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(4); // header + 3
    expect(rows[1]).toHaveTextContent("0x1000");
    expect(rows[1]).toHaveTextContent("rw-");
    expect(rows[3]).toHaveTextContent("r-x");
    expect(rows[3]).toHaveTextContent("/usr/bin/app");
    expect(rows[3]).toHaveAttribute("data-included", "false");
  });

  it("offers materialize only for .msl input", async () => {
    previewImport.mockResolvedValue(preview());
    const { unmount } = render(<Host />);
    await screen.findByTestId("region-summary");
    expect(screen.queryByTestId("region-materialize")).not.toBeInTheDocument();
    unmount();

    previewImport.mockResolvedValue(preview({ is_msl: true, format: "msl" }));
    render(<Host paths={["/dumps/a.msl"]} />);
    const box = await screen.findByTestId("region-materialize");
    expect(box).not.toBeChecked();
    expect(screen.getByText(/does not keep the original's integrity hash/)).toBeInTheDocument();
    fireEvent.click(box);
    expect(box).toBeChecked();
  });

  it("always explains where static keys live", async () => {
    previewImport.mockResolvedValue(preview());
    render(<Host />);
    expect(screen.getByTestId("region-image-data-info")).toHaveTextContent(/\.data \/ \.bss/);
  });

  it("previews the first of several dumps and says the choice applies to all", async () => {
    previewImport.mockResolvedValue(preview());
    render(<Host paths={["/d/one.core", "/d/two.core"]} />);
    await screen.findByTestId("region-summary");
    expect(previewImport).toHaveBeenCalledTimes(1);
    expect(previewImport).toHaveBeenCalledWith("/d/one.core");
    expect(screen.getByTestId("region-scope-note")).toHaveTextContent(
      "Previewing one.core. The selection applies to all 2 dumps.",
    );
  });

  it("shows an error with a working retry", async () => {
    previewImport.mockRejectedValueOnce(new Error("boom")).mockResolvedValueOnce(preview());
    render(<Host />);
    const error = await screen.findByTestId("region-preview-error");
    expect(error).toHaveTextContent("boom");

    fireEvent.click(within(error).getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.getByTestId("region-summary")).toBeInTheDocument());
    expect(previewImport).toHaveBeenCalledTimes(2);
  });

  it("still offers the checklist when there is nothing to preview", () => {
    render(<Host paths={[]} dumpCount={null} />);
    expect(previewImport).not.toHaveBeenCalled();
    expect(screen.getByTestId("region-category-heap")).toBeChecked();
    expect(screen.getByTestId("region-scope-note")).toHaveTextContent(
      "The selection applies to every dump in this directory.",
    );
  });

  describe("encrypted .msl", () => {
    const locked = () => preview({ format: "msl", is_msl: true, regions: [], totals: {}, encrypted: true, decrypted: false });

    it("hides the key inputs for a plaintext .msl", async () => {
      previewImport.mockResolvedValue(preview({ format: "msl", is_msl: true }));
      render(<Host paths={["/d/a.msl"]} />);
      await screen.findByTestId("region-summary");
      expect(screen.queryByTestId("encrypted-msl-options")).not.toBeInTheDocument();
    });

    it("shows password inputs and re-previews with the key in the POST body", async () => {
      previewImport.mockResolvedValueOnce(locked()).mockResolvedValueOnce(preview({ format: "msl", is_msl: true, encrypted: true, decrypted: true }));
      render(<Host paths={["/d/e.msl"]} />);
      const pass = await screen.findByTestId("encrypted-passphrase");
      expect(pass).toHaveAttribute("type", "password");
      expect(pass).toHaveAttribute("autocomplete", "off");
      expect(screen.getByTestId("encrypted-key-hex")).toHaveAttribute("type", "password");
      expect(screen.getByTestId("encrypted-reencrypt-note")).toHaveTextContent("re-encrypted with the same key");
      expect(screen.getByTestId("encrypted-unlock")).toBeDisabled();

      fireEvent.change(pass, { target: { value: "s3cret" } });
      fireEvent.click(screen.getByTestId("encrypted-unlock"));
      await screen.findByTestId("region-stats-heap");
      expect(previewImport).toHaveBeenLastCalledWith("/d/e.msl", undefined, undefined, { passphrase: "s3cret" });
      expect(screen.getByText("Unlocked with the supplied key material.")).toBeInTheDocument();
    });

    it("warns only when the decrypted-copy opt-in is checked", async () => {
      previewImport.mockResolvedValue(locked());
      render(<Host paths={["/d/e.msl"]} />);
      const box = await screen.findByTestId("encrypted-decrypt-output");
      expect(box).not.toBeChecked();
      expect(screen.queryByTestId("encrypted-decrypt-warning")).not.toBeInTheDocument();
      fireEvent.click(box);
      expect(screen.getByTestId("encrypted-decrypt-warning")).toHaveTextContent("PLAINTEXT");
    });
  });

  describe("preview layout", () => {
    const CATEGORIES = ["heap", "stack", "unclassified", "image_data", "image_code", "mapped_file", "shared", "runtime"];
    const raw = (layout?: ImportPreview["layout"]) => preview({
      format: "raw",
      layout,
      regions: [{ base_addr: 0, size: 4096, protection: 0, region_type: 0, category: "unclassified", module_path: null, captured_bytes: 4096 }],
      totals: { unclassified: { count: 1, bytes: 4096 } },
    });

    it("layout 'none': shows the callout, disables checkboxes and presets, selects all", async () => {
      previewImport.mockResolvedValue(raw("none"));
      render(<Host paths={["/dumps/a.bin"]} />);
      const callout = await screen.findByTestId("region-no-layout-info");
      expect(callout).toHaveTextContent("This raw dump has no memory layout; categories can't be separated.");
      expect(callout).toHaveTextContent(".maps sidecar");
      for (const c of CATEGORIES) {
        const box = screen.getByTestId(`region-category-${c}`);
        expect(box).toBeDisabled();
        await waitFor(() => expect(box).toBeChecked());
      }
      expect(screen.getByTestId("region-defaults")).toBeDisabled();
      expect(screen.getByTestId("region-all")).toBeDisabled();
    });

    it.each([["maps"], [undefined]] as const)("layout %s: no callout, checkboxes enabled", async (layout) => {
      previewImport.mockResolvedValue(raw(layout));
      render(<Host paths={["/dumps/a.bin"]} />);
      await screen.findByTestId("region-summary");
      expect(screen.queryByTestId("region-no-layout-info")).not.toBeInTheDocument();
      for (const c of CATEGORIES) {
        expect(screen.getByTestId(`region-category-${c}`)).toBeEnabled();
      }
      expect(screen.getByTestId("region-defaults")).toBeEnabled();
      expect(screen.getByTestId("region-category-image_code")).not.toBeChecked();
    });
  });

  describe("runtime regions", () => {
    const runtimeRegion = {
      base_addr: 0x70000000, size: 3 * 1024 * 1024, protection: 1, region_type: 0,
      category: "runtime" as const, module_path: null, captured_bytes: 3 * 1024 * 1024,
      name: "[anon:dalvik-zygote space]",
    };
    const withRuntime = (platform: string | null, count = 2) => preview({
      regions: [...preview().regions, runtimeRegion],
      totals: { ...preview().totals, runtime: { count, bytes: 3 * 1024 * 1024 } },
      platform,
      runtime_count: count,
      runtime_bytes: 3 * 1024 * 1024,
    });

    it("shows the Android notice with count and size, runtime unchecked", async () => {
      previewImport.mockResolvedValue(withRuntime("android"));
      render(<Host />);
      const notice = await screen.findByTestId("region-runtime-notice");
      expect(notice).toHaveTextContent("Android process: 2 runtime regions (3.0 MiB)");
      expect(notice).toHaveTextContent("are excluded by default");
      expect(screen.getByTestId("region-category-runtime")).not.toBeChecked();
      expect(screen.getByTestId("region-stats-runtime")).toHaveTextContent("2 regions · 3.0 MiB");
    });

    it("uses generic singular wording on other platforms", async () => {
      previewImport.mockResolvedValue(withRuntime("linux", 1));
      render(<Host />);
      const notice = await screen.findByTestId("region-runtime-notice");
      expect(notice).toHaveTextContent("1 platform runtime region (3.0 MiB) is excluded by default.");
      expect(notice).not.toHaveTextContent("Android");
    });

    it.each([[0], [undefined]] as const)("shows no notice when runtime_count is %s", async (count) => {
      previewImport.mockResolvedValue(preview({ platform: "android", runtime_count: count, runtime_bytes: 0 }));
      render(<Host />);
      await screen.findByTestId("region-summary");
      expect(screen.queryByTestId("region-runtime-notice")).not.toBeInTheDocument();
    });

    it("shows mapping names in the region table with a dash fallback", async () => {
      previewImport.mockResolvedValue(withRuntime("android"));
      render(<Host />);
      fireEvent.click(await screen.findByTestId("region-table-toggle"));
      const table = screen.getByTestId("region-table");
      expect(within(table).getByRole("columnheader", { name: "Name" })).toBeInTheDocument();
      const names = within(table).getAllByTestId("region-table-name");
      expect(names).toHaveLength(4);
      expect(names[0]).toHaveTextContent("—");
      expect(names[3]).toHaveTextContent("[anon:dalvik-zygote space]");
      expect(within(table).getAllByRole("row")[4]).toHaveTextContent("Runtime");
    });
  });
});
