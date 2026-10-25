import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import { render, screen, waitFor } from "@testing-library/react";
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

const BASE = {
  format: "image_view", is_msl: false, layout: "native" as const, notes: [],
  summary: { included_count: 0, included_bytes: 0, excluded_count: 0, excluded_bytes: 0 },
};

const PROCESS: ImportPreview = {
  ...BASE, view_kind: "process", selection_applicable: false,
  regions: [
    { base_addr: 0x1000, size: 8192, protection: 3, region_type: 1, category: "heap", module_path: null, captured_bytes: 8192 },
  ],
  totals: { heap: { count: 1, bytes: 8192 } },
};
const PHYSICAL: ImportPreview = {
  ...BASE, view_kind: "physical", selection_applicable: false, regions: [], totals: {},
};

function Host({ onSelected }: { onSelected: (s: RegionCategory[]) => void }) {
  const [selected, setSelected] = useState<RegionCategory[]>([...DEFAULT_REGION_CATEGORIES]);
  return (
    <RegionSelectStep
      paths={["/images/v.mdview"]}
      selected={selected}
      onSelectedChange={(next) => { setSelected(next); onSelected(next); }}
      materialize={false}
      onMaterializeChange={() => {}}
    />
  );
}

afterEach(() => previewImport.mockReset());

describe("RegionSelectStep on an .mdview", () => {
  it("lists a process view's VMAs and does not claim a raw conversion", async () => {
    previewImport.mockResolvedValue(PROCESS);
    render(<Host onSelected={() => {}} />);
    // The mappings are listed by kind, but the note says the selection is NOT
    // applied to the open view (region choice happens on extraction).
    expect(await screen.findByTestId("region-no-selection-info")).toHaveTextContent(/extract the process/i);
    expect(screen.getAllByText(/1 region/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/opened in place/i)).toBeInTheDocument();
    expect(screen.queryByText(/written to the converted \.msl/i)).not.toBeInTheDocument();
  });

  it("explains that a physical view has nothing to select and pins the selection to all", async () => {
    previewImport.mockResolvedValue(PHYSICAL);
    const onSelected = vi.fn();
    render(<Host onSelected={onSelected} />);
    const note = await screen.findByTestId("region-no-selection-info");
    expect(note).toHaveTextContent(/does not apply to a physical view/i);
    expect(screen.queryByTestId("region-summary")).not.toBeInTheDocument();
    await waitFor(() => expect(onSelected).toHaveBeenCalled());
    expect(onSelected.mock.calls.at(-1)![0]).toHaveLength(8);
  });
});
