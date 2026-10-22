import { beforeEach, describe, expect, it } from "vitest";
import {
  useRegionSelectionStore,
  withSessionRegionFilter,
} from "@/stores/region-selection-store";

beforeEach(() => useRegionSelectionStore.getState().reset());

describe("region selection store", () => {
  it("starts with the default wizard selection and no filter", () => {
    const s = useRegionSelectionStore.getState();
    expect(s.wizardCategories).toEqual(["heap", "stack", "unclassified"]);
    expect(s.wizardMaterialize).toBe(false);
    expect(s.regionFilter).toBeNull();
  });

  it("leaves request bodies untouched without a filter", () => {
    const body = { dump_paths: ["/a"] };
    expect(withSessionRegionFilter(body)).toBe(body);
  });

  it("adds the session filter, but never over an explicit one", () => {
    useRegionSelectionStore.getState().setRegionFilter("heap,stack");
    expect(withSessionRegionFilter({ size: 4 })).toEqual({ size: 4, region_filter: "heap,stack" });
    expect(withSessionRegionFilter({ size: 4, region_filter: null })).toEqual({ size: 4, region_filter: null });
  });

  it("treats an empty filter as none", () => {
    useRegionSelectionStore.getState().setRegionFilter("");
    expect(useRegionSelectionStore.getState().regionFilter).toBeNull();
  });
});
