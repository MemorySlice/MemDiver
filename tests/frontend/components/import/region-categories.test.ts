import { describe, expect, it } from "vitest";
import {
  DEFAULT_REGION_CATEGORIES,
  REGION_CATEGORIES,
  categoriesToSpec,
  isAllCategories,
  isDefaultCategories,
  isMslPath,
  orderCategories,
  protectionString,
  selectionCounts,
  specToCategories,
} from "@/components/import/region-categories";
import { formatBytes } from "@/utils/format-bytes";

describe("region category helpers", () => {
  it("orders and de-duplicates a selection", () => {
    expect(orderCategories(["stack", "heap", "stack"])).toEqual(["heap", "stack"]);
  });

  it("maps all categories to a null spec and others to a comma list", () => {
    expect(categoriesToSpec([...REGION_CATEGORIES])).toBeNull();
    expect(categoriesToSpec(["stack", "heap"])).toBe("heap,stack");
    expect(isAllCategories([...REGION_CATEGORIES])).toBe(true);
    expect(isDefaultCategories(["unclassified", "stack", "heap"])).toBe(true);
    expect(isDefaultCategories(["heap"])).toBe(false);
  });

  it("lists runtime last and keeps it out of the defaults", () => {
    expect(REGION_CATEGORIES[REGION_CATEGORIES.length - 1]).toBe("runtime");
    expect(REGION_CATEGORIES).toHaveLength(8);
    expect(DEFAULT_REGION_CATEGORIES).not.toContain("runtime");
    expect(isDefaultCategories([...DEFAULT_REGION_CATEGORIES, "runtime"])).toBe(false);
  });

  it("treats the old seven-category selection as a filter that drops runtime", () => {
    const allButRuntime = REGION_CATEGORIES.filter((c) => c !== "runtime");
    expect(isAllCategories(allButRuntime)).toBe(false);
    expect(categoriesToSpec(allButRuntime)).toBe(
      "heap,stack,unclassified,image_data,image_code,mapped_file,shared",
    );
    expect(specToCategories("runtime,heap")).toEqual(["heap", "runtime"]);
    expect(specToCategories("all")).toContain("runtime");
  });

  it("counts runtime totals as excluded unless selected", () => {
    const totals = { heap: { count: 1, bytes: 10 }, runtime: { count: 3, bytes: 30 } };
    expect(selectionCounts(totals, [...DEFAULT_REGION_CATEGORIES]).excluded_count).toBe(3);
    expect(selectionCounts(totals, ["heap", "runtime"]).excluded_count).toBe(0);
  });

  it("parses wire specs, persisted notes, aliases and null", () => {
    expect(specToCategories(null)).toEqual([...REGION_CATEGORIES]);
    expect(specToCategories("all")).toEqual([...REGION_CATEGORIES]);
    expect(specToCategories("heap,stack")).toEqual(["heap", "stack"]);
    expect(specToCategories("regions=stack,heap;writable=1")).toEqual(["heap", "stack"]);
    expect(specToCategories("image,bogus")).toEqual(["image_data", "image_code"]);
  });

  it("splits preview totals into included and excluded", () => {
    const counts = selectionCounts(
      { heap: { count: 2, bytes: 100 }, image_code: { count: 1, bytes: 50 } },
      ["heap", "stack"],
    );
    expect(counts).toEqual({ included_count: 2, included_bytes: 100, excluded_count: 1, excluded_bytes: 50 });
  });

  it("formats protection bits and recognises .msl paths", () => {
    expect(protectionString(7)).toBe("rwx");
    expect(protectionString(1)).toBe("r--");
    expect(protectionString(0)).toBe("---");
    expect(isMslPath("/a/B.MSL")).toBe(true);
    expect(isMslPath("/a/b.core")).toBe(false);
  });
});

describe("formatBytes", () => {
  it("uses binary units with one decimal above bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(3 * 1024 ** 3)).toBe("3.0 GiB");
    expect(formatBytes(-1)).toBe("--");
  });
});
