import { afterEach, describe, expect, it, vi } from "vitest";
import type { ImportPreview } from "@/api/types";

const importDumpPath = vi.fn();
vi.mock("@/api/dump-import", () => ({
  importDumpPath: (...args: unknown[]) => importDumpPath(...args),
}));

const { applyRegionSelection } = await import("@/components/wizard/apply-region-selection");

const DEFAULTS = ["heap", "stack", "unclassified"] as const;
const ALL = ["heap", "stack", "unclassified", "image_data", "image_code", "mapped_file", "shared", "runtime"] as const;

function preview(isMsl: boolean, withImage = true): ImportPreview {
  return {
    format: isMsl ? "msl" : "elf_core",
    is_msl: isMsl,
    regions: [],
    totals: {
      heap: { count: 1, bytes: 10 },
      ...(withImage ? { image_code: { count: 1, bytes: 10 } } : {}),
    },
    summary: { included_count: 0, included_bytes: 0, excluded_count: 0, excluded_bytes: 0 },
    notes: [],
  };
}

const imported = { id: "x", path: "/imports/a-1234.msl", name: "a-1234.msl", size: 10, regionsWritten: 1 };

afterEach(() => importDumpPath.mockReset());

describe("applyRegionSelection", () => {
  it("uses the session filter for directories, never converting", async () => {
    const out = await applyRegionSelection({
      inputMode: "dataset", inputPath: "/ds", categories: [...DEFAULTS], materialize: true, preview: null,
    });
    expect(out).toEqual({ regionFilter: "heap,stack,unclassified", imported: null });
    expect(importDumpPath).not.toHaveBeenCalled();
  });

  it("filters an .msl at analysis time by default", async () => {
    const out = await applyRegionSelection({
      inputMode: "file", inputPath: "/a.msl", categories: [...DEFAULTS], materialize: false, preview: preview(true),
    });
    expect(out).toEqual({ regionFilter: "heap,stack,unclassified", imported: null });
    expect(importDumpPath).not.toHaveBeenCalled();
  });

  it("writes a filtered copy of an .msl when materialize is chosen", async () => {
    importDumpPath.mockResolvedValue(imported);
    const out = await applyRegionSelection({
      inputMode: "file", inputPath: "/a.msl", categories: [...DEFAULTS], materialize: true, preview: preview(true),
    });
    expect(importDumpPath).toHaveBeenCalledWith("/a.msl", { regions: "heap,stack,unclassified", materialize: true });
    expect(out).toEqual({ regionFilter: null, imported });
  });

  it("forwards encrypted-.msl key material and the decrypt opt-in", async () => {
    importDumpPath.mockResolvedValue(imported);
    await applyRegionSelection({
      inputMode: "file", inputPath: "/e.msl", categories: [...DEFAULTS], materialize: true,
      preview: preview(true), keyMaterial: { passphrase: "pw" }, decryptOutput: true,
    });
    expect(importDumpPath).toHaveBeenCalledWith("/e.msl", {
      regions: "heap,stack,unclassified", materialize: true,
      keyMaterial: { passphrase: "pw" }, decryptOutput: true,
    });
  });

  it("never sends key material for a non-.msl conversion", async () => {
    importDumpPath.mockResolvedValue(imported);
    await applyRegionSelection({
      inputMode: "file", inputPath: "/a.core", categories: ["heap"], materialize: true,
      preview: preview(false), keyMaterial: { passphrase: "pw" }, decryptOutput: true,
    });
    expect(importDumpPath).toHaveBeenCalledWith("/a.core", { regions: "heap" });
  });

  it("converts a raw/ELF/minidump input with the selection", async () => {
    importDumpPath.mockResolvedValue(imported);
    const out = await applyRegionSelection({
      inputMode: "file", inputPath: "/a.core", categories: ["heap"], materialize: true, preview: preview(false),
    });
    expect(importDumpPath).toHaveBeenCalledWith("/a.core", { regions: "heap" });
    expect(out.imported).toBe(imported);
  });

  it("changes nothing when every category is selected", async () => {
    const out = await applyRegionSelection({
      inputMode: "file", inputPath: "/a.core", categories: [...ALL], materialize: false, preview: preview(false),
    });
    expect(out).toEqual({ regionFilter: null, imported: null });
    expect(importDumpPath).not.toHaveBeenCalled();
  });

  it("skips conversion when the preview shows nothing would be excluded", async () => {
    const out = await applyRegionSelection({
      inputMode: "file", inputPath: "/a.bin", categories: [...DEFAULTS], materialize: false, preview: preview(false, false),
    });
    expect(out).toEqual({ regionFilter: null, imported: null });
    expect(importDumpPath).not.toHaveBeenCalled();
  });

  it("converts by extension when no preview is available", async () => {
    importDumpPath.mockResolvedValue(imported);
    await applyRegionSelection({
      inputMode: "file", inputPath: "/a.dmp", categories: [...DEFAULTS], materialize: false, preview: null,
    });
    expect(importDumpPath).toHaveBeenCalledWith("/a.dmp", { regions: "heap,stack,unclassified" });
  });

  describe("raw dump split by a memory map", () => {
    function mapsPreview(mapsPath: string | null): ImportPreview {
      return { ...preview(false), format: "raw", layout: "maps", maps_path: mapsPath };
    }

    it("converts a subset with the same maps_path the preview used", async () => {
      importDumpPath.mockResolvedValue(imported);
      await applyRegionSelection({
        inputMode: "file", inputPath: "/a.dump", categories: [...DEFAULTS], materialize: false,
        preview: mapsPreview("/maps/a.layout"),
      });
      expect(importDumpPath).toHaveBeenCalledWith("/a.dump", {
        regions: "heap,stack,unclassified", mapsPath: "/maps/a.layout",
      });
    });

    it("keeps analysing the file directly when nothing is excluded", async () => {
      const out = await applyRegionSelection({
        inputMode: "file", inputPath: "/a.dump", categories: [...ALL], materialize: false,
        preview: mapsPreview("/maps/a.layout"),
      });
      expect(out).toEqual({ regionFilter: null, imported: null });
      expect(importDumpPath).not.toHaveBeenCalled();
    });

    it("sends no maps_path for a layout-less raw preview", async () => {
      importDumpPath.mockResolvedValue(imported);
      await applyRegionSelection({
        inputMode: "file", inputPath: "/a.dump", categories: [...DEFAULTS], materialize: false,
        preview: { ...preview(false), layout: "none", maps_path: null },
      });
      expect(importDumpPath).toHaveBeenCalledWith("/a.dump", { regions: "heap,stack,unclassified" });
    });
  });

  it("never imports a memory-image view, even when the selection excludes something", async () => {
    for (const p of [{ ...preview(false), format: "image_view", view_kind: "process" as const }, null]) {
      const out = await applyRegionSelection({
        inputMode: "file", inputPath: "/cases/a/views/x.process.pid7.mdview",
        categories: [...DEFAULTS], materialize: true, preview: p,
      });
      expect(out).toEqual({ regionFilter: null, imported: null });
    }
    expect(importDumpPath).not.toHaveBeenCalled();
  });
});
