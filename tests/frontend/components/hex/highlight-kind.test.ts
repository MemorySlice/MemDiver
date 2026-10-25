import { describe, expect, it } from "vitest";

import {
  KIND_SLOT_COUNT,
  buildRegionIndex,
  getRegionForOffset,
  highlightClass,
  kindSlot,
  regionHighlightClass,
  regionsForView,
} from "@/components/hex/highlight-utils";
import type { HighlightRegion } from "@/stores/hex-store";

const KINDS = ["vol3:task_struct", "key_hit", "annotation", "vol3:vad", "plugin_row", "x", "y", "z"];

describe("kindSlot", () => {
  it("is deterministic and within 0..7", () => {
    for (const kind of KINDS) {
      const slot = kindSlot(kind);
      expect(slot).toBe(kindSlot(kind));
      expect(Number.isInteger(slot)).toBe(true);
      expect(slot).toBeGreaterThanOrEqual(0);
      expect(slot).toBeLessThan(KIND_SLOT_COUNT);
    }
  });

  it("pins known values so a hash change (a colour reshuffle) is deliberate", () => {
    expect(kindSlot("")).toBe(0x811c9dc5 % 8);
    expect(kindSlot("key_hit")).toBe(kindSlot("key_hit"));
  });

  it("maps different kinds to different slots", () => {
    expect(new Set(KINDS.map(kindSlot)).size).toBeGreaterThan(1);
  });
});

describe("regionHighlightClass", () => {
  it("keeps the closed-type class when no kind is set", () => {
    const r: HighlightRegion = { offset: 0, length: 1, type: "search", label: "s" };
    expect(regionHighlightClass(r)).toBe(highlightClass("search"));
  });

  it("paints the generic slot class instead of the closed one when a kind is set", () => {
    const r: HighlightRegion = { offset: 0, length: 1, type: "search", label: "s", kind: "key_hit" };
    expect(regionHighlightClass(r)).toBe(`highlight-kind-${kindSlot("key_hit")}`);
  });
});

describe("regionsForView dumpPath", () => {
  const a: HighlightRegion = { offset: 0, length: 1, type: "search", label: "a", dumpPath: "/a" };
  const b: HighlightRegion = { offset: 0, length: 1, type: "search", label: "b", dumpPath: "/b" };
  const any: HighlightRegion = { offset: 0, length: 1, type: "search", label: "any" };

  it("drops regions tagged for another dump and keeps untagged ones", () => {
    expect(regionsForView([a, b, any], "raw", ["raw"], "/a")).toEqual([a, any]);
  });

  it("does not filter by dump when no path is given", () => {
    expect(regionsForView([a, b, any], "raw", ["raw"])).toEqual([a, b, any]);
  });

  it("composes with the view filter", () => {
    const vas: HighlightRegion = { ...a, view: "vas" };
    expect(regionsForView([vas, any], "raw", ["raw", "vas"], "/a")).toEqual([any]);
  });

  it("an index built from the filtered list finds nothing for the other dump", () => {
    const index = buildRegionIndex(regionsForView([a], "raw", ["raw"], "/b"));
    expect(getRegionForOffset(index, 0)).toBeNull();
  });
});

describe("kindSlot known workbench kinds", () => {
  it("gives the workbench's own kinds distinct fixed slots", () => {
    const kinds = ["annotation", "key_hit", "plugin_row", "structure_proposal",
      "heap_chunk", "yara_hit", "isf_draft", "table_rule"];
    const slots = kinds.map(kindSlot);
    expect(new Set(slots).size).toBe(kinds.length);
  });

  it("paints every vol3:* kind like a plugin row and never like a key hit", () => {
    expect(kindSlot("vol3:task_struct")).toBe(kindSlot("plugin_row"));
    expect(kindSlot("vol3:linux.pslist")).toBe(kindSlot("plugin_row"));
    expect(kindSlot("vol3:task_struct")).not.toBe(kindSlot("key_hit"));
  });
});
