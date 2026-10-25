import { describe, expect, it, vi } from "vitest";

import { applyAnnotations } from "@/utils/apply-hits";
import type { AnnotationEntry } from "@/utils/apply-hits";

vi.mock("@/api/client", () => ({
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

function entry(over: Partial<AnnotationEntry> = {}): AnnotationEntry {
  return {
    id: "e1",
    capture_id: "c1",
    kind: "annotation",
    label: "note",
    locations: [{ space: "msl_va", value: 0x1000 }],
    length: 8,
    payload: {},
    ...over,
  };
}

const identity = (l: { value: number }) => l.value;

describe("applyAnnotations", () => {
  it("turns an entry into a kinded region with length, label and dumpPath", () => {
    const [r] = applyAnnotations([entry()], { space: "msl_va", toOffset: identity, dumpPath: "/d" });
    expect(r).toMatchObject({
      offset: 0x1000,
      length: 8,
      kind: "annotation",
      label: "note",
      dumpPath: "/d",
    });
  });

  it("prefers payload.highlight_kind over the entry kind", () => {
    const [r] = applyAnnotations(
      [entry({ kind: "plugin_row", payload: { highlight_kind: "vol3:vad" } })],
      { space: "msl_va", toOffset: identity },
    );
    expect(r.kind).toBe("vol3:vad");
    expect(r.dumpPath).toBeUndefined();
  });

  it("filters locations by space", () => {
    const out = applyAnnotations(
      [entry({ locations: [{ space: "phys", value: 1 }, { space: "msl_va", value: 2 }] })],
      { space: "msl_va", toOffset: identity },
    );
    expect(out.map((r) => r.offset)).toEqual([2]);
  });

  it("skips locations the mapper cannot place, never inventing an offset", () => {
    const out = applyAnnotations([entry()], { space: "msl_va", toOffset: () => null });
    expect(out).toEqual([]);
  });

  it("paints one byte when the entry has no usable length", () => {
    const out = applyAnnotations([entry({ length: null })], { space: "msl_va", toOffset: identity });
    expect(out[0].length).toBe(1);
  });

  it("falls back to the kind when the entry has no label", () => {
    const out = applyAnnotations([entry({ label: "", kind: "key_hit" })], {
      space: "msl_va",
      toOffset: identity,
    });
    expect(out[0].label).toBe("key_hit");
  });
});
