import { describe, expect, it } from "vitest";

import type { Vol3QueryResult, Vol3RunResult } from "@/api/vol3";
import { planColumnHighlights, planQueryHighlights } from "@/components/vol3/vol3-highlights";
import type { ViewContext } from "@/components/vol3/vol3-navigation";

const ctx: ViewContext = {
  kind: "kernel", pid: null, mode: "va", vaSpanStart: 0x1000, vaSize: 0x100000, pageStatesLoaded: true,
};
const run = (extra: object): Vol3RunResult => ({
  plugin: "linux.pslist.PsList",
  columns: [{ name: "COMM", type: "str", space: null }, { name: "OFFSET (V)", type: "hex", space: "kernel_va", ...extra }],
  rows: [{ depth: 0, values: ["sshd", 0x2000], absent: {} }],
} as unknown as Vol3RunResult);

describe("planColumnHighlights object size", () => {
  it("paints object_size bytes and names the type in the label", () => {
    const plan = planColumnHighlights(run({ object_type: "task_struct", object_size: 10624 }), "OFFSET (V)", ctx, null,
      { labelColumn: "COMM" });
    expect(plan.regions[0]).toMatchObject({ offset: 0x1000, length: 10624, label: "sshd (task_struct)" });
  });

  it("keeps one byte without object_size or with an invalid one", () => {
    expect(planColumnHighlights(run({}), "OFFSET (V)", ctx, null).regions[0].length).toBe(1);
    expect(planColumnHighlights(run({ object_size: 0 }), "OFFSET (V)", ctx, null).regions[0].length).toBe(1);
  });
});

describe("planQueryHighlights size column", () => {
  const q = (rows: unknown[][]): Vol3QueryResult =>
    ({ columns: ["addr", "space", "size"], rows } as unknown as Vol3QueryResult);

  it("uses the size column per row, one byte when absent", () => {
    const plan = planQueryHighlights(q([[0x2000, "kernel_va", 64], [0x3000, "kernel_va", null]]), ctx, null);
    expect(plan.regions.map((r) => r.length)).toEqual([64, 1]);
  });
});
