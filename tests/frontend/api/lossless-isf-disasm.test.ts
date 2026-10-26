import { afterEach, describe, expect, it, vi } from "vitest";

import { disassemble } from "@/api/disasm";
import { getIsfDraft } from "@/api/isf";

afterEach(() => vi.unstubAllGlobals());
const stub = (text: string) => vi.stubGlobal("fetch", vi.fn(async () => new Response(text, { status: 200 })));

describe("lossless decoding", () => {
  it("keeps a kernel-VA gap start exact in the disasm answer", async () => {
    stub('{"coverage":{"gaps":[{"start":18446744071562067235,"length":2,"reason":"x"}]}}');
    const r = await disassemble("/d", 1n, 4);
    expect(r.coverage.gaps[0].start).toBe("18446744071562067235");
  });
  it("keeps big integers in an isf draft answer exact", async () => {
    stub('{"sections":{"enums":{"items":{"e":{"constants":{"A":18446744071562067235}}}}}}');
    const r = await getIsfDraft({ caseDir: "/c", captureId: "x" }, "d");
    expect((r.sections as never as Record<string, { items: Record<string, { constants: Record<string, string> }> }>).enums.items.e.constants.A)
      .toBe("18446744071562067235");
  });
});
