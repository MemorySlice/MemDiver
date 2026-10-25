import { describe, expect, it } from "vitest";

import type { PageStateInterval } from "@/api/types";
import { resolveOffset, type ViewContext } from "@/components/vol3/vol3-navigation";

const ctx = (over: Partial<ViewContext> = {}): ViewContext => ({
  kind: "kernel", pid: null, mode: "va", vaSpanStart: 0x1000, vaSize: 0x4000, pageStatesLoaded: true, ...over,
});
const ref = (value: bigint, space = "kernel_va", pid: number | null = null) => ({ value, space, pid });
const IV: PageStateInterval[] = [
  { va: 0x1000, length: 0x1000, state: "CAPTURED", page_count: 1, vas_offset: 0 },
  { va: 0x8000, length: 0x1000, state: "CAPTURED", page_count: 1, vas_offset: 0x1000 },
  { va: 0x9000, length: 0x1000, state: "FAILED", page_count: 1 },
];

describe("resolveOffset", () => {
  it("va view: address minus the span start", () => {
    expect(resolveOffset(ref(0x1234n), ctx(), null)).toEqual({ ok: true, offset: 0x234 });
  });

  it("refuses an address outside the view and a view whose pages have not loaded", () => {
    expect(resolveOffset(ref(0x9000n), ctx(), null)).toMatchObject({ ok: false, hint: "nav.outOfView" });
    expect(resolveOffset(ref(0x1234n), ctx({ pageStatesLoaded: false }), null))
      .toMatchObject({ hint: "nav.pageStatesPending" });
  });

  it("vas view: packed offset of the CAPTURED interval, never of a failed one", () => {
    expect(resolveOffset(ref(0x8010n), ctx({ mode: "vas" }), IV)).toEqual({ ok: true, offset: 0x1010 });
    expect(resolveOffset(ref(0x9010n), ctx({ mode: "vas" }), IV)).toMatchObject({ hint: "nav.notCaptured" });
    expect(resolveOffset(ref(0x5000n), ctx({ mode: "vas" }), IV)).toMatchObject({ hint: "nav.notCaptured" });
  });

  it("raw view has no address map", () => {
    expect(resolveOffset(ref(0x1234n), ctx({ mode: "raw" }), null)).toMatchObject({ hint: "nav.rawView" });
  });

  it("matches spaces to the view kind", () => {
    expect(resolveOffset(ref(0x1234n, "physical"), ctx(), null)).toMatchObject({ hint: "nav.spaceMismatch" });
    expect(resolveOffset(ref(0x1234n, "physical"), ctx({ kind: "physical" }), null)).toMatchObject({ ok: true });
    expect(resolveOffset(ref(1n), ctx({ kind: null }), null)).toMatchObject({ hint: "nav.viewUnknown" });
    expect(resolveOffset(ref(1n, "msl_va"), ctx(), null)).toMatchObject({ hint: "nav.unsupportedSpace" });
  });

  it("process addresses need a row pid equal to the view's pid", () => {
    const proc = (pid: number | null) => ctx({ kind: "process", pid });
    expect(resolveOffset(ref(0x1234n, "process_va", null), proc(5), null)).toMatchObject({ hint: "nav.rowNoPid" });
    expect(resolveOffset(ref(0x1234n, "process_va", 5), proc(null), null)).toMatchObject({ hint: "nav.viewPidUnknown" });
    expect(resolveOffset(ref(0x1234n, "process_va", 6), proc(5), null)).toMatchObject({ hint: "nav.pidMismatch" });
    expect(resolveOffset(ref(0x1234n, "process_va", 5), proc(5), null)).toMatchObject({ ok: true });
  });
});
