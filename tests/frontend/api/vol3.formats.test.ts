import { afterEach, describe, expect, it, vi } from "vitest";

import { addFormatOracle } from "@/api/oracles";
import { listFormatOracles, suggestFormatOracle } from "@/api/vol3";

function mockFetch(body: unknown) {
  const fn = vi.fn(async () => new Response(JSON.stringify(body), { status: 200 }));
  vi.stubGlobal("fetch", fn);
  return fn;
}
const lastCall = (fn: ReturnType<typeof mockFetch>) => fn.mock.calls.at(-1) as unknown as [string, RequestInit];

afterEach(() => vi.unstubAllGlobals());

describe("format oracle client", () => {
  it("lists the format kinds", async () => {
    const body = { formats: [{ kind: "luks", resource_type: "format:luks", candidate_lengths: [32], cost_us: 5,
      sample_kind: "file", unique: true }], count: 1 };
    const fn = mockFetch(body);
    expect(await listFormatOracles()).toEqual(body);
    expect(lastCall(fn)[0]).toBe("/api/oracles/formats");
  });

  it("posts the dump path to suggest", async () => {
    const body = { dump_path: "/d.msl", suggestion: null, reason: "none" };
    const fn = mockFetch(body);
    expect(await suggestFormatOracle("/d.msl")).toEqual(body);
    const [url, init] = lastCall(fn);
    expect(url).toBe("/api/oracles/formats/suggest");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ dump_path: "/d.msl" });
  });

  it("registers a format oracle, dropping a blank sample", async () => {
    const fn = mockFetch({ id: "x", filename: "format:luks", format_kind: "luks" });
    await addFormatOracle("luks", "/vault");
    expect(lastCall(fn)[0]).toBe("/api/oracles/formats/luks");
    expect(JSON.parse(lastCall(fn)[1].body as string)).toEqual({ oracle_sample_path: "/vault" });
    await addFormatOracle("luks", "");
    expect(JSON.parse(lastCall(fn)[1].body as string)).toEqual({});
  });
});
