import { afterEach, describe, expect, it, vi } from "vitest";

import { parseJsonLossless } from "@/api/lossless-json";
import {
  annotateVol3Run, cancelVol3Job, getVasNavigationMap, checkVol3Source, describeVol3Plugin, isJobTicket, listVol3Fixtures,
  listVol3Plugins, listVol3Sources, putVol3Fixture, putVol3Source, runVol3Fixture, runVol3Plugin, scaffoldVol3Plugin,
} from "@/api/vol3";

function mockFetchText(body: string, status = 200) {
  const fn = vi.fn(async () => new Response(body, { status }));
  vi.stubGlobal("fetch", fn);
  return fn;
}
const lastCall = (fn: ReturnType<typeof mockFetchText>) =>
  fn.mock.calls.at(-1) as unknown as [string, RequestInit];

afterEach(() => vi.unstubAllGlobals());

describe("vol3 client", () => {
  it("lists plugins of an OS family", async () => {
    const fn = mockFetchText(JSON.stringify({ plugins: [], count: 0, os_family: "linux" }));
    await listVol3Plugins("linux");
    expect(lastCall(fn)[0]).toBe("/api/vol3/plugins?os_family=linux");
  });

  it("describes a plugin by name", async () => {
    const fn = mockFetchText("{}");
    await describeVol3Plugin("linux.pslist.PsList");
    expect(JSON.parse(lastCall(fn)[1].body as string)).toEqual({ plugin: "linux.pslist.PsList" });
  });

  it("drops empty optionals from a run and posts `async`", async () => {
    const fn = mockFetchText(JSON.stringify({ task_id: "t1", status: "pending" }));
    const out = await runVol3Plugin({
      view_path: "/v.mdview", plugin: "p", case_dir: "", args: {}, async: true, limit: undefined,
    });
    expect(JSON.parse(lastCall(fn)[1].body as string))
      .toEqual({ view_path: "/v.mdview", plugin: "p", args: {}, async: true });
    expect(isJobTicket(out)).toBe(true);
  });

  it("tells an inline result from a job ticket", async () => {
    mockFetchText(JSON.stringify({ plugin: "p", rows: [], columns: [] }));
    expect(isJobTicket(await runVol3Plugin({ view_path: "/v", plugin: "p" }))).toBe(false);
  });

  it("keeps a kernel address beyond 2^53 exact in a run result", async () => {
    mockFetchText('{"rows":[{"values":[18446612682103595008,7],"depth":0,"absent":{}}]}');
    const out = await runVol3Plugin({ view_path: "/v", plugin: "p" }) as unknown as
      { rows: { values: unknown[] }[] };
    expect(out.rows[0].values).toEqual(["18446612682103595008", 7]);
  });

  it("raises the response body for a failed run", async () => {
    mockFetchText('{"error":"volatility3 is not installed"}', 503);
    await expect(runVol3Plugin({ view_path: "/v", plugin: "p" })).rejects.toThrow(/not installed/);
  });

  it("annotates and cancels", async () => {
    const fn = mockFetchText('{"created":2}');
    await annotateVol3Run({ case_dir: "/c", table: "t", run_id: "r", column: "Offset", label_column: "" });
    expect(lastCall(fn)[0]).toBe("/api/vol3/annotate");
    expect(JSON.parse(lastCall(fn)[1].body as string))
      .toEqual({ case_dir: "/c", table: "t", run_id: "r", column: "Offset" });
    await cancelVol3Job("a b");
    expect(lastCall(fn)[0]).toBe("/api/tasks/a%20b");
    expect(lastCall(fn)[1].method).toBe("DELETE");
  });
});

describe("parseJsonLossless", () => {
  it("quotes only unsafe integers, never text inside strings", () => {
    const parsed = parseJsonLossless('{"a":12345678901234567890,"b":"x 12345678901234567890","c":1.5,"d":-3}');
    expect(parsed).toEqual({ a: "12345678901234567890", b: "x 12345678901234567890", c: 1.5, d: -3 });
  });

  it("handles escaped quotes inside strings", () => {
    expect(parseJsonLossless('{"s":"a\\"1234567890123456789"}')).toEqual({ s: 'a"1234567890123456789' });
  });

  it("scaffolds and checks with the documented bodies", async () => {
    const fn = mockFetchText("{}");
    await scaffoldVol3Plugin("demo", false);
    expect(lastCall(fn)[0]).toBe("/api/vol3/scaffold");
    expect(JSON.parse(lastCall(fn)[1].body as string)).toEqual({ name: "demo", per_process: false });
    await checkVol3Source({ source: "x", view_path: "" });
    expect(JSON.parse(lastCall(fn)[1].body as string)).toEqual({ source: "x" });
  });

  it("lists sources and PUTs one with the case dir in the body", async () => {
    const fn = mockFetchText("{}");
    await listVol3Sources("/c a");
    expect(lastCall(fn)[0]).toBe("/api/vol3/sources?case_dir=%2Fc%20a");
    await putVol3Source("/c", "p", "src", "/v.mdview");
    expect(lastCall(fn)[0]).toBe("/api/vol3/sources/p");
    expect(lastCall(fn)[1].method).toBe("PUT");
    expect(JSON.parse(lastCall(fn)[1].body as string)).toEqual({ case_dir: "/c", source: "src", view_path: "/v.mdview" });
  });

  it("stores and runs fixtures", async () => {
    const fn = mockFetchText("{}");
    await listVol3Fixtures("/c");
    expect(lastCall(fn)[0]).toBe("/api/vol3/fixtures?case_dir=%2Fc");
    await putVol3Fixture("/c", "f", { view_path: "/v", expect: [{ min_rows: 1 }], source_name: "p" });
    expect(lastCall(fn)[0]).toBe("/api/vol3/fixtures/f");
    expect(lastCall(fn)[1].method).toBe("PUT");
    await runVol3Fixture("/c", "f");
    expect(lastCall(fn)[0]).toBe("/api/vol3/fixtures/f/run");
    expect(JSON.parse(lastCall(fn)[1].body as string)).toEqual({ case_dir: "/c" });
  });

  it("runs a stored source by name without a plugin field", async () => {
    const fn = mockFetchText("{}");
    await runVol3Plugin({ view_path: "/v", source_name: "p", case_dir: "/c" });
    expect(JSON.parse(lastCall(fn)[1].body as string)).toEqual({ view_path: "/v", source_name: "p", case_dir: "/c" });
  });
});

describe("getVasNavigationMap", () => {
  // Found in the browser: a kernel view refused the default page-states request,
  // so Vol3 row clicks / column highlights in its `vas` view never resolved.
  it("asks for the vas map and keeps kernel VAs exact", async () => {
    const fn = mockFetchText(
      '{"regions":[{"base_addr":18393349275437531136,"region_size":4096,"page_size":4096,' +
      '"intervals":[{"va":18393349275437531136,"length":4096,"state":"CAPTURED","page_count":1,"vas_offset":0}]}],' +
      '"total_pages":1,"captured_pages":1,"coverage":1.0,"vas_size":4096}');
    const map = await getVasNavigationMap("/c/k.mdview");
    expect(lastCall(fn)[0]).toBe("/api/inspect/page-states?msl_path=%2Fc%2Fk.mdview&view=vas");
    expect(BigInt(map.regions[0].intervals[0].va)).toBe(18393349275437531136n);
  });

  it("throws on the legacy 200 + error body instead of returning an empty map", async () => {
    mockFetchText(JSON.stringify({ error: "view 'vas' is not available" }));
    await expect(getVasNavigationMap("/c/k.mdview")).rejects.toThrow();
  });
});
