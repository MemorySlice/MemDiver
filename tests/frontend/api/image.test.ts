import { afterEach, describe, expect, it, vi } from "vitest";

import {
  listImageProcesses, probeImage, startExtractProcessJob, startOpenViewJob, startProfileJob,
} from "@/api/image";

function mockFetch(body: unknown = { task_id: "t1", status: "pending" }) {
  const fn = vi.fn(async () => new Response(JSON.stringify(body), { status: 200 }));
  vi.stubGlobal("fetch", fn);
  return fn;
}
const lastCall = (fn: ReturnType<typeof mockFetch>) => fn.mock.calls.at(-1) as unknown as [string, RequestInit];

afterEach(() => vi.unstubAllGlobals());

describe("image client", () => {
  it("probes with an encoded path and opt-in banners", async () => {
    const fn = mockFetch({});
    await probeImage("/a b/x.lime", true, "/k.json");
    const [url] = lastCall(fn);
    expect(url).toBe("/api/image/probe?image_path=%2Fa+b%2Fx.lime&banners=true&isf=%2Fk.json");
  });

  it("probes without banners by default", async () => {
    const fn = mockFetch({});
    await probeImage("/x.lime");
    expect(lastCall(fn)[0]).toBe("/api/image/probe?image_path=%2Fx.lime");
  });

  it("posts the profile job, dropping an empty isf", async () => {
    const fn = mockFetch();
    await startProfileJob("/x.lime", "");
    const [url, init] = lastCall(fn);
    expect(url).toBe("/api/image/profile");
    expect(JSON.parse(init.body as string)).toEqual({ image_path: "/x.lime", allow_pakunoda: true });
  });

  it("posts open-view with pid and drops an empty case dir", async () => {
    const fn = mockFetch();
    await startOpenViewJob({ image_path: "/x.lime", view: "process", pid: 7, case_dir: "" });
    const [url, init] = lastCall(fn);
    expect(url).toBe("/api/image/open-view");
    expect(JSON.parse(init.body as string)).toEqual({ image_path: "/x.lime", view: "process", pid: 7 });
  });

  it("lists processes and posts extract-process", async () => {
    const fn = mockFetch({ processes: [] });
    await listImageProcesses("/v.mdview", 50);
    expect(lastCall(fn)[0]).toBe("/api/image/processes?view_path=%2Fv.mdview&limit=50");
    await startExtractProcessJob("/v.mdview", "/v.msl");
    const [url, init] = lastCall(fn);
    expect(url).toBe("/api/image/extract-process");
    expect(JSON.parse(init.body as string)).toEqual({ view_path: "/v.mdview", out_path: "/v.msl" });
  });
});
