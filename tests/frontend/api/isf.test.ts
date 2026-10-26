import { afterEach, describe, expect, it, vi } from "vitest";

import { listIsfTries } from "@/api/annotations";
import { disassemble } from "@/api/disasm";
import {
  createIsfDraft, diffIsfDraft, getIsfDraft, getIsfJobPayload, getIsfDraftVersions, listIsfDrafts, retractIsfEntry,
  setIsfDraft, startIsfProbeJob, startIsfTryJob, validateIsfDraft,
} from "@/api/isf";

function mockFetch(body: unknown = {}) {
  const fn = vi.fn(async () => new Response(JSON.stringify(body), { status: 200 }));
  vi.stubGlobal("fetch", fn);
  return fn;
}
const last = (fn: ReturnType<typeof mockFetch>) => fn.mock.calls.at(-1) as unknown as [string, RequestInit];
const bodyOf = (fn: ReturnType<typeof mockFetch>) => JSON.parse(last(fn)[1].body as string);
const REF = { caseDir: "/cases/a b", captureId: "ab".repeat(32) };

afterEach(() => vi.unstubAllGlobals());

describe("isf client", () => {
  it("lists drafts with an encoded case dir and the capture id", async () => {
    const fn = mockFetch({ drafts: [], count: 0, capture_id: REF.captureId });
    await listIsfDrafts(REF);
    expect(last(fn)[0]).toBe(`/api/isf/drafts?case_dir=%2Fcases%2Fa+b&capture_id=${REF.captureId}`);
  });

  it("creates a draft as human with name and arch", async () => {
    const fn = mockFetch({ draft: "d" });
    await createIsfDraft(REF, "d", "x86_64");
    expect(last(fn)[0]).toBe("/api/isf/drafts");
    expect(bodyOf(fn)).toEqual({ case_dir: REF.caseDir, capture_id: REF.captureId, name: "d", arch: "x86_64", author: "human" });
  });

  it("reads a section with origins, a limit and a JSON `only`", async () => {
    const fn = mockFetch({});
    await getIsfDraft(REF, "d", { only: { symbols: ["init_task", "jiffies"] }, includeOrigins: true, limit: 400 });
    const url = new URL(last(fn)[0], "http://x");
    expect(url.pathname).toBe("/api/isf/drafts/d");
    expect(JSON.parse(url.searchParams.get("only")!)).toEqual({ symbols: ["init_task", "jiffies"] });
    expect(url.searchParams.get("include_origins")).toBe("true");
    expect(url.searchParams.get("limit")).toBe("400");
  });

  it("reads versions with a limit", async () => {
    const fn = mockFetch({});
    await getIsfDraftVersions(REF, "d", 50);
    expect(last(fn)[0]).toContain("/api/isf/drafts/d/versions?");
    expect(last(fn)[0]).toContain("limit=50");
  });

  it("sends a set op with its provenance flattened into the request", async () => {
    const fn = mockFetch({});
    await setIsfDraft(REF, "d", {
      op: "field", args: { struct: "task_struct", field: "pid", offset: 8, type: { kind: "base", name: "int" } },
      provenance: { source: "manual", tier: "exact", evidence: ["hex selection 0x10"], author: "human" },
    });
    expect(last(fn)[0]).toBe("/api/isf/drafts/d/set");
    expect(bodyOf(fn)).toMatchObject({
      op: "field", source: "manual", tier: "exact", evidence: ["hex selection 0x10"], author: "human",
      args: { struct: "task_struct", offset: 8 },
    });
  });

  it("retracts, diffs and validates", async () => {
    const fn = mockFetch({});
    await retractIsfEntry(REF, "d", "e1", "wrong");
    expect(bodyOf(fn)).toMatchObject({ entry_id: "e1", reason: "wrong", author: "human" });
    await diffIsfDraft(REF, "d", { version: "e0" });
    expect(bodyOf(fn)).toMatchObject({ against_version: "e0" });
    expect(bodyOf(fn)).not.toHaveProperty("against_isf");
    await diffIsfDraft(REF, "d", { isf: "/x.json" }, 10);
    expect(bodyOf(fn)).toMatchObject({ against_isf: "/x.json", limit: 10 });
    await validateIsfDraft(REF, "d");
    expect(last(fn)[0]).toBe("/api/isf/drafts/d/validate");
  });

  it("submits try and probe as async jobs, omitting empty optionals", async () => {
    const fn = mockFetch({ task_id: "t", status: "pending" });
    await startIsfTryJob({ imagePath: "/i.lime", caseDir: "c", draft: "d", plugin: "linux.pslist", groundTruth: "" });
    expect(last(fn)[0]).toBe("/api/isf/try");
    expect(bodyOf(fn)).toEqual({ image_path: "/i.lime", case_dir: "c", draft: "d", plugin: "linux.pslist", async: true });
    await startIsfProbeJob({ imagePath: "/i.lime", probe: "kallsyms", arch: "auto", caseDir: "c", draft: "d" });
    expect(bodyOf(fn)).toEqual({ image_path: "/i.lime", probe: "kallsyms", arch: "auto", async: true, case_dir: "c", draft: "d" });
    await startIsfProbeJob({ imagePath: "/i.lime", probe: "banner", arch: "auto" });
    expect(bodyOf(fn)).not.toHaveProperty("draft");
  });

  it("sends a disasm address past 2^53 as an exact integer literal", async () => {
    const fn = mockFetch({});
    await disassemble("/v.mdview", 0xffffffff81000123n, 64, { arch: "x86_64" });
    const raw = last(fn)[1].body as string;
    expect(raw).toContain('"address":18446744071578845475');
    expect(raw).toContain('"length":64');
  });

  it("sends search and offset to the draft read", async () => {
    const fn = mockFetch({});
    await getIsfDraft(REF, "d", { only: { symbols: [] }, search: "init", offset: 400, limit: 200 });
    const url = new URL(last(fn)[0], "http://x");
    expect(url.searchParams.get("search")).toBe("init");
    expect(url.searchParams.get("offset")).toBe("400");
    await getIsfDraft(REF, "d", { only: { symbols: [] }, search: "" });
    expect(new URL(last(fn)[0], "http://x").searchParams.has("search")).toBe(false);
  });

  it("reads a job payload losslessly from the task result", async () => {
    const fn = vi.fn(async () => new Response(
      '{"payload":{"rows":[{"location":{"space":"kernel_va","value":18446744071578845475}}]}}', { status: 200 }));
    vi.stubGlobal("fetch", fn);
    const payload = await getIsfJobPayload<{ rows: { location: { value: string } }[] }>("t 1");
    expect(fn).toHaveBeenCalledWith("/api/tasks/t%201/result");
    expect(payload!.rows[0].location.value).toBe("18446744071578845475");
  });

  it("returns null for a task with no payload", async () => {
    mockFetch({ payload: null });
    expect(await getIsfJobPayload("t")).toBeNull();
  });

  it("lists past tries through the annotations route with kind=isf_try", async () => {
    const fn = mockFetch({ entries: [], count: 0 });
    await listIsfTries("case1", "cap");
    expect(last(fn)[0]).toBe("/api/annotations?case_dir=case1&capture_id=cap&kind=isf_try");
  });
});
