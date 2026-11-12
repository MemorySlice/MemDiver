import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@/api/client";
import {
  execVol3Plugin, getVol3PluginDir, getVol3SynthJobPayload, isJobTicket, KNOWN_ORACLE_KINDS,
  synthesizeVol3Plugin, vol3ErrorOf,
} from "@/api/vol3";

function mockFetchText(body: string, status = 200) {
  const fn = vi.fn(async () => new Response(body, { status }));
  vi.stubGlobal("fetch", fn);
  return fn;
}
const lastCall = (fn: ReturnType<typeof mockFetchText>) =>
  fn.mock.calls.at(-1) as unknown as [string, RequestInit];

afterEach(() => vi.unstubAllGlobals());

describe("vol3 synthesize / exec client", () => {
  it("reads the installed plugin directory", async () => {
    const fn = mockFetchText(JSON.stringify({ path: "/repo/vol3plugins" }));
    expect(await getVol3PluginDir()).toEqual({ path: "/repo/vol3plugins" });
    expect(lastCall(fn)[0]).toBe("/api/vol3/plugin-dir");
  });

  it("posts a synthesize request with the secret as secret_hex and drops blank optionals", async () => {
    const fn = mockFetchText(JSON.stringify({ proven: true }));
    await synthesizeVol3Plugin({
      dump_paths: ["/a.msl", "/b.msl"], name: "memdiver_gocryptfs", oracle_kind: "gocryptfs-gcm",
      secret_hex: ["aa", "bb"], oracle_sample_path: ["/a/cipher", null], case_dir: "", full_image: undefined,
      verify_on: ["msl"],
    });
    const [url, init] = lastCall(fn);
    expect(url).toBe("/api/vol3/synthesize");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      dump_paths: ["/a.msl", "/b.msl"], name: "memdiver_gocryptfs", oracle_kind: "gocryptfs-gcm",
      secret_hex: ["aa", "bb"], oracle_sample_path: ["/a/cipher", null], verify_on: ["msl"],
    });
  });

  it("posts async: true and answers with the job ticket", async () => {
    const fn = mockFetchText(JSON.stringify({ task_id: "ab12", status: "pending" }));
    const answer = await synthesizeVol3Plugin({
      dump_paths: ["/a.msl"], name: "memdiver_gocryptfs", oracle_kind: "gocryptfs-gcm", secret_hex: "aa", async: true,
    });
    expect(JSON.parse(lastCall(fn)[1].body as string)).toEqual({
      dump_paths: ["/a.msl"], name: "memdiver_gocryptfs", oracle_kind: "gocryptfs-gcm", secret_hex: "aa", async: true,
    });
    expect(isJobTicket(answer)).toBe(true);
    expect(answer).toEqual({ task_id: "ab12", status: "pending" });
  });

  it("reads a finished synthesize job's stored payload", async () => {
    const fn = mockFetchText(JSON.stringify({ task_id: "ab12", payload: { proven: true, proven_hits: 2 } }));
    expect(await getVol3SynthJobPayload("ab12")).toEqual({ proven: true, proven_hits: 2 });
    expect(lastCall(fn)[0]).toBe("/api/tasks/ab12/result");

    mockFetchText(JSON.stringify({ task_id: "ab12", payload: null }));
    expect(await getVol3SynthJobPayload("ab12")).toBeNull();
  });

  it("posts exec and keeps an offset beyond 2^53 exact", async () => {
    const fn = mockFetchText('{"ok":true,"rows":[{"Offset":18446612682103595008,"Proven":"oracle:x"}],"row_count":1}');
    const out = await execVol3Plugin({ plugin: "m.P", image_path: "/a.msl", plugin_dirs: ["/c"], args: [] });
    expect(lastCall(fn)[0]).toBe("/api/vol3/exec");
    expect(JSON.parse(lastCall(fn)[1].body as string))
      .toEqual({ plugin: "m.P", image_path: "/a.msl", plugin_dirs: ["/c"], args: [] });
    expect(String(out.rows[0].Offset)).toBe("18446612682103595008");
  });

  it("knows the gocryptfs oracle", () => {
    expect(KNOWN_ORACLE_KINDS).toContain("gocryptfs-gcm");
  });
});

describe("vol3ErrorOf", () => {
  it("reads code and message from a CapabilityError body", () => {
    const body = JSON.stringify({ error: "not a case: /x", code: "case.not_a_case", category: "INVALID_INPUT" });
    expect(vol3ErrorOf(new ApiError(400, body))).toEqual({ code: "case.not_a_case", message: "not a case: /x" });
  });

  it("falls back to readable text without a code", () => {
    expect(vol3ErrorOf(new Error("network down"))).toEqual({ code: null, message: "network down" });
    const detail = JSON.stringify({ detail: "Unprocessable" });
    expect(vol3ErrorOf(new ApiError(422, detail))).toEqual({ code: null, message: "Unprocessable" });
  });
});
