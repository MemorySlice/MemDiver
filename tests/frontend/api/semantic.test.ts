import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, readableFailure } from "@/api/client";
import {
  buildArtifactModel, exportArtifactModel, getAnchorConsensus, proposeLayout, validateArtifactModel,
} from "@/api/semantic";

function mockFetch(body: unknown = {}, status = 200) {
  const fn = vi.fn(async () => new Response(JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", fn);
  return fn;
}
const last = (fn: ReturnType<typeof mockFetch>) => fn.mock.calls.at(-1) as unknown as [string, RequestInit];
const bodyOf = (fn: ReturnType<typeof mockFetch>) => JSON.parse(last(fn)[1].body as string);

afterEach(() => vi.unstubAllGlobals());

describe("semantic client", () => {
  it("POSTs the anchor consensus body verbatim", async () => {
    const fn = mockFetch({ regions: [] });
    await getAnchorConsensus({
      dump_paths: ["/a"], needles: { "/a": "aabb" }, occurrence: 1,
      delta_start: -16, length: 64, min_instances: 2, include_bytes: false, mixed_ok: true,
    });
    expect(last(fn)[0]).toBe("/api/analysis/consensus/anchor");
    expect(last(fn)[1].method).toBe("POST");
    expect(bodyOf(fn)).toEqual({
      dump_paths: ["/a"], needles: { "/a": "aabb" }, occurrence: 1,
      delta_start: -16, length: 64, min_instances: 2, include_bytes: false, mixed_ok: true,
    });
  });

  it("POSTs propose-layout with related values and anchors", async () => {
    const fn = mockFetch({ fields: [] });
    await proposeLayout({
      anchors: [{ dump_path: "/a", va: 4096 }], anchor_length: 8,
      related: { sid: { "/a": "0102" } }, pointer_quorum: 2, heap: false, case_dir: "/case",
    });
    expect(last(fn)[0]).toBe("/api/semantic/propose-layout");
    expect(bodyOf(fn).related).toEqual({ sid: { "/a": "0102" } });
    expect(bodyOf(fn).anchors).toEqual([{ dump_path: "/a", va: 4096 }]);
    expect(bodyOf(fn).heap).toBe(false);
  });

  it("surfaces a CapabilityError envelope as a readable message", async () => {
    mockFetch({ error: "pass exactly one of 'anchors' or 'needles'" }, 400);
    const err = await getAnchorConsensus({}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(readableFailure(err)).toContain("exactly one of");
  });

  it("POSTs model-build with meanings, relationships and applicability", async () => {
    const fn = mockFetch({ path: "/m.json" });
    await buildArtifactModel({
      needles: { "/a": "aa" }, name: "m",
      meanings: [{ field: "key", meaning: "tls_secret", label: "CLIENT" }],
      relationships: [{ kind: "owned_by", source: "key", target: "anchor" }],
      applicability: { library: "boringssl", states: ["live"] }, out_path: "/m.json",
    });
    expect(last(fn)[0]).toBe("/api/semantic/model-build");
    expect(bodyOf(fn)).toMatchObject({
      name: "m", out_path: "/m.json", applicability: { library: "boringssl", states: ["live"] },
      relationships: [{ kind: "owned_by", source: "key", target: "anchor" }],
    });
    expect(bodyOf(fn).meanings[0].label).toBe("CLIENT");
  });

  it("POSTs model-export and model-validate bodies", async () => {
    const fn = mockFetch({});
    await exportArtifactModel({ model_path: "/m.json", out_path: "/p.py" });
    expect(last(fn)[0]).toBe("/api/semantic/model-export");
    expect(bodyOf(fn)).toEqual({ model_path: "/m.json", out_path: "/p.py" });
    await validateArtifactModel({
      model_path: "/m.json", held_out: [{ dump_path: "/h", keylog_path: "/k" }],
    });
    expect(last(fn)[0]).toBe("/api/semantic/model-validate");
    expect(bodyOf(fn).held_out).toEqual([{ dump_path: "/h", keylog_path: "/k" }]);
  });

  it("surfaces the held-out leak refusal readably", async () => {
    mockFetch({ error: "held-out dump was used for learning: /a", code: "semantic.held_out_leak" }, 400);
    const err = await validateArtifactModel({ model_path: "/m", held_out: [] }).catch((e: unknown) => e);
    expect(readableFailure(err)).toContain("used for learning");
  });
});
