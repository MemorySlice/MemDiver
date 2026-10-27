import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, compact, postJson, request } from "@/api/client";
import { getTaskPayload, parseJsonLossless, postLossless, requestLossless } from "@/api/lossless-json";
import { getStringsJobPayload } from "@/api/strings";
import i18n from "@/i18n";
import { cellToBigInt } from "@/components/vol3/vol3-address";

afterEach(() => vi.unstubAllGlobals());

const stubFetch = (status: number, text: string) => {
  const fetchMock = vi.fn(async () => ({ ok: status < 400, status, text: async () => text }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
};

describe("parseJsonLossless", () => {
  it("parses small-number documents exactly like JSON.parse (fast path)", () => {
    const text = '{"a":1,"b":-2.5e3,"c":"123456789012345","d":[0,900719925474099],"e":null}';
    expect(parseJsonLossless(text)).toEqual(JSON.parse(text));
  });

  it("keeps an integer past 2^53 as a decimal string", () => {
    expect(parseJsonLossless('{"addr":18446612682441367552,"n":1}'))
      .toEqual({ addr: "18446612682441367552", n: 1 });
  });

  it("leaves a 16-digit run inside a string untouched", () => {
    expect(parseJsonLossless('{"s":"1234567890123456","n":7}')).toEqual({ s: "1234567890123456", n: 7 });
  });

  it("rejects malformed JSON on the fast path", () => {
    expect(() => parseJsonLossless("{")).toThrow();
  });
});

describe("getTaskPayload", () => {
  it("returns the payload decoded losslessly", async () => {
    const fetchMock = stubFetch(200, '{"payload":{"addr":18446612682441367552}}');
    await expect(getTaskPayload<{ addr: string }>("t/1")).resolves.toEqual({ addr: "18446612682441367552" });
    expect(fetchMock).toHaveBeenCalledWith("/api/tasks/t%2F1/result");
  });

  it("returns null when no payload was stored", async () => {
    stubFetch(200, '{"payload":null}');
    await expect(getTaskPayload("t")).resolves.toBeNull();
  });

  it("throws ApiError with the raw body on failure (strings alias included)", async () => {
    stubFetch(404, '{"error":"gone"}');
    const err = await getStringsJobPayload("t").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).message).toBe('{"error":"gone"}');
    expect((err as ApiError).status).toBe(404);
  });
});

describe("request transport (shared by the lossless wrappers)", () => {
  const KVA = "18446612682441367552";

  it("request rounds past 2^53 by default; the lossless parser keeps it exact", async () => {
    stubFetch(200, `{"addr":${KVA}}`);
    expect((await request<{ addr: unknown }>("/x")).addr).toBe(Number(KVA));
    expect((await request<{ addr: unknown }>("/x", undefined, { parse: parseJsonLossless })).addr).toBe(KVA);
    expect((await requestLossless<{ addr: unknown }>("/x")).addr).toBe(KVA);
  });

  it("postLossless posts JSON with the signal, decoding losslessly", async () => {
    const fetchMock = stubFetch(200, `{"addr":${KVA}}`);
    const signal = new AbortController().signal;
    expect((await postLossless<{ addr: unknown }>("/p", { a: 1 }, signal)).addr).toBe(KVA);
    expect(fetchMock).toHaveBeenCalledWith("/p", {
      method: "POST", body: '{"a":1}', signal, headers: { "Content-Type": "application/json" },
    });
  });

  it("postLossless rejects an empty body and a malformed one as ApiError", async () => {
    stubFetch(200, "");
    const empty = await postLossless("/p", {}).catch((e: unknown) => e);
    expect(empty).toBeInstanceOf(ApiError);
    expect(empty).toMatchObject({ status: 200, message: i18n.t("common:emptyResponse") });
    stubFetch(200, "{nope");
    const err = await postLossless("/p", {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).message).toBe("Malformed JSON response: {nope");
  });

  it("request and requestLossless still answer undefined for an empty body (e.g. 204)", async () => {
    stubFetch(200, "");
    await expect(request("/x")).resolves.toBeUndefined();
    await expect(requestLossless("/x")).resolves.toBeUndefined();
  });

  it("a failed request throws ApiError with the raw body, lossless or not", async () => {
    stubFetch(500, "boom");
    for (const call of [() => request("/x"), () => postJson("/x", {}), () => postLossless("/x", {})]) {
      const err = await call().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ApiError);
      expect(err).toMatchObject({ status: 500, message: "boom", body: "boom" });
    }
  });

  it("compact drops undefined and empty-string fields only", () => {
    expect(compact({ a: undefined, b: "", c: 0, d: null, e: false, f: "x" }))
      .toEqual({ c: 0, d: null, e: false, f: "x" });
  });
});

describe("cellToBigInt", () => {
  it("reads exact integers and refuses rounded ones", () => {
    expect(cellToBigInt(42)).toBe(42n);
    expect(cellToBigInt("18446612682441367552")).toBe(18446612682441367552n);
    expect(cellToBigInt(2 ** 60)).toBeNull();
    expect(cellToBigInt("0x10")).toBeNull();
  });
});
