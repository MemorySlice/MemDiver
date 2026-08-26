import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import {
  request,
  ApiError,
  readHex,
  extractStrings,
  getVasRegions,
} from "@/api/client";

/** Build a minimal Response-like stub for the mocked fetch. */
function jsonResponse(body: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("request", () => {
  it("issues the URL with the default JSON content-type header", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: 1 }));
    const out = await request<{ ok: number }>("/api/thing");

    expect(out).toEqual({ ok: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/thing");
    expect(init.headers).toMatchObject({ "Content-Type": "application/json" });
  });

  it("merges a caller-supplied headers object with the default Content-Type", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await request("/api/thing", { headers: { "X-Trace": "abc" } });

    const init = fetchMock.mock.calls[0][1];
    expect(init.headers).toEqual({
      "Content-Type": "application/json",
      "X-Trace": "abc",
    });
  });

  it("lets a caller-supplied Content-Type override the default", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await request("/api/thing", {
      headers: { "Content-Type": "text/plain", "X-Trace": "abc" },
    });

    const init = fetchMock.mock.calls[0][1];
    expect(init.headers).toEqual({
      "Content-Type": "text/plain",
      "X-Trace": "abc",
    });
  });

  it("still forwards other init fields (method, body) alongside the merged headers", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await request("/api/thing", {
      method: "POST",
      body: JSON.stringify({ a: 1 }),
      headers: { "X-Trace": "abc" },
    });

    const init = fetchMock.mock.calls[0][1];
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ a: 1 }));
    expect(init.headers).toEqual({
      "Content-Type": "application/json",
      "X-Trace": "abc",
    });
  });

  it("throws an ApiError carrying status + body on a non-ok response", async () => {
    fetchMock.mockResolvedValue(jsonResponse("nope", false, 422));

    await expect(request("/api/thing")).rejects.toBeInstanceOf(ApiError);
    await expect(request("/api/thing")).rejects.toMatchObject({
      status: 422,
      message: "nope",
      name: "ApiError",
    });
  });
});

describe("readHex", () => {
  it("builds the query string with dump_path, offset and length", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await readHex("/dumps/a.bin", 16, 64);

    const url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.pathname).toBe("/api/inspect/hex");
    expect(url.searchParams.get("dump_path")).toBe("/dumps/a.bin");
    expect(url.searchParams.get("offset")).toBe("16");
    expect(url.searchParams.get("length")).toBe("64");
  });

  it("appends only the provided key-material fields (appendKey)", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await readHex("/dumps/a.bin", 0, 256, { key_hex: "deadbeef" });

    const url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.searchParams.get("key_hex")).toBe("deadbeef");
    expect(url.searchParams.has("passphrase")).toBe(false);
    expect(url.searchParams.has("kem_key_hex")).toBe(false);
  });
});

describe("extractStrings", () => {
  it("omits keys for options that were not provided", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await extractStrings("/dumps/a.bin");

    const url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.searchParams.get("dump_path")).toBe("/dumps/a.bin");
    for (const key of [
      "min_length",
      "encoding",
      "max_results",
      "cursor",
      "chunk_size",
    ]) {
      expect(url.searchParams.has(key)).toBe(false);
    }
  });

  it("sets only the provided option keys", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await extractStrings("/dumps/a.bin", { minLength: 4, maxResults: 10 });

    const url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.searchParams.get("min_length")).toBe("4");
    expect(url.searchParams.get("max_results")).toBe("10");
    expect(url.searchParams.has("encoding")).toBe(false);
    expect(url.searchParams.has("cursor")).toBe(false);
    expect(url.searchParams.has("chunk_size")).toBe(false);
  });

  it("includes cursor=0 because 0 is defined (not undefined)", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await extractStrings("/dumps/a.bin", { cursor: 0 });

    const url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.searchParams.get("cursor")).toBe("0");
  });
});

describe("getVasRegions", () => {
  it("hits /api/inspect/vas with the msl_path query", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await getVasRegions("/dumps/a.msl");

    const url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.pathname).toBe("/api/inspect/vas");
    expect(url.searchParams.get("msl_path")).toBe("/dumps/a.msl");
  });

  it("appends only the provided key-material fields (appendKey)", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await getVasRegions("/dumps/a.msl", { passphrase: "hunter2" });

    const url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.searchParams.get("passphrase")).toBe("hunter2");
    expect(url.searchParams.has("key_hex")).toBe(false);
    expect(url.searchParams.has("kem_key_hex")).toBe(false);
  });

  it("returns the parsed VasRegionsResponse (entries passed through)", async () => {
    const body = {
      vas_entries: [
        {
          base_addr: 4096,
          region_size: 8192,
          region_type: 1,
          protection: 3,
          mapped_path: "/lib/libc.so",
        },
      ],
      region_count: 1,
      total_region_size: 8192,
      vas_coverage: { captured: 1 },
    };
    fetchMock.mockResolvedValueOnce(jsonResponse(body));

    const out = await getVasRegions("/dumps/a.msl");
    expect(out).toEqual(body);
    expect(out.vas_entries[0].mapped_path).toBe("/lib/libc.so");
  });
});
