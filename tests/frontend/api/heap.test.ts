import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  fetchHeapChunkAt,
  fetchHeapChunks,
  fetchHeapDetect,
  fetchHeapRoles,
} from "@/api/heap";
import { ApiError } from "@/api/client";

const fetchMock = vi.fn();

function ok(body: unknown): Response {
  return { ok: true, text: async () => JSON.stringify(body) } as unknown as Response;
}

function calledUrl(): URL {
  return new URL(String(fetchMock.mock.calls[0][0]), "http://x");
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api/heap", () => {
  it("omits allocator=auto and forwards key material", async () => {
    fetchMock.mockResolvedValue(ok({ best: "ptmalloc2" }));
    await fetchHeapDetect({ dumpPath: "/d.msl", allocator: "auto", key: { passphrase: "pw" } });
    const url = calledUrl();
    expect(url.pathname).toBe("/api/heap/detect");
    expect(url.searchParams.get("dump_path")).toBe("/d.msl");
    expect(url.searchParams.has("allocator")).toBe(false);
    expect(url.searchParams.get("passphrase")).toBe("pw");
  });

  it("maps chunk filters onto the wire names and skips unset ones", async () => {
    fetchMock.mockResolvedValue(ok({ chunks: [] }));
    await fetchHeapChunks({
      dumpPath: "/d",
      allocator: "scudo",
      filters: { state: "free", minSize: 32, maxSize: null, vaStart: 4096 },
      view: "va",
      page: 2,
      pageSize: 50,
    });
    const qs = calledUrl().searchParams;
    expect(qs.get("allocator")).toBe("scudo");
    expect(qs.get("state")).toBe("free");
    expect(qs.get("min_size")).toBe("32");
    expect(qs.has("max_size")).toBe(false);
    expect(qs.get("va_start")).toBe("4096");
    expect(qs.get("view")).toBe("va");
    expect(qs.get("page")).toBe("2");
    expect(qs.get("page_size")).toBe("50");
  });

  it("addresses chunk-at by offset in a view", async () => {
    fetchMock.mockResolvedValue(ok({ found: false }));
    await fetchHeapChunkAt({ dumpPath: "/d", offset: 64, view: "vas" });
    const qs = calledUrl().searchParams;
    expect(qs.get("offset")).toBe("64");
    expect(qs.get("view")).toBe("vas");
    expect(qs.has("va")).toBe(false);
  });

  it("requests a role window", async () => {
    fetchMock.mockResolvedValue(ok({ runs: [] }));
    await fetchHeapRoles({ dumpPath: "/d", view: "raw", offset: 65536, length: 65536 });
    const url = calledUrl();
    expect(url.pathname).toBe("/api/heap/roles");
    expect(url.searchParams.get("offset")).toBe("65536");
    expect(url.searchParams.get("length")).toBe("65536");
  });

  it("rejects a non-2xx answer with ApiError", async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 422,
      text: async () => JSON.stringify({ error: "bad", code: "x", category: "y" }),
    });
    await expect(fetchHeapDetect({ dumpPath: "/d" })).rejects.toBeInstanceOf(ApiError);
  });
});
