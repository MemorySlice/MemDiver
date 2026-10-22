import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { readHex, applyStructure, autoDetectStructure } from "@/api/client";

/** Reads that describe a hex-viewer cursor carry the view it addresses. */

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({}), text: async () => "{}" } as unknown as Response);
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function calledUrl(): URL {
  return new URL(fetchMock.mock.calls[0][0], "http://x");
}

describe("view-aware inspect reads", () => {
  it("readHex sends the view when given", async () => {
    await readHex("/c", 0x1100, 1, undefined, { view: "vas" });
    expect(calledUrl().searchParams.get("view")).toBe("vas");
    expect(calledUrl().searchParams.get("offset")).toBe(String(0x1100));
  });

  it("readHex omits the view by default (backend default)", async () => {
    await readHex("/c", 0, 1);
    expect(calledUrl().searchParams.has("view")).toBe(false);
  });

  it("applyStructure sends the view when given", async () => {
    await applyStructure("/c", 16, "s", undefined, "raw");
    expect(calledUrl().pathname).toBe("/api/inspect/structure-apply");
    expect(calledUrl().searchParams.get("view")).toBe("raw");
  });

  it("autoDetectStructure sends the view only when given", async () => {
    await autoDetectStructure("/c", 16, undefined, "va");
    expect(calledUrl().searchParams.get("view")).toBe("va");
    fetchMock.mockClear();
    await autoDetectStructure("/c", 16);
    expect(calledUrl().searchParams.has("view")).toBe(false);
  });
});
