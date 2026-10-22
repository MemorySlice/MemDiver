import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { ENTROPY_ENVELOPE_BUCKETS, ENTROPY_MAX_PROFILE_POSITIONS, getEntropy } from "@/api/client";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => "{}" } as unknown as Response);
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function calledParams(): URLSearchParams {
  return new URL(fetchMock.mock.calls[0][0], "http://x").searchParams;
}

describe("getEntropy query parameters", () => {
  it("exports the envelope bucket count the entropy tab asks for", () => {
    expect(ENTROPY_ENVELOPE_BUCKETS).toBe(1500);
  });

  it("sends only the historical params by default", async () => {
    await getEntropy("/d.bin", 0, 0);
    const qs = calledParams();
    expect(qs.get("dump_path")).toBe("/d.bin");
    expect(qs.get("max_positions")).toBe(String(ENTROPY_MAX_PROFILE_POSITIONS));
    for (const name of ["view", "buckets", "resolution", "threshold"]) {
      expect(qs.has(name)).toBe(false);
    }
  });

  it("accepts the options object as the fifth argument", async () => {
    await getEntropy("/d.bin", 16, 256, undefined, {
      view: "vas",
      buckets: 1500,
      resolution: "full",
      threshold: 4.25,
    });
    const qs = calledParams();
    expect(qs.get("view")).toBe("vas");
    expect(qs.get("buckets")).toBe("1500");
    expect(qs.get("resolution")).toBe("full");
    expect(qs.get("threshold")).toBe("4.25");
    expect(qs.get("offset")).toBe("16");
    expect(qs.get("length")).toBe("256");
  });

  it("accepts maxPositions plus options as fifth and sixth arguments", async () => {
    await getEntropy("/d.bin", 0, 0, undefined, 1024, { resolution: "sampled", threshold: 0 });
    const qs = calledParams();
    expect(qs.get("max_positions")).toBe("1024");
    expect(qs.get("resolution")).toBe("sampled");
    expect(qs.get("threshold")).toBe("0");
  });

  it("passes an abort signal through to fetch", async () => {
    const controller = new AbortController();
    await getEntropy("/d.bin", 0, 0, undefined, { signal: controller.signal });
    expect(fetchMock.mock.calls[0][1].signal).toBe(controller.signal);
    expect(calledParams().has("signal")).toBe(false);
  });
});
