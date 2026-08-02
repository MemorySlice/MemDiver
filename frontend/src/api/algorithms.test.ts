import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { getAlgorithmAvailability } from "./algorithms";

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockResolvedValue(jsonResponse({ availability: {} }));
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("getAlgorithmAvailability", () => {
  it("stringifies the boolean + count context params", async () => {
    await getAlgorithmAvailability({
      dumpCount: 3,
      hasKeylog: true,
      hasCandidateKeys: false,
    });

    const url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.pathname).toBe("/api/algorithms/availability");
    expect(url.searchParams.get("dump_count")).toBe("3");
    expect(url.searchParams.get("has_keylog")).toBe("true");
    expect(url.searchParams.get("has_candidate_keys")).toBe("false");
  });

  it("repeats the algorithms param once per name", async () => {
    await getAlgorithmAvailability({
      dumpCount: 1,
      hasKeylog: false,
      hasCandidateKeys: false,
      algorithms: ["consensus", "reduce", "brute_force"],
    });

    const url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.searchParams.getAll("algorithms")).toEqual([
      "consensus",
      "reduce",
      "brute_force",
    ]);
  });

  it("only sets mode when a truthy value is given", async () => {
    await getAlgorithmAvailability({
      dumpCount: 1,
      hasKeylog: false,
      hasCandidateKeys: false,
    });
    let url = new URL(fetchMock.mock.calls[0][0], "http://x");
    expect(url.searchParams.has("mode")).toBe(false);

    await getAlgorithmAvailability({
      dumpCount: 1,
      hasKeylog: false,
      hasCandidateKeys: false,
      mode: "single_file",
    });
    url = new URL(fetchMock.mock.calls[1][0], "http://x");
    expect(url.searchParams.get("mode")).toBe("single_file");
  });
});
