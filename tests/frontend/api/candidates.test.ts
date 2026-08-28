import { afterEach, describe, it, expect, vi } from "vitest";

import {
  analyzeCandidates,
  buildCandidatesRequest,
  dominantClass,
  BYTE_CLASSES,
  DEFAULT_CANDIDATE_CLASSES,
  DEFAULT_CANDIDATE_FILTERS,
  NON_INVARIANT_CLASSES,
  type AnalysisCandidatesRequest,
} from "@/api/candidates";

afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * THE MEASURED PRODUCT RULE.
 *
 * On eight real dumps of one OpenSSL run, the actual 48-byte TLS 1.2 secret
 * classifies as 22 KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL — its longest
 * contiguous KEY_CANDIDATE run is 3 bytes. `key_candidate` alone returns 7
 * regions and the key is NOT among them; all three non-invariant classes
 * return 25 regions with the key as one clean 48-byte row at rank 10.
 *
 * These tests exist so that narrowing the default back to key-candidate-only
 * — the intuitive-looking change — fails loudly instead of silently losing
 * every mixed-class key.
 */
describe("default class selection", () => {
  it("is every non-invariant class", () => {
    expect([...DEFAULT_CANDIDATE_CLASSES].sort()).toEqual(
      ["key_candidate", "pointer", "structural"].sort(),
    );
    expect(DEFAULT_CANDIDATE_CLASSES).toBe(NON_INVARIANT_CLASSES);
  });

  it("is NOT key_candidate-only", () => {
    expect(DEFAULT_CANDIDATE_CLASSES).not.toEqual(["key_candidate"]);
    expect(DEFAULT_CANDIDATE_CLASSES.length).toBeGreaterThan(1);
    for (const cls of ["structural", "pointer"] as const) {
      expect(
        DEFAULT_CANDIDATE_CLASSES,
        `${cls} must stay in the default selection: a real TLS secret is class-mixed`,
      ).toContain(cls);
    }
  });

  it("excludes invariant — 99.9 % of a process is invariant", () => {
    expect(DEFAULT_CANDIDATE_CLASSES).not.toContain("invariant");
  });

  it("is what the default filter state carries", () => {
    expect(DEFAULT_CANDIDATE_FILTERS.classes).toEqual([...DEFAULT_CANDIDATE_CLASSES]);
  });
});

describe("buildCandidatesRequest", () => {
  const paths = ["/dumps/a.bin", "/dumps/b.bin"];

  it("composes the filter state into the request body", () => {
    const body = buildCandidatesRequest(paths, {
      classes: ["pointer", "key_candidate"],
      minRegion: 32,
      maxRegion: 256,
      entropyThreshold: 5.5,
      alignment: 16,
    });
    expect(body).toMatchObject({
      dump_paths: paths,
      classes: ["pointer", "key_candidate"],
      min_region: 32,
      max_region: 256,
      entropy_threshold: 5.5,
      alignment: 16,
      order: "rank",
      normalize: false,
    });
  });

  it("NEVER sends min_variance — 3000 would re-impose the floor the class filter opens", () => {
    const body: AnalysisCandidatesRequest = buildCandidatesRequest(
      paths,
      DEFAULT_CANDIDATE_FILTERS,
    );
    expect(Object.prototype.hasOwnProperty.call(body, "min_variance")).toBe(false);
    expect(body.min_variance).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain("min_variance");
    expect(JSON.stringify(body)).not.toContain("3000");
  });

  it("sends the default non-invariant class list on a default query", () => {
    const body = buildCandidatesRequest(paths, DEFAULT_CANDIDATE_FILTERS);
    expect(body.classes).toEqual(["structural", "pointer", "key_candidate"]);
  });

  it("sends null (not []) when every class is deselected, so the backend resolves it", () => {
    const body = buildCandidatesRequest(paths, {
      ...DEFAULT_CANDIDATE_FILTERS,
      classes: [],
    });
    expect(body.classes).toBeNull();
  });

  it("copies the path list so a later mutation cannot reach the sent body", () => {
    const mutable = [...paths];
    const body = buildCandidatesRequest(mutable, DEFAULT_CANDIDATE_FILTERS);
    mutable.push("/dumps/c.bin");
    expect(body.dump_paths).toHaveLength(2);
  });

  it("honours the normalize + maxReturned + order overrides", () => {
    const body = buildCandidatesRequest(paths, DEFAULT_CANDIDATE_FILTERS, {
      normalize: true,
      maxReturned: 25,
      order: "offset",
    });
    expect(body.normalize).toBe(true);
    expect(body.max_returned).toBe(25);
    expect(body.order).toBe("offset");
  });
});

describe("dominantClass", () => {
  it("returns the class owning the most bytes", () => {
    expect(dominantClass({ structural: 8, pointer: 18, key_candidate: 22 })).toBe(
      "key_candidate",
    );
    expect(dominantClass({ structural: 40, pointer: 2 })).toBe("structural");
  });

  it("breaks a tie toward the higher-variance class", () => {
    expect(dominantClass({ pointer: 10, key_candidate: 10 })).toBe("key_candidate");
  });

  it("returns null for the entropy-only fallback, where nothing was classified", () => {
    expect(dominantClass({})).toBeNull();
  });

  it("knows all four classes", () => {
    expect(BYTE_CLASSES).toEqual([
      "invariant",
      "structural",
      "pointer",
      "key_candidate",
    ]);
  });
});

describe("analyzeCandidates", () => {
  it("POSTs the body to /api/analysis/candidates", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ num_regions: 0, regions: [] }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const body = buildCandidatesRequest(["/a", "/b"], DEFAULT_CANDIDATE_FILTERS);
    await analyzeCandidates(body);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/analysis/candidates");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual(body);

    vi.unstubAllGlobals();
  });
});
