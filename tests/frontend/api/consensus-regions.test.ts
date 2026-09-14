import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import {
  DEFAULT_REGION_MIN_LENGTH,
  DEFAULT_REGIONS_PER_PAGE,
  MAX_REGIONS_PER_PAGE,
  NO_HONEST_ANSWER,
  NON_INVARIANT_UNION,
  REGION_CURSOR_START,
  anchorSpan,
  buildConsensusRegionsRequest,
  fetchConsensusRegions,
  hasNextPage,
  isJumpable,
  type ClassRegion,
  type ConsensusRegionsResponse,
} from "@/api/consensus-regions";

/**
 * The wire seam of the consensus-regions browser:
 *
 *   buildConsensusRegionsRequest -> POST /api/analysis/consensus/regions
 *     -> ClassRegion[] -> anchor_offset -> hex-store.scrollToOffset
 *
 * Three of the four things this file can get wrong are silent. A request that
 * names a class instead of the union comes back EMPTY for a real key and looks
 * like "no hits". A `-1` read as an offset scrolls to byte 0 and looks like a
 * jump. `length` read as a VA span highlights the wrong bytes and looks like a
 * selection. Each case below pins one of them.
 */

const CONSENSUS_ID = "cns-1";
const DUMP_A = "/dumps/a.msl";
const DUMP_B = "/dumps/b.msl";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function region(overrides: Partial<ClassRegion> = {}): ClassRegion {
  return {
    slab_start: 1024,
    slab_end: 1072,
    length: 48,
    classification: "key_candidate",
    mean_variance: 9001.5,
    class_counts: { key_candidate: 27, pointer: 18, structural: 3 },
    anchor_va: 0x7f0000001000,
    anchor_offset: 583560,
    anchor_offset_end: 583608,
    anchor_contiguous: true,
    ...overrides,
  };
}

function pageBody(
  overrides: Partial<ConsensusRegionsResponse> = {},
): ConsensusRegionsResponse {
  return {
    consensus_id: CONSENSUS_ID,
    coordinate: "aligned",
    alignment: {
      method: "module_offset",
      bytes_compared: 8192,
      bytes_discarded: 0,
      sizes_differed: false,
      n_sources: 2,
      warnings: [],
    },
    anchor: {
      dump_path: DUMP_A,
      dump_index: 0,
      view: "va",
      jumpable: true,
    },
    classes: ["structural", "pointer", "key_candidate"],
    union: true,
    min_length: 8,
    max_length: 0,
    sort: "offset",
    after: -1,
    next_after: -1,
    total: 1,
    returned: 1,
    truncated: false,
    counts: { invariant: 8100, structural: 40, pointer: 30, key_candidate: 22 },
    regions: [region()],
    ...overrides,
  };
}

/** A Response as `@/api/client`'s `request` consumes it: ok + text(). */
function asResponse(body: ConsensusRegionsResponse): Response {
  return { ok: true, text: async () => JSON.stringify(body) } as unknown as Response;
}

function lastBody(): Record<string, unknown> {
  const call = fetchMock.mock.calls.at(-1);
  return JSON.parse(String((call?.[1] as RequestInit).body)) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// The either/or contract
// ---------------------------------------------------------------------------

describe("buildConsensusRegionsRequest — exactly one source", () => {
  it("sends consensus_id and NOT dump_paths for a registered build", () => {
    const body = buildConsensusRegionsRequest({ consensusId: CONSENSUS_ID });

    expect(body.consensus_id).toBe(CONSENSUS_ID);
    expect(body).not.toHaveProperty("dump_paths");
  });

  it("sends dump_paths and NOT consensus_id for the ad-hoc branch", () => {
    const body = buildConsensusRegionsRequest({ dumpPaths: [DUMP_A, DUMP_B] });

    expect(body.dump_paths).toEqual([DUMP_A, DUMP_B]);
    expect(body).not.toHaveProperty("consensus_id");
  });

  it("copies dump_paths rather than aliasing the caller's array", () => {
    // The body outlives the call site; a later splice of the selection must not
    // retroactively change the request that was sent.
    const paths = [DUMP_A, DUMP_B];
    const body = buildConsensusRegionsRequest({ dumpPaths: paths });
    paths.pop();

    expect(body.dump_paths).toEqual([DUMP_A, DUMP_B]);
  });

  it("never emits both keys, whichever source it is given", () => {
    for (const source of [
      { consensusId: CONSENSUS_ID },
      { dumpPaths: [DUMP_A, DUMP_B] },
    ] as const) {
      const body = buildConsensusRegionsRequest(source);
      const named = ["consensus_id", "dump_paths"].filter((k) => k in body);
      // Both, or neither, is a 400 at the boundary — "which correspondence are
      // these regions in" has to have exactly one answer.
      expect(named).toHaveLength(1);
    }
  });
});

// ---------------------------------------------------------------------------
// THE MEASURED PRODUCT RULE: classes=null is the non-invariant union
// ---------------------------------------------------------------------------

describe("the class filter", () => {
  /**
   * Measured on real data this session: a planted 48-byte TLS secret classifies
   * as 27 key_candidate + 18 pointer + 3 structural, and
   * `classes=["key_candidate"], min_length=8` returns **total 0** — the naive
   * per-class query loses the secret entirely. `null` is the server's
   * non-invariant union and is therefore the default here.
   */
  it("defaults to null — the NON-INVARIANT UNION, not a class list", () => {
    const body = buildConsensusRegionsRequest({ consensusId: CONSENSUS_ID });

    expect(body.classes).toBeNull();
  });

  it("is NOT defaulted to key_candidate-only", () => {
    const body = buildConsensusRegionsRequest({ consensusId: CONSENSUS_ID });

    expect(body.classes).not.toEqual(["key_candidate"]);
  });

  it("passes an explicit null through unchanged instead of substituting", () => {
    // `null` is a real, load-bearing value on this route. Coercing it to a
    // list here would reintroduce the shattered-key bug from the other end.
    const body = buildConsensusRegionsRequest(
      { consensusId: CONSENSUS_ID },
      { classes: null },
    );

    expect(body.classes).toBeNull();
  });

  it("carries the union alias verbatim when a caller names it", () => {
    const body = buildConsensusRegionsRequest(
      { consensusId: CONSENSUS_ID },
      { classes: [NON_INVARIANT_UNION] },
    );

    expect(body.classes).toEqual(["non_invariant"]);
  });

  it("carries a single named class when a caller really wants one", () => {
    const body = buildConsensusRegionsRequest(
      { consensusId: CONSENSUS_ID },
      { classes: ["pointer"] },
    );

    expect(body.classes).toEqual(["pointer"]);
  });
});

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

describe("request defaults", () => {
  it("mirrors the server's own defaults, explicitly", () => {
    const body = buildConsensusRegionsRequest({ consensusId: CONSENSUS_ID });

    expect(body.min_length).toBe(DEFAULT_REGION_MIN_LENGTH);
    expect(DEFAULT_REGION_MIN_LENGTH).toBe(8);
    expect(body.max_length).toBe(0); // 0 = unbounded, the backend contract
    expect(body.after).toBe(REGION_CURSOR_START);
    expect(REGION_CURSOR_START).toBe(-1); // -1 = start, never "offset zero"
    expect(body.limit).toBe(DEFAULT_REGIONS_PER_PAGE);
    expect(DEFAULT_REGIONS_PER_PAGE).toBe(200);
    expect(body.anchor_view).toBe("va");
    expect(body.include_anchor_offsets).toBe(true);
    expect(body.normalize).toBe(false);
  });

  it("knows the hard page cap the route enforces with a 422", () => {
    expect(MAX_REGIONS_PER_PAGE).toBe(500);
  });

  it("omits anchor_path entirely when there is no anchor", () => {
    // Its ABSENCE is what tells the producer to open no container at all.
    const body = buildConsensusRegionsRequest({ consensusId: CONSENSUS_ID });

    expect(body).not.toHaveProperty("anchor_path");
  });

  it("omits keys when there are none — key material stays out of the body", () => {
    const body = buildConsensusRegionsRequest(
      { consensusId: CONSENSUS_ID },
      { keys: [] },
    );

    expect(body).not.toHaveProperty("keys");
  });

  it("carries the anchor, its view and its key when one is given", () => {
    const body = buildConsensusRegionsRequest(
      { consensusId: CONSENSUS_ID },
      {
        anchorPath: DUMP_A,
        anchorView: "vas",
        keys: [{ dump_path: DUMP_A, passphrase: "hunter2" }],
      },
    );

    expect(body.anchor_path).toBe(DUMP_A);
    // Resolving a "vas" anchor offset means OPENING — and decrypting — the
    // anchor container, which is why the key travels with the request.
    expect(body.anchor_view).toBe("vas");
    expect(body.keys).toEqual([{ dump_path: DUMP_A, passphrase: "hunter2" }]);
  });

  it("forwards an explicit cursor for the next page", () => {
    const body = buildConsensusRegionsRequest(
      { consensusId: CONSENSUS_ID },
      { after: 4096, minLength: 32, maxLength: 256, limit: 50 },
    );

    expect(body.after).toBe(4096);
    expect(body.min_length).toBe(32);
    expect(body.max_length).toBe(256);
    expect(body.limit).toBe(50);
  });
});

// ---------------------------------------------------------------------------
// The transport
// ---------------------------------------------------------------------------

describe("fetchConsensusRegions", () => {
  it("POSTs the body to the regions route", async () => {
    fetchMock.mockResolvedValue(asResponse(pageBody()));

    await fetchConsensusRegions(
      buildConsensusRegionsRequest({ consensusId: CONSENSUS_ID }),
    );

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/analysis/consensus/regions");
    // POST, not GET: N key triples do not fit a query string, and key material
    // must stay out of access logs, shell history and `Referer`.
    expect(init.method).toBe("POST");
    expect(lastBody().consensus_id).toBe(CONSENSUS_ID);
  });

  it("parses the envelope and every field of a row", async () => {
    fetchMock.mockResolvedValue(asResponse(pageBody()));

    const res = await fetchConsensusRegions({ consensus_id: CONSENSUS_ID });

    expect(res.consensus_id).toBe(CONSENSUS_ID);
    expect(res.coordinate).toBe("aligned");
    expect(res.union).toBe(true);
    expect(res.classes).toEqual(["structural", "pointer", "key_candidate"]);
    expect(res.alignment.method).toBe("module_offset");
    expect(res.counts.key_candidate).toBe(22);
    expect(res.total).toBe(1);
    expect(res.returned).toBe(1);
    expect(res.truncated).toBe(false);

    const row = res.regions[0];
    expect(row.slab_start).toBe(1024);
    expect(row.slab_end).toBe(1072);
    expect(row.length).toBe(48);
    // The row's OWN label — never inferred from mean_variance against a second,
    // drifting copy of core.variance's 0/200/3000 bands.
    expect(row.classification).toBe("key_candidate");
    // The fact that makes the union defensible: 27 + 18 + 3 = 48.
    expect(row.class_counts).toEqual({
      key_candidate: 27,
      pointer: 18,
      structural: 3,
    });
    expect(row.anchor_offset).toBe(583560);
    expect(row.anchor_contiguous).toBe(true);
  });

  it("reports a non-2xx as an ApiError, like every other typed client", async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 400,
      text: async () => "exactly one of consensus_id / dump_paths",
    } as unknown as Response);

    await expect(
      fetchConsensusRegions({ consensus_id: CONSENSUS_ID }),
    ).rejects.toMatchObject({ name: "ApiError", status: 400 });
  });
});

// ---------------------------------------------------------------------------
// The `-1` sentinel
// ---------------------------------------------------------------------------

describe("the -1 sentinel", () => {
  it("is spelled once and means -1", () => {
    expect(NO_HONEST_ANSWER).toBe(-1);
  });

  it("next_after === -1 is END OF LIST, not offset zero", () => {
    expect(hasNextPage(pageBody({ next_after: -1 }))).toBe(false);
    expect(hasNextPage(pageBody({ next_after: 0 }))).toBe(true);
    expect(hasNextPage(pageBody({ next_after: 8192 }))).toBe(true);
  });

  it("anchor_offset === -1 is a refusal, and 0 is a real offset", () => {
    expect(isJumpable(region({ anchor_offset: -1 }))).toBe(false);
    // The whole reason the sentinel is -1 and not 0: byte zero is jumpable.
    expect(isJumpable(region({ anchor_offset: 0 }))).toBe(true);
    expect(isJumpable(region({ anchor_offset: 583560 }))).toBe(true);
  });

  it("hides the jump for a whole page when the anchor is not jumpable", async () => {
    // A raw/flat build queried in "va", or a LOCKED anchor: reported, never
    // raised, because the regions themselves are unaffected by a missing key.
    fetchMock.mockResolvedValue(
      asResponse(
        pageBody({
          anchor: { dump_path: DUMP_A, dump_index: 0, view: "va", jumpable: false },
          regions: [
            region({ anchor_va: -1, anchor_offset: -1, anchor_offset_end: -1,
              anchor_contiguous: false }),
          ],
        }),
      ),
    );

    const res = await fetchConsensusRegions({ consensus_id: CONSENSUS_ID });

    expect(res.anchor.jumpable).toBe(false);
    // The page-level flag and the per-row sentinel are the same statement: a
    // caller reads `jumpable` once instead of inferring a refusal from a sea
    // of -1s, and the two must never disagree.
    expect(res.regions.every((r) => !isJumpable(r))).toBe(true);
  });

  it("reports no anchor at all as dump_path null / dump_index -1", async () => {
    fetchMock.mockResolvedValue(
      asResponse(
        pageBody({
          anchor: { dump_path: null, dump_index: -1, view: "va", jumpable: false },
        }),
      ),
    );

    const res = await fetchConsensusRegions({ consensus_id: CONSENSUS_ID });

    expect(res.anchor.dump_path).toBeNull();
    expect(res.anchor.dump_index).toBe(-1);
  });
});

// ---------------------------------------------------------------------------
// Fact 3: a region is contiguous in SLAB space, not in the anchor's
// ---------------------------------------------------------------------------

describe("anchorSpan", () => {
  it("is the jump target's extent, and equals length when contiguous", () => {
    const row = region();

    expect(anchorSpan(row)).toBe(48);
    expect(anchorSpan(row)).toBe(row.length);
  });

  it("DIFFERS from length across an msl_layout page boundary", () => {
    // `msl_layout` rows are per page and slab_to_va is linear only WITHIN a
    // row, so a 48-byte slab run can be two disjoint runs in the anchor's own
    // coordinate. `anchor_offset_end` is resolved from the region's LAST byte,
    // so the anchor-space range CONTAINS the region rather than equalling it.
    const split = region({
      length: 48,
      anchor_offset: 4064,
      anchor_offset_end: 8224,
      anchor_contiguous: false,
    });

    expect(split.length).toBe(48);
    expect(anchorSpan(split)).toBe(4160);
    // Rendering `length` as the highlighted span would paint 48 bytes over a
    // range the viewer never selected. Never render `length` as a VA span.
    expect(anchorSpan(split)).not.toBe(split.length);
    expect(split.anchor_contiguous).toBe(false);
  });

  it("refuses rather than returning a plausible span when unresolved", () => {
    expect(anchorSpan(region({ anchor_offset: -1, anchor_offset_end: -1 })))
      .toBe(NO_HONEST_ANSWER);
    // Half-resolved is still unresolved: -1 must never be subtracted.
    expect(anchorSpan(region({ anchor_offset: 583560, anchor_offset_end: -1 })))
      .toBe(NO_HONEST_ANSWER);
    expect(anchorSpan(region({ anchor_offset: -1, anchor_offset_end: 583608 })))
      .toBe(NO_HONEST_ANSWER);
  });
});
