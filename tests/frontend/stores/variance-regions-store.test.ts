import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { useVarianceRegionsStore } from "@/stores/variance-regions-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { CHUNK_SIZE } from "@/components/hex/multi-window-utils";
import { BYTES_PER_ROW } from "@/components/hex/window-utils";
import type { ClassRegion, ConsensusRegionsResponse } from "@/api/consensus-regions";

/**
 * The list-and-jump seam of the consensus-regions browser:
 *
 *   selectCategory -> loadMore -> POST /api/analysis/consensus/regions
 *     -> regions[] -> jumpToIndex -> hex-store.scrollToOffset
 *
 * Two failure modes here are silent and both put PLAUSIBLE BYTES IN THE WRONG
 * PLACE — the same class of bug as this session's `---` bands:
 *
 *   1. `requestKey` missing the live `hex-store.viewMode`. A "vas" <-> "va"
 *      switch changes the coordinate `anchor_offset` is expressed in, so a list
 *      that survives the switch serves offsets in the PREVIOUS coordinate and
 *      every jump lands somewhere believable and wrong.
 *   2. Jumping with `slab_start` (or with any client-side adjustment of
 *      `anchor_offset`). The server did the slab -> VA -> navigable conversion
 *      exactly so nothing here has to.
 *
 * Each case below pins one of them.
 */

const CONSENSUS_ID = "cns-1";
const DUMP_A = "/dumps/a.msl";
const DUMP_B = "/dumps/b.msl";

const fetchMock = vi.fn();

// The real hex actions, captured before any test swaps one for a spy.
const realHexActions = {
  scrollToOffset: useHexStore.getState().scrollToOffset,
  startSelection: useHexStore.getState().startSelection,
  extendSelection: useHexStore.getState().extendSelection,
  selectRange: useHexStore.getState().selectRange,
};

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
  regions: ClassRegion[],
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
    anchor: { dump_path: DUMP_A, dump_index: 0, view: "va", jumpable: true },
    classes: ["structural", "pointer", "key_candidate"],
    union: true,
    min_length: 8,
    max_length: 0,
    after: -1,
    next_after: -1,
    total: regions.length,
    returned: regions.length,
    truncated: false,
    counts: { invariant: 8100, structural: 40, pointer: 30, key_candidate: 22 },
    regions,
    ...overrides,
  };
}

/** A Response as `@/api/client`'s `request` consumes it: ok + text(). */
function asResponse(body: ConsensusRegionsResponse): Response {
  return { ok: true, text: async () => JSON.stringify(body) } as unknown as Response;
}

/** One row per slab offset, with a matching anchor offset in the SAME order. */
function rowsAt(slabStarts: number[]): ClassRegion[] {
  return slabStarts.map((slab) =>
    region({
      slab_start: slab,
      slab_end: slab + 48,
      // Deliberately NOT equal to `slab`: a jump that used the slab coordinate
      // by mistake would still look plausible if the two matched.
      anchor_offset: 500000 + slab,
      anchor_offset_end: 500000 + slab + 48,
    }),
  );
}

function requestBodies(): Record<string, unknown>[] {
  return fetchMock.mock.calls.map((call) =>
    JSON.parse(String((call[1] as RequestInit).body)) as Record<string, unknown>,
  );
}

function slabStarts(): number[] {
  return useVarianceRegionsStore.getState().regions.map((r) => r.slab_start);
}

/** Drains the microtask queue behind fetch -> text -> JSON.parse -> set. */
function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/** Seeds a built consensus anchored on `DUMP_A`, viewed in `view`. */
function seedWorkspace(view: "raw" | "vas" | "va" = "va") {
  useConsensusStore.setState({ consensusId: CONSENSUS_ID, builtFrom: [DUMP_A, DUMP_B] });
  useHexStore.setState({ dumpPath: DUMP_A, viewMode: view });
}

/**
 * Injects one loaded chunk into the byte cache, with the server's `variants`
 * reporting a disagreement (`>= 2`) over `[differsFrom, differsTo)` and every
 * one of those bytes classified as POINTER (code 2).
 *
 * `1` outside that range, never `0`: `0` means "no dump is present here",
 * which is a different fact from "every present dump agrees".
 */
function seedLoadedWindow(differsFrom: number, differsTo: number) {
  const identity = `${DUMP_A}|raw|${DUMP_A},${DUMP_B}`;
  const variants = new Uint8Array(CHUNK_SIZE).fill(1);
  const classes = new Int8Array(CHUNK_SIZE).fill(-1);
  for (let i = differsFrom; i < differsTo; i++) {
    variants[i] = 2;
    classes[i] = 2;
  }
  useMultiHexStore.setState({
    identity,
    chunkIdentity: new Map([[0, identity]]),
    variantChunks: new Map([[0, variants]]),
    classChunks: new Map([[0, classes]]),
    lastRequest: {
      anchorPath: DUMP_A,
      view: "raw",
      paths: [DUMP_A, DUMP_B],
      consensusId: CONSENSUS_ID,
    },
  });
}

/**
 * The same loaded window, but with NO server `variants` — the shape an older
 * backend sends, where the disagreement has to be derived from the bytes the
 * panes hold.
 *
 * Worth its own fixture because that fallback is where the "Differs" chip used
 * to freeze the tab: it was walked one offset at a time through `differsAt`,
 * which re-resolved both panes' chunks per byte. It is now one typed-array
 * pass per chunk, and this pins that the answer did not move.
 */
function seedLoadedWindowWithoutServerMask(differsFrom: number, differsTo: number) {
  const identity = `${DUMP_A}|raw|${DUMP_A},${DUMP_B}`;
  const classes = new Int8Array(CHUNK_SIZE).fill(-1);
  const a = new Uint8Array(CHUNK_SIZE).fill(7);
  const b = new Uint8Array(CHUNK_SIZE).fill(7);
  const valid = new Uint8Array(CHUNK_SIZE).fill(1);
  for (let i = differsFrom; i < differsTo; i++) {
    b[i] = 9;
    classes[i] = 2;
  }
  const chunk = (data: Uint8Array) => ({ offset: 0, data, valid, fetchedAt: 1 });
  useMultiHexStore.setState({
    identity,
    chunkIdentity: new Map([[0, identity]]),
    // Deliberately absent: `variantChunks` carries no entry for this chunk.
    variantChunks: new Map(),
    classChunks: new Map([[0, classes]]),
    byPath: new Map([
      [DUMP_A, { chunks: new Map([[0, chunk(a)]]), error: null }],
      [DUMP_B, { chunks: new Map([[0, chunk(b)]]), error: null }],
    ]),
    lastRequest: {
      anchorPath: DUMP_A,
      view: "raw",
      paths: [DUMP_A, DUMP_B],
      consensusId: CONSENSUS_ID,
    },
  });
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  useVarianceRegionsStore.getState().reset();
  useMultiHexStore.getState().reset();
  useDumpStore.setState({ dumps: [] });
  useConsensusStore.setState({ consensusId: null, builtFrom: [] });
  useHexStore.setState({
    dumpPath: null,
    viewMode: "raw",
    cursorOffset: null,
    selection: null,
    scrollTarget: null,
    ...realHexActions,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// Category selection
// ---------------------------------------------------------------------------

describe("selectCategory", () => {
  it("starts idle: no category, no rows, no request", () => {
    const state = useVarianceRegionsStore.getState();

    expect(state.category).toBeNull();
    expect(state.regions).toEqual([]);
    expect(state.requestKey).toBeNull();
    expect(state.activeIndex).toBe(-1);
  });

  it("selects a category without fetching — the effect calls loadMore", () => {
    useVarianceRegionsStore.getState().selectCategory("key_candidate");

    expect(useVarianceRegionsStore.getState().category).toBe("key_candidate");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("null returns to idle and drops the loaded page", async () => {
    seedWorkspace();
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0, 1024]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    useVarianceRegionsStore.getState().selectCategory(null);

    const state = useVarianceRegionsStore.getState();
    expect(state.category).toBeNull();
    expect(state.regions).toEqual([]);
    expect(state.requestKey).toBeNull();
  });

  it("re-selecting the same category keeps the loaded page", async () => {
    seedWorkspace();
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0, 1024]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    // A stray re-render must not discard a page that cost a round trip.
    useVarianceRegionsStore.getState().selectCategory("non_invariant");

    expect(useVarianceRegionsStore.getState().regions).toHaveLength(2);
  });

  it("asks for the NON-INVARIANT UNION, not a class list, for non_invariant", async () => {
    // Measured: a planted 48-byte TLS secret is 27 key_candidate + 18 pointer +
    // 3 structural, and classes=["key_candidate"] with min_length 8 returns
    // total 0. The union alias is the only query that keeps it whole.
    seedWorkspace();
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0]))));

    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    expect(requestBodies()[0].classes).toEqual(["non_invariant"]);
  });

  it("asks for exactly the one class a per-class category names", async () => {
    seedWorkspace();
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0]))));

    useVarianceRegionsStore.getState().selectCategory("pointer");
    await useVarianceRegionsStore.getState().loadMore();

    expect(requestBodies()[0].classes).toEqual(["pointer"]);
  });
});

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

describe("loadMore", () => {
  it("appends the next page with no gaps and no repeats", async () => {
    seedWorkspace();
    fetchMock
      .mockResolvedValueOnce(
        asResponse(pageBody(rowsAt([0, 1024]), { next_after: 1024, total: 4,
          truncated: true })),
      )
      .mockResolvedValueOnce(
        asResponse(pageBody(rowsAt([2048, 3072]), { after: 1024, next_after: -1,
          total: 4 })),
      );

    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    expect(slabStarts()).toEqual([0, 1024]);

    await useVarianceRegionsStore.getState().loadMore();

    expect(slabStarts()).toEqual([0, 1024, 2048, 3072]);
    expect(new Set(slabStarts()).size).toBe(4);
    expect(useVarianceRegionsStore.getState().total).toBe(4);
  });

  it("carries the previous page's next_after as the cursor", async () => {
    seedWorkspace();
    fetchMock
      .mockResolvedValueOnce(
        asResponse(pageBody(rowsAt([0, 1024]), { next_after: 1024, truncated: true })),
      )
      .mockResolvedValueOnce(asResponse(pageBody(rowsAt([2048]), { next_after: -1 })));

    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    await useVarianceRegionsStore.getState().loadMore();

    const bodies = requestBodies();
    expect(bodies[0].after).toBe(-1); // -1 = start, never "offset zero"
    expect(bodies[1].after).toBe(1024);
  });

  it("stops at next_after === -1 and issues no further request", async () => {
    seedWorkspace();
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0, 1024]), {
      next_after: -1 })));

    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    await useVarianceRegionsStore.getState().loadMore();
    await useVarianceRegionsStore.getState().loadMore();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(slabStarts()).toEqual([0, 1024]);
  });

  it("does nothing at all while idle", async () => {
    seedWorkspace();

    await useVarianceRegionsStore.getState().loadMore();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("is silent, not an error, when there is no build and too few dumps", async () => {
    useVarianceRegionsStore.getState().selectCategory("non_invariant");

    await useVarianceRegionsStore.getState().loadMore();

    expect(fetchMock).not.toHaveBeenCalled();
    // "Nothing to ask yet" is not a failure; a banner here would fire on every
    // fresh mount.
    expect(useVarianceRegionsStore.getState().error).toBeNull();
  });

  it("falls back to dump_paths when no consensus is registered", async () => {
    useHexStore.setState({ dumpPath: DUMP_A, viewMode: "va" });
    useMultiHexStore.setState({
      lastRequest: { anchorPath: DUMP_A, view: "va", paths: [DUMP_A, DUMP_B],
        consensusId: null },
    });
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0]))));

    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    const body = requestBodies()[0];
    expect(body.dump_paths).toEqual([DUMP_A, DUMP_B]);
    expect(body).not.toHaveProperty("consensus_id");
  });

  it("records a failure as an error instead of a half-loaded list", async () => {
    seedWorkspace();
    fetchMock.mockResolvedValue({
      ok: false, status: 409, text: async () => "not classified yet",
    } as unknown as Response);

    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    const state = useVarianceRegionsStore.getState();
    expect(state.loading).toBe(false);
    expect(state.error).toContain("not classified");
    expect(state.regions).toEqual([]);
  });

  it("anchors on the hex viewer's dump, in the hex viewer's view", async () => {
    seedWorkspace("vas");
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0]))));

    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    const body = requestBodies()[0];
    expect(body.anchor_path).toBe(DUMP_A);
    expect(body.anchor_view).toBe("vas");
    expect(body.include_anchor_offsets).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// THE INVALIDATION RULE
// ---------------------------------------------------------------------------

describe("requestKey invalidation", () => {
  /**
   * The single most likely way this feature ships broken.
   *
   * `"vas"` and `"va"` are DIFFERENT COORDINATES. A list loaded in one and
   * served in the other hands `scrollToOffset` a number that names a byte —
   * just not the byte the row is about. Nothing downstream can detect that.
   */
  it("throws the page away when hex-store.viewMode changes", async () => {
    seedWorkspace("va");
    fetchMock.mockResolvedValue(
      asResponse(pageBody(rowsAt([0, 1024]), { next_after: 1024, truncated: true })),
    );
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    const keyInVa = useVarianceRegionsStore.getState().requestKey;
    expect(slabStarts()).toEqual([0, 1024]);

    useHexStore.setState({ viewMode: "vas" });
    fetchMock.mockResolvedValue(
      asResponse(pageBody(rowsAt([4096]), { next_after: -1 })),
    );
    await useVarianceRegionsStore.getState().loadMore();

    const state = useVarianceRegionsStore.getState();
    // REPLACED, not appended: the previous rows were in the previous coordinate.
    expect(slabStarts()).toEqual([4096]);
    expect(state.requestKey).not.toBe(keyInVa);
    // And re-asked from the START, because a cursor from the other coordinate
    // is meaningless too.
    expect(requestBodies()[1].after).toBe(-1);
    expect(requestBodies()[1].anchor_view).toBe("vas");
  });

  it("puts the view mode in the key even with everything else identical", async () => {
    seedWorkspace("va");
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    const keyInVa = useVarianceRegionsStore.getState().requestKey;

    useVarianceRegionsStore.getState().reset();
    useHexStore.setState({ viewMode: "vas" });
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    expect(useVarianceRegionsStore.getState().requestKey).not.toBe(keyInVa);
    expect(keyInVa).toContain("va");
  });

  it("also invalidates on a new build, a new anchor and a new min_length", async () => {
    seedWorkspace("va");
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0]))));
    const keyFor = async () => {
      useVarianceRegionsStore.getState().selectCategory(null);
      useVarianceRegionsStore.getState().selectCategory("non_invariant");
      await useVarianceRegionsStore.getState().loadMore();
      return useVarianceRegionsStore.getState().requestKey;
    };

    const base = await keyFor();
    useConsensusStore.setState({ consensusId: "cns-2" });
    const otherBuild = await keyFor();
    useConsensusStore.setState({ consensusId: CONSENSUS_ID });
    useHexStore.setState({ dumpPath: DUMP_B });
    const otherAnchor = await keyFor();
    useHexStore.setState({ dumpPath: DUMP_A });
    useVarianceRegionsStore.getState().setMinLength(32);
    const otherMinLength = await keyFor();

    expect(new Set([base, otherBuild, otherAnchor, otherMinLength]).size).toBe(4);
  });

  it("drops a response that lands after the view changed", async () => {
    seedWorkspace("va");
    let land: (value: Response) => void = () => {};
    fetchMock.mockReturnValueOnce(
      new Promise<Response>((resolve) => {
        land = resolve;
      }),
    );

    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    const inFlight = useVarianceRegionsStore.getState().loadMore();
    useHexStore.setState({ viewMode: "vas" });
    // Re-key without issuing a second request, the way the mounted effect would.
    useVarianceRegionsStore.getState().selectCategory(null);
    land(asResponse(pageBody(rowsAt([0, 1024]))));
    await inFlight;
    await flush();

    // Landing it anyway would paint "va" offsets into a "vas" list.
    expect(useVarianceRegionsStore.getState().regions).toEqual([]);
  });

  it("changing min_length drops the page it was loaded under", async () => {
    seedWorkspace();
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0, 1024]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    useVarianceRegionsStore.getState().setMinLength(64);

    expect(useVarianceRegionsStore.getState().regions).toEqual([]);
    expect(useVarianceRegionsStore.getState().minLength).toBe(64);
  });
});

// ---------------------------------------------------------------------------
// THE COORDINATE-SAFETY TEST
// ---------------------------------------------------------------------------

describe("jumpToIndex", () => {
  async function loadTwoRows() {
    seedWorkspace();
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0, 1024]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
  }

  it("calls scrollToOffset with anchor_offset and NEVER with slab_start", async () => {
    await loadTwoRows();
    const scrollToOffset = vi.fn();
    useHexStore.setState({ scrollToOffset });
    const row = useVarianceRegionsStore.getState().regions[1];

    useVarianceRegionsStore.getState().jumpToIndex(1);

    // The exact argument. The server did the slab -> VA -> navigable
    // conversion so that no client does coordinate arithmetic; any adjustment
    // of this number here is a bug, not a refinement.
    expect(scrollToOffset).toHaveBeenCalledTimes(1);
    expect(scrollToOffset).toHaveBeenCalledWith(row.anchor_offset);
    expect(scrollToOffset).toHaveBeenCalledWith(501024);
    expect(scrollToOffset).not.toHaveBeenCalledWith(row.slab_start);
    expect(scrollToOffset).not.toHaveBeenCalledWith(1024);
    expect(scrollToOffset).not.toHaveBeenCalledWith(row.anchor_va);
  });

  it("moves the real window target to anchor_offset's row", async () => {
    await loadTwoRows();

    useVarianceRegionsStore.getState().jumpToIndex(0);

    const hex = useHexStore.getState();
    // `useHexScrollTarget` honours this and slides the bounded window itself —
    // nothing here touches recenterWindow / setWindowStart.
    expect(hex.scrollTarget).toBe(Math.floor(500000 / BYTES_PER_ROW));
    // …and the CURSOR stays on the byte the jump landed on. It used to follow
    // `extendSelection` to the region's LAST byte — 511 rows below the target
    // row on an 8 KiB run — so `Agreement k/N` and the byte inspector described
    // a byte nowhere near the screen. See `hex-store.selectRange`.
    expect(hex.cursorOffset).toBe(500000);
    expect(useVarianceRegionsStore.getState().activeIndex).toBe(0);
  });

  /**
   * THE CURSOR RULE, both branches.
   *
   * A jump is navigation: the analyst asked to be taken to a region, so the
   * cursor belongs on that region's FIRST byte — the one the scroll target
   * guarantees is on screen. The two branches used to disagree (a contiguous
   * run took a selection and dragged the cursor to its last byte; a
   * slab-only-contiguous run took none and correctly kept the first), which is
   * why both are pinned here rather than just the one that broke.
   */
  it("leaves the cursor on the region's FIRST byte — contiguous run", async () => {
    await loadTwoRows();

    useVarianceRegionsStore.getState().jumpToIndex(0);

    expect(useHexStore.getState().cursorOffset).toBe(500000);
    expect(useHexStore.getState().selection).toEqual({
      anchor: 500000,
      active: 500047,
    });
  });

  it("leaves the cursor on the region's FIRST byte — non-contiguous run", async () => {
    seedWorkspace();
    fetchMock.mockResolvedValue(
      asResponse(
        pageBody([
          region({ anchor_offset: 4064, anchor_offset_end: 8224,
            anchor_contiguous: false }),
        ]),
      ),
    );
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    useVarianceRegionsStore.getState().jumpToIndex(0);

    expect(useHexStore.getState().cursorOffset).toBe(4064);
    expect(useHexStore.getState().selection).toBeNull();
  });

  it("selects [anchor_offset, anchor_offset_end) when the run is contiguous", async () => {
    await loadTwoRows();

    useVarianceRegionsStore.getState().jumpToIndex(0);

    // `selectRange` takes the LAST byte inclusive, hence `- 1`.
    expect(useHexStore.getState().selection).toEqual({
      anchor: 500000,
      active: 500047,
    });
  });

  it("does NOT select a region that is contiguous in slab space only", async () => {
    // `msl_layout` rows are per page, so a 48-byte slab run can be two disjoint
    // runs in the anchor's coordinate. [offset, offset_end) then CONTAINS the
    // region rather than being it, and highlighting it would claim bytes the
    // region does not hold.
    seedWorkspace();
    fetchMock.mockResolvedValue(
      asResponse(
        pageBody([
          region({ anchor_offset: 4064, anchor_offset_end: 8224,
            anchor_contiguous: false }),
        ]),
      ),
    );
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    useVarianceRegionsStore.getState().jumpToIndex(0);

    expect(useHexStore.getState().cursorOffset).toBe(4064);
    expect(useHexStore.getState().selection).toBeNull();
  });

  it("refuses a non-jumpable row without moving the cursor", async () => {
    // A raw/flat build queried in "va", a LOCKED anchor, a slab offset outside
    // msl_layout: all three arrive as -1, and -1 is never 0.
    seedWorkspace();
    fetchMock.mockResolvedValue(
      asResponse(
        pageBody(
          [region({ anchor_va: -1, anchor_offset: -1, anchor_offset_end: -1,
            anchor_contiguous: false })],
          { anchor: { dump_path: DUMP_A, dump_index: 0, view: "va",
            jumpable: false } },
        ),
      ),
    );
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    const scrollToOffset = vi.fn();
    useHexStore.setState({ scrollToOffset, cursorOffset: 4242 });

    useVarianceRegionsStore.getState().jumpToIndex(0);

    expect(scrollToOffset).not.toHaveBeenCalled();
    expect(useHexStore.getState().cursorOffset).toBe(4242);
    expect(useHexStore.getState().selection).toBeNull();
    expect(useVarianceRegionsStore.getState().anchorJumpable).toBe(false);
  });

  it("is a no-op for an index outside the list", async () => {
    await loadTwoRows();
    const scrollToOffset = vi.fn();
    useHexStore.setState({ scrollToOffset });

    useVarianceRegionsStore.getState().jumpToIndex(-1);
    useVarianceRegionsStore.getState().jumpToIndex(2);

    expect(scrollToOffset).not.toHaveBeenCalled();
    expect(useVarianceRegionsStore.getState().activeIndex).toBe(-1);
  });
});

// ---------------------------------------------------------------------------
// Clamping
// ---------------------------------------------------------------------------

describe("jumpNext / jumpPrev", () => {
  async function loadThreeRows() {
    seedWorkspace();
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0, 1024, 2048]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
  }

  it("walks forward from idle and clamps at the last row", async () => {
    await loadThreeRows();
    const store = useVarianceRegionsStore.getState();

    store.jumpNext();
    expect(useVarianceRegionsStore.getState().activeIndex).toBe(0);
    store.jumpNext();
    store.jumpNext();
    expect(useVarianceRegionsStore.getState().activeIndex).toBe(2);

    store.jumpNext();
    store.jumpNext();
    expect(useVarianceRegionsStore.getState().activeIndex).toBe(2);
  });

  it("walks backward and clamps at the first row", async () => {
    await loadThreeRows();
    const store = useVarianceRegionsStore.getState();
    store.jumpToIndex(2);

    store.jumpPrev();
    expect(useVarianceRegionsStore.getState().activeIndex).toBe(1);
    store.jumpPrev();
    store.jumpPrev();
    store.jumpPrev();
    expect(useVarianceRegionsStore.getState().activeIndex).toBe(0);
  });

  it("scrolls to the row it lands on, in anchor coordinates", async () => {
    await loadThreeRows();
    const scrollToOffset = vi.fn();
    useHexStore.setState({ scrollToOffset });

    useVarianceRegionsStore.getState().jumpNext();
    useVarianceRegionsStore.getState().jumpNext();

    expect(scrollToOffset.mock.calls).toEqual([[500000], [501024]]);
  });

  it("does nothing on an empty list", () => {
    useVarianceRegionsStore.getState().selectCategory("non_invariant");

    useVarianceRegionsStore.getState().jumpNext();
    useVarianceRegionsStore.getState().jumpPrev();

    expect(useVarianceRegionsStore.getState().activeIndex).toBe(-1);
  });
});

// ---------------------------------------------------------------------------
// `differs` — the window-scoped category
// ---------------------------------------------------------------------------

describe("the differs category", () => {
  /**
   * There is deliberately NO server-side whole-dump `differs` enumeration: it
   * would cost O(size x N) uncached disk I/O on a synchronous route. So this
   * category is derived from the bytes `multi-hex-store` currently holds, and
   * flags itself as such rather than fabricating a whole-dump total.
   */
  it("never hits the regions endpoint", async () => {
    seedWorkspace("raw");
    seedLoadedWindow(100, 148);

    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("flags itself window-scoped so the UI cannot imply a full total", async () => {
    seedWorkspace("raw");
    seedLoadedWindow(100, 148);

    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();

    const state = useVarianceRegionsStore.getState();
    expect(state.windowScoped).toBe(true);
    expect(state.total).toBe(state.regions.length);
    // There is no next page to ask for, and -1 says exactly that.
    expect(state.nextAfter).toBe(-1);
  });

  it("derives one row per disagreement run, in anchor coordinates", async () => {
    seedWorkspace("raw");
    seedLoadedWindow(100, 148);

    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();

    const rows = useVarianceRegionsStore.getState().regions;
    expect(rows).toHaveLength(1);
    expect(rows[0].anchor_offset).toBe(100);
    expect(rows[0].anchor_offset_end).toBe(148);
    expect(rows[0].length).toBe(48);
    expect(rows[0].anchor_contiguous).toBe(true);
    // The byte cache is indexed in the ANCHOR's coordinate and knows no slab
    // offset and no VA. `-1`, never a plausible 0.
    expect(rows[0].slab_start).toBe(-1);
    expect(rows[0].slab_end).toBe(-1);
    expect(rows[0].anchor_va).toBe(-1);
    expect(rows[0].mean_variance).toBe(-1);
    // The class IS known — it comes from the same loaded window.
    expect(rows[0].classification).toBe("pointer");
  });

  /**
   * The client fallback, for a response that carried no `differs` field at all.
   * Same runs, same class, same coordinates as the server-mask path above.
   */
  it("derives the same runs from the bytes when the server sent no mask", async () => {
    seedWorkspace("raw");
    seedLoadedWindowWithoutServerMask(100, 148);

    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();

    const rows = useVarianceRegionsStore.getState().regions;
    expect(rows).toHaveLength(1);
    expect(rows[0].anchor_offset).toBe(100);
    expect(rows[0].anchor_offset_end).toBe(148);
    expect(rows[0].classification).toBe("pointer");
  });

  /** An absent byte is not a disagreement, however different the stored 0 is. */
  it("does not call a byte only one dump holds a disagreement", async () => {
    seedWorkspace("raw");
    seedLoadedWindowWithoutServerMask(100, 148);
    // Take DUMP_B out of the window entirely: one present dump cannot disagree.
    const state = useMultiHexStore.getState();
    const cache = state.byPath.get(DUMP_B)!;
    const chunk = cache.chunks.get(0)!;
    useMultiHexStore.setState({
      byPath: new Map([
        [DUMP_A, state.byPath.get(DUMP_A)!],
        [
          DUMP_B,
          {
            ...cache,
            chunks: new Map([[0, { ...chunk, valid: new Uint8Array(CHUNK_SIZE) }]]),
          },
        ],
      ]),
    });

    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();

    expect(useVarianceRegionsStore.getState().regions).toEqual([]);
  });

  it("honours min_length", async () => {
    seedWorkspace("raw");
    seedLoadedWindow(100, 104); // a 4-byte run

    useVarianceRegionsStore.getState().setMinLength(8);
    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();

    expect(useVarianceRegionsStore.getState().regions).toEqual([]);
  });

  it("finds nothing when no window is loaded, rather than guessing", async () => {
    seedWorkspace("raw");

    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();

    expect(useVarianceRegionsStore.getState().regions).toEqual([]);
    expect(useVarianceRegionsStore.getState().windowScoped).toBe(true);
  });

  it("jumps like any other row", async () => {
    seedWorkspace("raw");
    seedLoadedWindow(100, 148);
    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();

    useVarianceRegionsStore.getState().jumpToIndex(0);

    expect(useHexStore.getState().scrollTarget).toBe(Math.floor(100 / BYTES_PER_ROW));
    expect(useHexStore.getState().selection).toEqual({ anchor: 100, active: 147 });
  });

  it("recomputes on a later loadMore instead of appending duplicates", async () => {
    seedWorkspace("raw");
    seedLoadedWindow(100, 148);
    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();

    seedLoadedWindow(100, 148);
    await useVarianceRegionsStore.getState().loadMore();

    expect(useVarianceRegionsStore.getState().regions).toHaveLength(1);
  });

  it("clears windowScoped when a server-backed category is selected", async () => {
    seedWorkspace("raw");
    seedLoadedWindow(100, 148);
    useVarianceRegionsStore.getState().selectCategory("differs");
    await useVarianceRegionsStore.getState().loadMore();
    expect(useVarianceRegionsStore.getState().windowScoped).toBe(true);

    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();

    expect(useVarianceRegionsStore.getState().windowScoped).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------

describe("reset", () => {
  it("returns every field to idle", async () => {
    seedWorkspace();
    fetchMock.mockResolvedValue(
      asResponse(pageBody(rowsAt([0, 1024]), { next_after: 1024, total: 9,
        truncated: true })),
    );
    useVarianceRegionsStore.getState().setMinLength(32);
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    useVarianceRegionsStore.getState().jumpToIndex(1);

    useVarianceRegionsStore.getState().reset();

    const state = useVarianceRegionsStore.getState();
    expect(state.category).toBeNull();
    expect(state.regions).toEqual([]);
    expect(state.total).toBe(0);
    expect(state.nextAfter).toBe(-1);
    expect(state.activeIndex).toBe(-1);
    expect(state.loading).toBe(false);
    expect(state.error).toBeNull();
    expect(state.requestKey).toBeNull();
    expect(state.windowScoped).toBe(false);
    expect(state.counts).toEqual({});
    expect(state.anchorJumpable).toBe(false);
    // The min_length knob goes back to the server default too: a reset that
    // left a narrowed floor in place would silently filter the next list.
    expect(state.minLength).toBe(8);
  });

  it("does not touch the hex viewer", async () => {
    seedWorkspace();
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    useVarianceRegionsStore.getState().jumpToIndex(0);

    useVarianceRegionsStore.getState().reset();

    // Closing the browser must not yank the analyst away from the bytes they
    // navigated to.
    expect(useHexStore.getState().scrollTarget).toBe(Math.floor(500000 / BYTES_PER_ROW));
    expect(useHexStore.getState().selection).toEqual({ anchor: 500000, active: 500047 });
  });
});

// ---------------------------------------------------------------------------
// THE CONSENSUS-REBUILD TEST
// ---------------------------------------------------------------------------

/**
 * The `Align: delta-fit │ raw offsets` switch rebuilds the consensus, and a
 * rebuild mints a NEW `consensus_id` in a DIFFERENT coordinate: a `file_offset`
 * build answers no virtual-address question at all, so every `anchor_offset` the
 * previous build produced is meaningless under the new one.
 *
 * This is the same failure as the `"vas"` <-> `"va"` switch above — plausible
 * bytes in the wrong place, invisible to every type check — reached through a
 * different gesture. `requestKey`'s FIRST term is `context.consensusId`, so the
 * store already invalidates here; these cases pin that it keeps doing so,
 * because the switch makes the rebuild a one-click operation rather than
 * something a user does once per session.
 */
describe("a consensus rebuild (the align switch)", () => {
  /** The flat build the raw-offsets option produces: nothing is jumpable. */
  function flatPage(regions: ClassRegion[]): ConsensusRegionsResponse {
    return pageBody(regions, {
      consensus_id: "cns-2",
      coordinate: "flat",
      alignment: {
        method: "file_offset",
        bytes_compared: 1024,
        bytes_discarded: 0,
        sizes_differed: false,
        n_sources: 2,
        warnings: [],
      },
      anchor: { dump_path: DUMP_A, dump_index: 0, view: "va", jumpable: false },
    });
  }

  it("replaces the page rather than appending the new build's rows to it", async () => {
    seedWorkspace("va");
    fetchMock.mockResolvedValue(
      asResponse(pageBody(rowsAt([0, 1024]), { next_after: 1024, truncated: true })),
    );
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    const keyBefore = useVarianceRegionsStore.getState().requestKey;
    expect(slabStarts()).toEqual([0, 1024]);

    // What `runConsensus` does when the switch flips: a new id for a build in
    // the other coordinate.
    useConsensusStore.setState({ consensusId: "cns-2", builtFrom: [DUMP_A, DUMP_B] });
    fetchMock.mockResolvedValue(asResponse(flatPage(rowsAt([4096]))));
    await useVarianceRegionsStore.getState().loadMore();

    const state = useVarianceRegionsStore.getState();
    expect(slabStarts()).toEqual([4096]);
    expect(state.requestKey).not.toBe(keyBefore);
    // Re-asked from the START: the previous build's cursor names nothing here.
    expect(requestBodies()[1].after).toBe(-1);
    expect(requestBodies()[1].consensus_id).toBe("cns-2");
  });

  it("stops offering the jump when the new build cannot answer in this view", async () => {
    seedWorkspace("va");
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    expect(useVarianceRegionsStore.getState().anchorJumpable).toBe(true);

    useConsensusStore.setState({ consensusId: "cns-2" });
    fetchMock.mockResolvedValue(asResponse(flatPage(rowsAt([4096]))));
    await useVarianceRegionsStore.getState().loadMore();

    // A flat build in a `"va"` view is the `anchorJumpable === false` case the
    // browser renders its `regions.noJump` warning for.
    expect(useVarianceRegionsStore.getState().anchorJumpable).toBe(false);
  });

  it("drops the old build's rows the moment the request re-keys, not when it lands", async () => {
    seedWorkspace("va");
    fetchMock.mockResolvedValue(asResponse(pageBody(rowsAt([0, 1024]))));
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    await useVarianceRegionsStore.getState().loadMore();
    expect(slabStarts()).toEqual([0, 1024]);

    useConsensusStore.setState({ consensusId: "cns-2" });
    let land: (value: Response) => void = () => {};
    fetchMock.mockReturnValueOnce(
      new Promise<Response>((resolve) => {
        land = resolve;
      }),
    );
    const inFlight = useVarianceRegionsStore.getState().loadMore();

    // IN FLIGHT: the previous build's rows are already gone, and nothing is
    // offered as jumpable, because they are expressed in a coordinate the
    // viewer has left. Keeping them "until the answer lands" is the bug.
    expect(useVarianceRegionsStore.getState().regions).toEqual([]);
    expect(useVarianceRegionsStore.getState().anchorJumpable).toBe(false);
    expect(useVarianceRegionsStore.getState().loading).toBe(true);

    land(asResponse(flatPage(rowsAt([4096]))));
    await inFlight;
    await flush();
    expect(slabStarts()).toEqual([4096]);
  });

  it("discards a response from the OLD build that lands after the rebuild", async () => {
    seedWorkspace("va");
    let land: (value: Response) => void = () => {};
    fetchMock.mockReturnValueOnce(
      new Promise<Response>((resolve) => {
        land = resolve;
      }),
    );
    useVarianceRegionsStore.getState().selectCategory("non_invariant");
    const inFlight = useVarianceRegionsStore.getState().loadMore();

    // The switch is flipped while page one of the previous build is in flight;
    // the mounted loader re-keys without issuing a second request yet.
    useConsensusStore.setState({ consensusId: "cns-2" });
    useVarianceRegionsStore.getState().selectCategory(null);
    land(asResponse(pageBody(rowsAt([0, 1024]))));
    await inFlight;
    await flush();

    // Landing it anyway would serve the previous build's offsets under the new
    // one — the aligned-coordinate form of the `"vas"`/`"va"` bug.
    expect(useVarianceRegionsStore.getState().regions).toEqual([]);
  });
});
