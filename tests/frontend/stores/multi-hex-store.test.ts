import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { MAX_CHUNK_RETRIES, useMultiHexStore } from "@/stores/multi-hex-store";
import { useDumpStore } from "@/stores/dump-store";
import { CHUNK_SIZE } from "@/components/hex/multi-window-utils";
import type { AlignedWindowResponse } from "@/api/aligned-window";

/**
 * The byte-cache seam of the N-pane hex viewer:
 *
 *   pane visible-range effect -> ensureLoaded
 *     -> POST /api/analysis/consensus/aligned-window
 *       -> byPath / classChunks -> getByteAt / isPresentAt / getClassAt / differsAt
 *
 * Every byte the user sees in every pane comes through here, and the failure
 * modes are all silent: a response landing in the wrong pane, a previous
 * selection's classes being served under a new one, an absent byte counted as
 * a difference. Each case below pins one of them.
 */

const DUMP_A = "/dumps/a.msl";
const DUMP_B = "/dumps/b.msl";
const DUMP_C = "/dumps/c.msl";

function toBase64(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes));
}

interface DumpSpec {
  path: string;
  bytes?: number[] | null;
  valid?: [number, number][];
  hint?: string | null;
}

/** Is window index `i` inside one of `runs`? */
function inRuns(runs: [number, number][], i: number): boolean {
  return runs.some(([start, run]) => i >= start && i < start + run);
}

/**
 * `variants` exactly as the backend defines it.
 *
 *   variants[i] = how many DISTINCT values the PRESENT dumps hold at i
 *
 * Which is ALSO the disagreement answer — an index differs iff
 * `variants[i] >= 2` — because two or more distinct values requires two or
 * more present dumps, so a byte only one dump holds is never a difference. The
 * response used to carry that predicate a second time as a boolean `differs`
 * run list; this fixture derived both from the same specs, and now derives the
 * one field that is left.
 */
function crossDumpFindings(
  dumps: DumpSpec[],
  length: number,
): { variants: number[] } {
  const variants: number[] = [];
  for (let i = 0; i < length; i++) {
    const values = new Set<number>();
    for (const spec of dumps) {
      if (spec.bytes === null) continue;
      const bytes = spec.bytes ?? new Array<number>(length).fill(0);
      const valid = spec.valid ?? ([[0, length]] as [number, number][]);
      if (!inRuns(valid, i)) continue;
      values.add(bytes[i] ?? 0);
    }
    variants.push(values.size);
  }
  return { variants };
}

function windowBody(
  dumps: DumpSpec[],
  classes: number[],
  overrides: Partial<AlignedWindowResponse> = {},
): AlignedWindowResponse {
  const length = classes.length;
  return {
    consensus_id: null,
    classified: true,
    alignment: {
      method: "module_offset",
      bytes_compared: length,
      bytes_discarded: 0,
      sizes_differed: false,
      n_sources: dumps.length,
      warnings: [],
    },
    anchor: {
      kind: "dump",
      dump_path: dumps[0]?.path ?? null,
      dump_index: 0,
      view: "raw",
      offset: 0,
      va: 0,
      va_span_start: 0,
      slab_offset: 0,
    },
    requested_length: length,
    length,
    truncated: false,
    classes,
    // The server's cross-dump findings, DERIVED from the same specs as the
    // bytes so the fixture cannot describe a window that could not exist —
    // `variants` claiming a disagreement the bytes do not show would test the
    // store against a response the backend never sends.
    ...crossDumpFindings(dumps, length),
    gaps: [],
    segments: [],
    dumps: dumps.map((spec, index) => ({
      dump_index: index,
      dump_path: spec.path,
      format: "msl",
      view: "raw",
      bytes: spec.bytes === null ? null : toBase64(spec.bytes ?? new Array(length).fill(0)),
      bytes_valid: spec.valid ?? ([[0, length]] as [number, number][]),
      key_status: {
        decrypted: spec.bytes !== null,
        hint: spec.hint ?? null,
        // Third field the backend actually ships alongside `decrypted`.
        tag_status: spec.bytes !== null ? ("not_encrypted" as const) : ("missing_key" as const),
      },
    })),
    ...overrides,
  };
}

/** A Response as `@/api/client`'s `request` consumes it: ok + text(). */
function asResponse(body: AlignedWindowResponse): Response {
  return {
    ok: true,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

function windowResponse(dumps: DumpSpec[], classes: number[]): Response {
  return asResponse(windowBody(dumps, classes));
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

function never(): Promise<Response> {
  return new Promise(() => {});
}

/** Drains the microtask queue behind fetch -> text -> JSON.parse -> set. */
function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * `flush` for a test running on fake timers, optionally after `ms` of them.
 *
 * The plain `flush` above never resolves under `vi.useFakeTimers()` — its own
 * `setTimeout` is one of the timers being faked — and the retry backoff can
 * only be observed by moving fake time, so the retry tests need both halves:
 * advance the clock, then let the promise chain behind `fetch` settle.
 */
async function settle(ms = 0): Promise<void> {
  await vi.advanceTimersByTimeAsync(ms);
  await vi.advanceTimersByTimeAsync(0);
}

const fetchMock = vi.fn();

/** Loads row 0 only, with `prefetch = 0` panes-worth of margin where possible. */
function load(paths: string[], startRow = 0, endRow = 0, consensusId: string | null = null) {
  useMultiHexStore.getState().ensureLoaded({
    anchorPath: paths[0],
    view: "raw",
    paths,
    startRow,
    endRow,
    consensusId,
  });
}

function requestBodies(): Record<string, unknown>[] {
  return fetchMock.mock.calls.map((call) =>
    JSON.parse(String((call[1] as RequestInit).body)) as Record<string, unknown>,
  );
}

/**
 * How many requests asked for `offset`. Each `ensureLoaded` fans out over the
 * visible chunk PLUS the pane-count-dependent prefetch margin, so counting all
 * calls would measure the margin rather than the cache decision under test.
 */
function callsForOffset(offset: number): number {
  return requestBodies().filter((body) => body.offset === offset).length;
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  useMultiHexStore.getState().reset();
  useDumpStore.setState({ dumps: [] });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("per-path isolation", () => {
  it("routes each dump's bytes to its OWN pane, by path and not by position", async () => {
    // The response deliberately lists B FIRST. Indexing `dumps[]` positionally
    // (or reusing the request order) would render A's pane with B's bytes --
    // wrong bytes under a correct-looking label, which nothing downstream can
    // detect.
    fetchMock.mockResolvedValue(
      asResponse(
        windowBody(
          [
            { path: DUMP_B, bytes: [0xbb, 0xbb, 0xbb, 0xbb] },
            { path: DUMP_A, bytes: [0xaa, 0xaa, 0xaa, 0xaa] },
          ],
          [0, 0, 0, 0],
        ),
      ),
    );

    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.getByteAt(DUMP_A, 0)).toBe(0xaa);
    expect(state.getByteAt(DUMP_A, 3)).toBe(0xaa);
    expect(state.getByteAt(DUMP_B, 0)).toBe(0xbb);
    expect(state.getByteAt(DUMP_B, 3)).toBe(0xbb);
  });

  it("never invents a pane for a dump the response did not carry", async () => {
    fetchMock.mockResolvedValue(
      windowResponse([{ path: DUMP_A, bytes: [1, 2] }], [0, 0]),
    );

    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.byPath.has(DUMP_B)).toBe(false);
    expect(state.getByteAt(DUMP_B, 0)).toBeUndefined();
    expect(state.isPresentAt(DUMP_B, 0)).toBe(false);
  });
});

describe("cache key", () => {
  it("invalidates when the SELECTION changes, same anchor + view + offset", async () => {
    fetchMock.mockResolvedValueOnce(
      windowResponse(
        [
          { path: DUMP_A, bytes: [0x11, 0x11] },
          { path: DUMP_B, bytes: [0x11, 0x11] },
        ],
        [0, 0],
      ),
    );

    fetchMock.mockReturnValue(never());
    load([DUMP_A, DUMP_B]);
    await flush();
    expect(callsForOffset(0)).toBe(1);
    expect(useMultiHexStore.getState().getClassAt(0)).toBe(0);

    // Same anchor, same view, same rows -- ONLY the selected set moved. The
    // classes are computed across the whole set, so they cannot be reused.
    const pending = createDeferred<Response>();
    fetchMock.mockReset();
    fetchMock.mockReturnValueOnce(pending.promise);
    fetchMock.mockReturnValue(never());
    load([DUMP_A, DUMP_B, DUMP_C]);

    expect(callsForOffset(0)).toBe(1);
    // The previous selection's classes and bytes must NOT be served while the
    // new selection's window is still in flight.
    expect(useMultiHexStore.getState().getClassAt(0)).toBeUndefined();
    expect(useMultiHexStore.getState().getByteAt(DUMP_A, 0)).toBeUndefined();

    pending.resolve(
      windowResponse(
        [
          { path: DUMP_A, bytes: [0x11, 0x11] },
          { path: DUMP_B, bytes: [0x11, 0x11] },
          { path: DUMP_C, bytes: [0x99, 0x99] },
        ],
        [3, 3],
      ),
    );
    await flush();

    expect(useMultiHexStore.getState().getClassAt(0)).toBe(3);
    expect(useMultiHexStore.getState().getByteAt(DUMP_C, 0)).toBe(0x99);
  });

  it("re-fetches when the view changes", async () => {
    fetchMock.mockResolvedValue(windowResponse([{ path: DUMP_A, bytes: [1] }], [0]));

    load([DUMP_A]);
    await flush();
    useMultiHexStore.getState().ensureLoaded({
      anchorPath: DUMP_A,
      view: "vas",
      paths: [DUMP_A],
      startRow: 0,
      endRow: 0,
      consensusId: null,
    });
    await flush();

    // Every request of the first pass asked for "raw", every request of the
    // second for "vas" -- the count itself is the prefetch margin, not a
    // cache decision.
    const views = requestBodies().map((body) => body.view);
    expect([...new Set(views)]).toEqual(["raw", "vas"]);
    expect(callsForOffset(0)).toBe(2);
  });

  it("does not re-fetch a chunk it already holds for the same selection", async () => {
    fetchMock.mockResolvedValue(
      windowResponse([{ path: DUMP_A, bytes: [1] }, { path: DUMP_B, bytes: [2] }], [0]),
    );

    load([DUMP_A, DUMP_B]);
    await flush();
    const first = fetchMock.mock.calls.length;

    load([DUMP_A, DUMP_B]);
    await flush();

    expect(fetchMock).toHaveBeenCalledTimes(first);
  });
});

describe("in-flight dedupe", () => {
  it("issues ONE fetch for two overlapping ensureLoaded calls", async () => {
    fetchMock.mockReturnValue(never());

    load([DUMP_A, DUMP_B, DUMP_C, DUMP_A + "2", DUMP_B + "2", DUMP_C + "2"]);
    const afterFirst = fetchMock.mock.calls.length;
    load([DUMP_A, DUMP_B, DUMP_C, DUMP_A + "2", DUMP_B + "2", DUMP_C + "2"]);

    // Six panes => prefetch margin 0 => exactly one chunk, fetched once.
    expect(afterFirst).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(useMultiHexStore.getState().pending.size).toBe(1);
  });
});

describe("shared byte budget", () => {
  it("evicts oldest-first ACROSS panes, not per pane", async () => {
    // Two panes => prefetch 2 => chunks 0, 8192, 16384 for row 0.
    fetchMock.mockImplementation((_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as { offset: number };
      const fill = (body.offset >> 8) & 0xff;
      return Promise.resolve(
        windowResponse(
          [
            { path: DUMP_A, bytes: [fill, fill, fill, fill] },
            { path: DUMP_B, bytes: [fill, fill, fill, fill] },
          ],
          [0, 0, 0, 0],
        ),
      );
    });
    // Each pane-chunk costs data(4) + mask(4) = 8 bytes, so two panes cost 16
    // per chunk offset. The two per-offset WINDOW arrays -- classes(4) and
    // variants(4) -- cost 8 more, once per offset rather than once per pane,
    // for 24 bytes per offset and 72 across the three. A 28-byte budget is
    // therefore room for exactly one offset, and keeps the newest.
    useMultiHexStore.setState({ budgetBytes: 28 });

    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(fetchMock).toHaveBeenCalledTimes(3);
    // A per-pane cap would have kept all three chunks in BOTH panes.
    expect(state.byPath.get(DUMP_A)!.chunks.size).toBe(1);
    expect(state.byPath.get(DUMP_B)!.chunks.size).toBe(1);
    expect([...state.byPath.get(DUMP_A)!.chunks.keys()]).toEqual([2 * CHUNK_SIZE]);
    expect([...state.byPath.get(DUMP_B)!.chunks.keys()]).toEqual([2 * CHUNK_SIZE]);
    // Class chunks for evicted offsets go with them.
    expect([...state.classChunks.keys()]).toEqual([2 * CHUNK_SIZE]);
  });

  /**
   * The window arrays are HELD, so they must be CHARGED.
   *
   * `chunkCost` used to sum `data + valid` only, which left `classes` and
   * `variants` -- 16,384 bytes per retained offset at the real 8 KiB chunk
   * size -- inside the cache but outside the budget. The ceiling the store
   * documents was then well under what the tab actually held.
   *
   * Sized so the pane bytes ALONE fit and the window arrays are what tips it:
   * two offsets x two panes x 8 = 32 pane bytes, plus 2 x 8 = 16 window bytes.
   * A 36-byte budget is under the true 48 and over the pane-only 32, so an
   * eviction here can only be the window arrays being counted.
   */
  it("charges the per-offset window arrays against the budget", async () => {
    fetchMock.mockImplementation((_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as { offset: number };
      const fill = (body.offset >> 8) & 0xff;
      return Promise.resolve(
        windowResponse(
          [
            { path: DUMP_A, bytes: [fill, fill, fill, fill] },
            { path: DUMP_B, bytes: [fill, fill, fill, fill] },
          ],
          [0, 0, 0, 0],
        ),
      );
    });
    useMultiHexStore.setState({ budgetBytes: 36 });

    // Two panes => prefetch 2 => three chunk offsets.
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    // 72 total against 36: the two oldest offsets go, the newest stays.
    expect([...state.byPath.get(DUMP_A)!.chunks.keys()]).toEqual([2 * CHUNK_SIZE]);
    expect([...state.classChunks.keys()]).toEqual([2 * CHUNK_SIZE]);
    expect([...state.variantChunks.keys()]).toEqual([2 * CHUNK_SIZE]);
  });

  /**
   * Narrowing the element types is only free if the VALUES survive it.
   * `classes` carries the `-1` gap sentinel, which an unsigned array would
   * turn into 255 -- a code that reads as a class rather than as a gap.
   */
  it("keeps the class gap sentinel and the variant counts through the narrower arrays", async () => {
    fetchMock.mockResolvedValue(
      asResponse(
        windowBody(
          [
            { path: DUMP_A, bytes: [5, 9, 0], valid: [[0, 2]] },
            { path: DUMP_B, bytes: [5, 7, 0], valid: [[0, 2]] },
          ],
          [-1, 3, 0],
        ),
      ),
    );
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.classChunks.get(0)).toBeInstanceOf(Int8Array);
    expect(state.variantChunks.get(0)).toBeInstanceOf(Uint8Array);
    // -1 is a gap, not class 255.
    expect(state.getClassAt(0)).toBeUndefined();
    expect(state.getClassAt(1)).toBe(3);
    expect(state.variantsAt(0)).toBe(1);
    expect(state.variantsAt(1)).toBe(2);
  });
});

describe("releasePaths", () => {
  it("frees deselected dumps and their repaint counters", async () => {
    fetchMock.mockResolvedValue(
      windowResponse([{ path: DUMP_A, bytes: [1] }, { path: DUMP_B, bytes: [2] }], [0]),
    );

    load([DUMP_A, DUMP_B]);
    await flush();
    expect(useMultiHexStore.getState().byPath.size).toBe(2);

    useMultiHexStore.getState().releasePaths([DUMP_A]);

    const state = useMultiHexStore.getState();
    expect([...state.byPath.keys()]).toEqual([DUMP_A]);
    expect([...state.chunkVersionByPath.keys()]).toEqual([DUMP_A]);
    expect(state.getByteAt(DUMP_B, 0)).toBeUndefined();
    expect(state.getByteAt(DUMP_A, 0)).toBe(1);
  });

  it("drops every pane when nothing is kept", async () => {
    fetchMock.mockResolvedValue(windowResponse([{ path: DUMP_A, bytes: [1] }], [0]));
    load([DUMP_A]);
    await flush();

    useMultiHexStore.getState().releasePaths([]);

    expect(useMultiHexStore.getState().byPath.size).toBe(0);
    expect(useMultiHexStore.getState().classChunks.size).toBe(0);
  });
});

describe("stale-response guard", () => {
  it("drops a response whose selection changed mid-flight", async () => {
    const pending = createDeferred<Response>();
    fetchMock.mockReturnValueOnce(pending.promise);
    fetchMock.mockReturnValue(never());

    load([DUMP_A, DUMP_B]);
    // The user adds a third dump while the first window is still in flight.
    load([DUMP_A, DUMP_B, DUMP_C]);
    const pendingBefore = useMultiHexStore.getState().pending.size;
    pending.resolve(
      windowResponse(
        [{ path: DUMP_A, bytes: [0xaa] }, { path: DUMP_B, bytes: [0xbb] }],
        [0],
      ),
    );
    await flush();

    const state = useMultiHexStore.getState();
    // The two-dump alignment must not be painted under a three-dump selection.
    expect(state.getByteAt(DUMP_A, 0)).toBeUndefined();
    expect(state.getClassAt(0)).toBeUndefined();
    expect(state.byPath.size).toBe(0);
    // The dropped response still retires its own in-flight key -- and only its
    // own, so the live selection's fetches stay pending.
    expect(state.pending.size).toBe(pendingBefore - 1);
  });
});

describe("differsAt", () => {
  async function loadPair(specs: DumpSpec[], classes: number[]) {
    fetchMock.mockResolvedValue(windowResponse(specs, classes));
    load(specs.map((s) => s.path));
    await flush();
  }

  it("is false when only one dump is present at the offset", async () => {
    await loadPair(
      [
        { path: DUMP_A, bytes: [0x01, 0x02], valid: [[0, 2]] },
        { path: DUMP_B, bytes: [0x00, 0x02], valid: [[1, 1]] },
      ],
      [0, 0],
    );

    expect(useMultiHexStore.getState().differsAt(0)).toBe(false);
  });

  it("is false when all present bytes are equal", async () => {
    await loadPair(
      [
        { path: DUMP_A, bytes: [0x42] },
        { path: DUMP_B, bytes: [0x42] },
      ],
      [0],
    );

    expect(useMultiHexStore.getState().differsAt(0)).toBe(false);
  });

  it("is true when two PRESENT dumps disagree", async () => {
    await loadPair(
      [
        { path: DUMP_A, bytes: [0x42] },
        { path: DUMP_B, bytes: [0x43] },
      ],
      [3],
    );

    expect(useMultiHexStore.getState().differsAt(0)).toBe(true);
  });

  it("is FALSE when the only disagreement is a present byte vs an absent one", async () => {
    // B holds 0x00 at index 0 purely because the backend zero-fills a gap.
    // Counting that as a difference would flag every unmapped hole in every
    // dump and fill the screen with false positives.
    await loadPair(
      [
        { path: DUMP_A, bytes: [0x42], valid: [[0, 1]] },
        { path: DUMP_B, bytes: [0x00], valid: [] },
      ],
      [-1],
    );

    expect(useMultiHexStore.getState().differsAt(0)).toBe(false);
  });

  it("is false where nothing is loaded", () => {
    expect(useMultiHexStore.getState().differsAt(0)).toBe(false);
  });
});

describe("getClassAt", () => {
  it("returns undefined for -1 and the real class otherwise", async () => {
    fetchMock.mockResolvedValue(
      windowResponse([{ path: DUMP_A, bytes: [1, 2, 3] }], [0, -1, 2]),
    );

    load([DUMP_A]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.getClassAt(0)).toBe(0);
    // -1 is "gap / unclassified". Returning 0 (INVARIANT) here would claim
    // every dump agrees about a byte no dump holds.
    expect(state.getClassAt(1)).toBeUndefined();
    expect(state.getClassAt(2)).toBe(2);
    // Past the window entirely.
    expect(state.getClassAt(9)).toBeUndefined();
  });
});

describe("isPresentAt", () => {
  it("honours bytes_valid: a genuine 0x00 inside a run is PRESENT", async () => {
    fetchMock.mockResolvedValue(
      windowResponse(
        [{ path: DUMP_A, bytes: [0x00, 0x00, 0x00], valid: [[0, 2]] }],
        [0, 0, -1],
      ),
    );

    load([DUMP_A]);
    await flush();

    const state = useMultiHexStore.getState();
    // Identical byte VALUES; only the mask separates them.
    expect(state.getByteAt(DUMP_A, 0)).toBe(0x00);
    expect(state.getByteAt(DUMP_A, 2)).toBe(0x00);
    expect(state.isPresentAt(DUMP_A, 0)).toBe(true);
    expect(state.isPresentAt(DUMP_A, 1)).toBe(true);
    expect(state.isPresentAt(DUMP_A, 2)).toBe(false);
  });

  it("treats a locked dump as entirely absent", async () => {
    fetchMock.mockResolvedValue(
      windowResponse(
        [{ path: DUMP_A, bytes: null, valid: [[0, 2]], hint: "passphrase required" }],
        [0, 0],
      ),
    );

    load([DUMP_A]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.isPresentAt(DUMP_A, 0)).toBe(false);
    expect(state.byPath.get(DUMP_A)!.error).toBe("passphrase required");
  });
});

describe("key material", () => {
  it("sends keys only for dumps that actually hold a secret", async () => {
    useDumpStore.setState({
      dumps: [
        {
          id: "a",
          path: DUMP_A,
          name: "a",
          size: 1,
          format: "msl",
          sameProcess: false,
          keyMaterial: { passphrase: "hunter2" },
        },
        {
          id: "b",
          path: DUMP_B,
          name: "b",
          size: 1,
          format: "msl",
          sameProcess: false,
          keyMaterial: {},
        },
      ],
    });
    fetchMock.mockReturnValue(never());

    load([DUMP_A, DUMP_B]);

    const body = requestBodies()[0];
    expect(body.keys).toEqual([{ dump_path: DUMP_A, passphrase: "hunter2" }]);
  });
});

describe("error capture", () => {
  /**
   * One aligned-window request carries EVERY selected pane, so its failure is
   * a fact about a WINDOW, not about a dump. Writing it into each pane's cache
   * is what made a single out-of-range look-ahead chunk paint
   * "Could not load run_1.msl: {…}" over panes whose visible bytes had already
   * arrived and were correct.
   */
  it("records the failure against the chunk, never against the panes", async () => {
    fetchMock.mockResolvedValue(
      windowResponse([{ path: DUMP_A, bytes: [1] }, { path: DUMP_C, bytes: [1] }], [0]),
    );
    load([DUMP_A, DUMP_C]);
    await flush();
    expect(useMultiHexStore.getState().byPath.get(DUMP_C)!.error).toBeNull();

    fetchMock.mockRejectedValue(new Error("aligned-window 500"));
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.getChunkError(0)).toBe("aligned-window 500");
    // No pane is blamed for a window that failed for all of them.
    expect(state.byPath.get(DUMP_A)?.error ?? null).toBeNull();
    expect(state.byPath.get(DUMP_B)?.error ?? null).toBeNull();
    expect(state.byPath.get(DUMP_C)!.error).toBeNull();
    expect(state.pending.size).toBe(0);
  });

  it("leaves the bytes a pane already holds readable after a failed chunk", async () => {
    fetchMock.mockResolvedValue(windowResponse([{ path: DUMP_A, bytes: [7] }], [0]));
    load([DUMP_A]);
    await flush();

    fetchMock.mockReset();
    fetchMock.mockRejectedValue(new Error("boom"));
    // Scroll on: the first load's own prefetch already covered chunks 0..16384,
    // so the only chunk this asks for — and the only one that can fail — is
    // 24576.
    load([DUMP_A], 512, 512);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.getChunkError(3 * CHUNK_SIZE)).toBe("boom");
    // The window the user is looking at is untouched.
    expect(state.getChunkError(0)).toBeNull();
    expect(state.getByteAt(DUMP_A, 0)).toBe(7);
    expect(state.byPath.get(DUMP_A)!.error).toBeNull();
  });

  it("clears the chunk error once a retry of that window arrives", async () => {
    // NOTE: this used to drive the second attempt with a plain `load()`,
    // which pinned the very bug this suite now guards against — `ensureLoaded`
    // refetching a failed chunk forever. `retryChunkAt` is the way back.
    fetchMock.mockRejectedValue(new Error("boom"));
    load([DUMP_A]);
    await flush();
    expect(useMultiHexStore.getState().getChunkError(0)).toBe("boom");

    fetchMock.mockReset();
    fetchMock.mockResolvedValue(windowResponse([{ path: DUMP_A, bytes: [7] }], [0]));
    useMultiHexStore.getState().retryChunkAt(0);
    await flush();

    expect(useMultiHexStore.getState().getChunkError(0)).toBeNull();
    expect(useMultiHexStore.getState().getByteAt(DUMP_A, 0)).toBe(7);
  });

  /**
   * The anti-storm property, pinned by an EXACT count.
   *
   * The reported storm: one unreachable dump produced a dozen identical POSTs,
   * because the virtualizer re-runs `ensureLoaded` on every row change and the
   * `needed` filter never consulted `chunkErrors`. A permanent latch stopped
   * it and created a dead end instead — a band of `--` nothing ever retried.
   * The contract is now BOUNDED: 1 + MAX_CHUNK_RETRIES requests per chunk per
   * identity, on a 1s / 4s backoff, and any number of `ensureLoaded` calls in
   * between add exactly nothing.
   */
  it("retries a failed chunk twice on a backoff, then latches, whatever ensureLoaded does", async () => {
    vi.useFakeTimers();
    try {
      fetchMock.mockRejectedValue(new Error("boom"));
      load([DUMP_A]);
      await settle();
      expect(callsForOffset(0)).toBe(1);

      // Eight scroll ticks inside the first backoff window: still one request.
      for (let i = 0; i < 8; i++) {
        load([DUMP_A]);
        await settle();
      }
      expect(callsForOffset(0)).toBe(1);

      await settle(1000);
      expect(callsForOffset(0)).toBe(2);
      for (let i = 0; i < 8; i++) {
        load([DUMP_A]);
        await settle();
      }
      expect(callsForOffset(0)).toBe(2);

      await settle(4000);
      expect(callsForOffset(0)).toBe(3);

      // Budget spent. No backoff, however long, and no amount of scrolling
      // buys a fourth request.
      await settle(60_000);
      for (let i = 0; i < 8; i++) {
        load([DUMP_A]);
        await settle();
      }
      expect(callsForOffset(0)).toBe(3);

      const failure = useMultiHexStore.getState().getChunkFailure(0);
      expect(failure?.attempts).toBe(MAX_CHUNK_RETRIES);
      expect(failure?.message).toBe("boom");
    } finally {
      useMultiHexStore.getState().reset();
      vi.useRealTimers();
    }
  });

  it("resets the retry budget for a user gesture — a human asking is not a retry", async () => {
    vi.useFakeTimers();
    try {
      fetchMock.mockRejectedValue(new Error("boom"));
      load([DUMP_A]);
      await settle();
      await settle(1000);
      await settle(4000);
      expect(callsForOffset(0)).toBe(3);
      expect(useMultiHexStore.getState().getChunkFailure(0)?.attempts).toBe(2);

      useMultiHexStore.getState().retryChunkAt(0);
      await settle();
      expect(callsForOffset(0)).toBe(4);
      // Failed again, but from a clean budget: the auto-retries are back.
      expect(useMultiHexStore.getState().getChunkFailure(0)?.attempts).toBe(0);
      await settle(1000);
      expect(callsForOffset(0)).toBe(5);
    } finally {
      useMultiHexStore.getState().reset();
      vi.useRealTimers();
    }
  });

  it("clears the failure when the scheduled retry lands", async () => {
    vi.useFakeTimers();
    try {
      fetchMock.mockRejectedValue(new Error("boom"));
      load([DUMP_A]);
      await settle();
      expect(useMultiHexStore.getState().getChunkError(0)).toBe("boom");

      fetchMock.mockReset();
      fetchMock.mockResolvedValue(windowResponse([{ path: DUMP_A, bytes: [7] }], [0]));
      await settle(1000);

      const state = useMultiHexStore.getState();
      expect(state.getChunkError(0)).toBeNull();
      expect(state.getChunkFailure(0)).toBeNull();
      expect(state.getByteAt(DUMP_A, 0)).toBe(7);
    } finally {
      useMultiHexStore.getState().reset();
      vi.useRealTimers();
    }
  });

  /**
   * A nudge scheduled under one selection must never fire under the next one:
   * the window it names was aligned over other dumps, so landing it would
   * paint the previous selection's bytes under the current one.
   */
  it("drops a scheduled retry when the selection changes under it", async () => {
    vi.useFakeTimers();
    try {
      fetchMock.mockRejectedValue(new Error("boom"));
      load([DUMP_A]);
      await settle();

      fetchMock.mockReset();
      fetchMock.mockReturnValue(never());
      load([DUMP_A, DUMP_B]);
      await settle();
      const afterSwitch = callsForOffset(0);

      await settle(60_000);
      expect(callsForOffset(0)).toBe(afterSwitch);
    } finally {
      useMultiHexStore.getState().reset();
      vi.useRealTimers();
    }
  });

  /**
   * The banner used to inspect the FIRST and LAST visible row's chunk only, so
   * a failure anywhere between them showed nothing at all — just a band of
   * `--` in the middle of the grid with no way to retry it.
   */
  it("reports a failure in the MIDDLE of a range, not only at its ends", async () => {
    fetchMock.mockImplementation((_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as { offset: number };
      if (body.offset === CHUNK_SIZE) return Promise.reject(new Error("middle chunk failed"));
      return Promise.resolve(windowResponse([{ path: DUMP_A, bytes: [1] }], [0]));
    });
    // One pane prefetches 2 chunks each side, so this covers 0, 8192, 16384.
    load([DUMP_A]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.getChunkError(0)).toBeNull();
    expect(state.getChunkError(2 * CHUNK_SIZE)).toBeNull();
    expect(state.getChunkErrorsInRange(0, 3 * CHUNK_SIZE - 1)).toEqual([
      { offset: CHUNK_SIZE, message: "middle chunk failed" },
    ]);
  });

  it("retryChunksInRange re-requests exactly the failed chunk in the range", async () => {
    fetchMock.mockImplementation((_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as { offset: number };
      if (body.offset === CHUNK_SIZE) return Promise.reject(new Error("middle chunk failed"));
      return Promise.resolve(windowResponse([{ path: DUMP_A, bytes: [1] }], [0]));
    });
    load([DUMP_A]);
    await flush();
    const before = fetchMock.mock.calls.length;

    useMultiHexStore.getState().retryChunksInRange(0, 3 * CHUNK_SIZE - 1);
    await flush();

    expect(fetchMock.mock.calls.length).toBe(before + 1);
    expect(callsForOffset(CHUNK_SIZE)).toBe(2);
  });

  it("retryChunkAt issues exactly one more request", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));
    load([DUMP_A]);
    await flush();
    expect(callsForOffset(0)).toBe(1);

    useMultiHexStore.getState().retryChunkAt(0);
    await flush();
    expect(callsForOffset(0)).toBe(2);

    // Still failing, so it latches again rather than looping.
    load([DUMP_A]);
    await flush();
    expect(callsForOffset(0)).toBe(2);
  });

  it("retryChunkAt is a no-op when the chunk did not fail", async () => {
    fetchMock.mockResolvedValue(windowResponse([{ path: DUMP_A, bytes: [7] }], [0]));
    load([DUMP_A]);
    await flush();
    const before = callsForOffset(0);

    useMultiHexStore.getState().retryChunkAt(0);
    await flush();
    expect(callsForOffset(0)).toBe(before);
  });

  it("a failed chunk does not block a DIFFERENT chunk from loading", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));
    load([DUMP_A]);
    await flush();
    expect(useMultiHexStore.getState().getChunkError(0)).toBe("boom");

    fetchMock.mockReset();
    fetchMock.mockResolvedValue(
      windowResponse([{ path: DUMP_A, bytes: [9] }], [0]),
    );
    // Scroll far enough to ask for a chunk that has never been requested.
    load([DUMP_A], 512, 512);
    await flush();
    expect(callsForOffset(3 * CHUNK_SIZE)).toBeGreaterThan(0);
  });

  it("forgets the failure and refetches when the SELECTION changes", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));
    load([DUMP_A]);
    await flush();
    expect(useMultiHexStore.getState().getChunkError(0)).toBe("boom");

    fetchMock.mockReset();
    fetchMock.mockResolvedValue(
      windowResponse([{ path: DUMP_A, bytes: [7] }, { path: DUMP_B, bytes: [8] }], [0]),
    );
    load([DUMP_A, DUMP_B]);
    await flush();

    expect(callsForOffset(0)).toBeGreaterThan(0);
    expect(useMultiHexStore.getState().getChunkError(0)).toBeNull();
  });

  it("keeps the LOCKED-dump hint on the pane it belongs to", async () => {
    fetchMock.mockResolvedValue(
      windowResponse(
        [{ path: DUMP_A, bytes: null, hint: "passphrase required" }, { path: DUMP_B, bytes: [3] }],
        [0],
      ),
    );
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.byPath.get(DUMP_A)!.error).toBe("passphrase required");
    expect(state.byPath.get(DUMP_B)!.error).toBeNull();
  });

  /**
   * `api/client.request` throws with the RAW response body, so surfacing
   * `err.message` put `{"error":…,"category":"INVALID_INPUT"}` in front of the
   * analyst verbatim.
   */
  it("unwraps the backend's JSON envelope instead of showing it raw", async () => {
    fetchMock.mockRejectedValue(
      new Error(
        JSON.stringify({
          error: "anchor offset does not name an addressable byte",
          category: "INVALID_INPUT",
        }),
      ),
    );
    load([DUMP_A]);
    await flush();

    expect(useMultiHexStore.getState().getChunkError(0)).toBe(
      "anchor offset does not name an addressable byte",
    );
  });

  it("forgets a failure recorded under a previous selection", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));
    load([DUMP_A]);
    await flush();
    expect(useMultiHexStore.getState().getChunkError(0)).toBe("boom");

    fetchMock.mockReset();
    fetchMock.mockReturnValue(never());
    load([DUMP_A, DUMP_B]);

    expect(useMultiHexStore.getState().getChunkError(0)).toBeNull();
  });
});

describe("addressable bounds", () => {
  /**
   * The pane loader must not ask for a window past the end of the dump. With
   * two panes the prefetch is 2 chunks on each side, so an 8192-byte
   * addressable anchor was asked for offsets 8192 and 16384 — both rejected
   * with 400 "anchor offset does not name an addressable byte".
   */
  it("never requests a chunk past the anchor's addressable size", async () => {
    fetchMock.mockReturnValue(never());

    useMultiHexStore.getState().ensureLoaded({
      anchorPath: DUMP_A,
      view: "vas",
      paths: [DUMP_A, DUMP_B],
      startRow: 0,
      endRow: 10,
      consensusId: null,
      anchorSize: CHUNK_SIZE,
    });

    expect(requestBodies().map((body) => body.offset)).toEqual([0]);
  });

  it("still prefetches when the size is not known yet", async () => {
    fetchMock.mockReturnValue(never());

    useMultiHexStore.getState().ensureLoaded({
      anchorPath: DUMP_A,
      view: "vas",
      paths: [DUMP_A, DUMP_B],
      startRow: 0,
      endRow: 10,
      consensusId: null,
    });

    expect(requestBodies().map((body) => body.offset)).toEqual([
      0,
      CHUNK_SIZE,
      2 * CHUNK_SIZE,
    ]);
  });
});

describe("absence", () => {
  /**
   * `isPresentAt` answers "is there a byte"; `absenceAt` answers "WHY not",
   * and the four answers are different findings. Two of them (`loading`,
   * `error`) are problems of this client and two (`no-correspondence`,
   * `not-in-dump`) are facts about the dumps — painting them alike is how a
   * failed request gets read as evidence that memory was empty.
   */
  it("says LOADING while the window is still in flight", () => {
    fetchMock.mockReturnValue(never());
    load([DUMP_A]);

    expect(useMultiHexStore.getState().absenceAt(DUMP_A, 0)).toBe("loading");
  });

  it("says ERROR when the request for that window failed", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));
    load([DUMP_A]);
    await flush();

    expect(useMultiHexStore.getState().absenceAt(DUMP_A, 0)).toBe("error");
  });

  it("says NO-CORRESPONDENCE for a gap — identically for every pane", async () => {
    // `classes[1] === -1` with index 1 outside every `bytes_valid` run is the
    // backend's shape for "the alignment placed nothing here".
    fetchMock.mockResolvedValue(
      windowResponse(
        [
          { path: DUMP_A, bytes: [1, 0, 3, 4], valid: [[0, 1], [2, 2]] },
          { path: DUMP_B, bytes: [1, 0, 3, 4], valid: [[0, 1], [2, 2]] },
        ],
        [0, -1, 0, 0],
      ),
    );
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.absenceAt(DUMP_A, 1)).toBe("no-correspondence");
    expect(state.absenceAt(DUMP_B, 1)).toBe("no-correspondence");
  });

  it("says NOT-IN-DUMP where the alignment holds the index but this dump does not", async () => {
    fetchMock.mockResolvedValue(
      windowResponse(
        [
          { path: DUMP_A, bytes: [1, 2, 3, 4], valid: [[0, 4]] },
          { path: DUMP_B, bytes: [1, 2, 0, 0], valid: [[0, 2]] },
        ],
        [0, 0, 0, 0],
      ),
    );
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    // Same offset, two different answers — which is the whole point: this is a
    // fact about ONE dump, not about the alignment.
    expect(state.absenceAt(DUMP_B, 3)).toBe("not-in-dump");
    expect(state.absenceAt(DUMP_A, 3)).toBeNull();
  });

  /**
   * The failure this store's presence mask exists to prevent, stated from the
   * other side: a real `0x00` is a byte, and no story about its absence may be
   * told about it.
   */
  it("returns null for a genuine 0x00 inside a bytes_valid run", async () => {
    fetchMock.mockResolvedValue(
      windowResponse([{ path: DUMP_A, bytes: [0, 0, 0, 0], valid: [[0, 4]] }], [0, 0, 0, 0]),
    );
    load([DUMP_A]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.absenceAt(DUMP_A, 0)).toBeNull();
    expect(state.getByteAt(DUMP_A, 0)).toBe(0);
    expect(state.isPresentAt(DUMP_A, 0)).toBe(true);
  });
});

describe("differsAt and filler zeros", () => {
  /**
   * The window carries `0` for a byte a dump does not hold, so a comparison
   * that skipped `isPresentAt` would report "these dumps disagree" about a
   * hole — flagging every unmapped page in every dump as a difference.
   */
  it("does not count a filler zero against a real 0x00", async () => {
    fetchMock.mockResolvedValue(
      windowResponse(
        [
          // A really holds 0x00 at index 0; B's window has 0 there too, but
          // index 0 is outside its `bytes_valid`, so B holds nothing.
          { path: DUMP_A, bytes: [0, 5], valid: [[0, 2]] },
          { path: DUMP_B, bytes: [0, 9], valid: [[1, 1]] },
        ],
        [0, 0],
      ),
    );
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.differsAt(0)).toBe(false);
    // …and where both dumps really do hold a byte, it still reports.
    expect(state.differsAt(1)).toBe(true);
  });
});

describe("server-computed cross-dump findings", () => {
  /**
   * `variants` is the SERVER's answer, and it outranks the client's.
   *
   * The server computes it over exactly the dumps the request named, before
   * any byte reaches this cache; a client reducer can only see what the cache
   * happens to hold. Where the two disagree the server is right by
   * construction, so this fixture makes them disagree on purpose.
   */
  it("reports the server's variant counts, not a recomputation of them", async () => {
    fetchMock.mockResolvedValue(
      asResponse(
        windowBody(
          [
            { path: DUMP_A, bytes: [1, 1] },
            { path: DUMP_B, bytes: [1, 1] },
          ],
          [0, 0],
          // The bytes agree everywhere; the server says index 0 disagrees.
          { variants: [2, 1] },
        ),
      ),
    );
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.differsAt(0)).toBe(true);
    expect(state.differsAt(1)).toBe(false);
  });

  it("falls back to comparing the cached bytes when the response carries no variants", async () => {
    fetchMock.mockResolvedValue(
      asResponse(
        windowBody(
          [
            { path: DUMP_A, bytes: [1, 7] },
            { path: DUMP_B, bytes: [1, 9] },
          ],
          [0, 0],
          // An older backend that does not send the field at all — which is
          // NOT the same as sending an all-agreeing one.
          { variants: undefined as unknown as number[] },
        ),
      ),
    );
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.differsAt(0)).toBe(false);
    expect(state.differsAt(1)).toBe(true);
  });

  /**
   * The bug the fallback used to carry: `byPath` deliberately keeps the chunks
   * of dumps that have LEFT the selection (so flipping back hits the cache),
   * and folding over them reported a disagreement between a pane on screen and
   * a dump nobody selected.
   */
  it("never compares against a dump that has left the selection", async () => {
    fetchMock.mockResolvedValue(
      windowResponse(
        [
          { path: DUMP_A, bytes: [1] },
          { path: DUMP_B, bytes: [2] },
        ],
        [0],
      ),
    );
    load([DUMP_A, DUMP_B]);
    await flush();
    expect(useMultiHexStore.getState().differsAt(0)).toBe(true);

    fetchMock.mockReset();
    fetchMock.mockResolvedValue(
      asResponse(
        windowBody(
          [
            { path: DUMP_A, bytes: [1] },
            { path: DUMP_C, bytes: [1] },
          ],
          [0],
          { variants: undefined as unknown as number[] },
        ),
      ),
    );
    load([DUMP_A, DUMP_C]);
    await flush();

    const state = useMultiHexStore.getState();
    // B's bytes are still cached and still visible to `getByteAt`...
    expect(state.getByteAt(DUMP_B, 0)).toBe(2);
    // ...and must count for nothing: the question is about A and C.
    expect(state.differsAt(0)).toBe(false);
  });

  it("exposes the server's variant count per index", async () => {
    fetchMock.mockResolvedValue(
      windowResponse(
        [
          { path: DUMP_A, bytes: [5, 5, 5], valid: [[0, 2]] },
          { path: DUMP_B, bytes: [5, 9, 5], valid: [[0, 2]] },
        ],
        [0, 0, 0],
      ),
    );
    load([DUMP_A, DUMP_B]);
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.variantsAt(0)).toBe(1); // both present, both 5
    expect(state.variantsAt(1)).toBe(2); // both present, 5 vs 9
    expect(state.variantsAt(2)).toBe(0); // nobody present
  });

  it("answers undefined for a window it does not hold", () => {
    expect(useMultiHexStore.getState().variantsAt(0)).toBeUndefined();
  });
});

describe("late failures after teardown", () => {
  /**
   * A rejection that lands after `reset()` must write NOTHING.
   *
   * The `.then` has carried a stale-identity guard from the start; the
   * `.catch` did not. So a request rejecting after the viewer was torn down
   * wrote its verdict into the freshly-cleared `chunkErrors` and re-registered
   * a handle in the just-cleared `retryTimers` -- resurrecting both maps, and
   * the retry POST behind them, for a viewer nobody is looking at.
   */
  it("drops a rejection that lands after reset, and schedules no retry", async () => {
    vi.useFakeTimers();
    try {
      const failing = Promise.reject(new Error("backend gone"));
      // Keep the rejection from being "unhandled" before the store takes it.
      failing.catch(() => {});
      fetchMock.mockReturnValue(failing);

      load([DUMP_A]);
      useMultiHexStore.getState().reset();
      await settle();

      const state = useMultiHexStore.getState();
      expect(state.chunkErrors.size).toBe(0);
      expect(state.pending.size).toBe(0);
      expect(state.identity).toBeNull();

      // And nothing was scheduled: moving past the whole backoff issues no
      // second request.
      fetchMock.mockClear();
      await settle(10_000);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  /**
   * The same guard for the other way an identity dies: a new selection.
   */
  it("drops a rejection whose selection changed mid-flight", async () => {
    const failing = Promise.reject(new Error("boom"));
    failing.catch(() => {});
    fetchMock.mockReturnValueOnce(failing);
    fetchMock.mockReturnValue(never());

    load([DUMP_A]);
    // A different selection => a different identity.
    load([DUMP_A, DUMP_B]);
    await flush();

    const errors = [...useMultiHexStore.getState().chunkErrors.keys()];
    expect(errors.every((key) => !key.startsWith(`${DUMP_A}|raw|${DUMP_A}|`))).toBe(true);
  });
});

describe("lastRequest identity", () => {
  /**
   * `ensureLoaded` re-runs on EVERY virtualizer row change, and `lastRequest`
   * used to get a fresh object each time -- above the `needed.length === 0`
   * early return, so even a fully cached scroll rotated it. Everything
   * subscribed to it (`useVarianceRegions`, and through it the class browser
   * and the chips) then re-rendered and re-ran its effect on every scroll
   * tick.
   */
  it("keeps the same object across scroll ticks that change nothing", async () => {
    fetchMock.mockResolvedValue(windowResponse([{ path: DUMP_A, bytes: [1] }], [0]));
    load([DUMP_A]);
    await flush();

    const first = useMultiHexStore.getState().lastRequest;
    expect(first).not.toBeNull();

    load([DUMP_A]);
    load([DUMP_A]);
    expect(useMultiHexStore.getState().lastRequest).toBe(first);
  });

  it("still replaces it when the request really changed", async () => {
    fetchMock.mockResolvedValue(
      windowResponse([{ path: DUMP_A, bytes: [1] }, { path: DUMP_B, bytes: [2] }], [0]),
    );
    load([DUMP_A]);
    await flush();
    const first = useMultiHexStore.getState().lastRequest;

    load([DUMP_A, DUMP_B]);
    const second = useMultiHexStore.getState().lastRequest;
    expect(second).not.toBe(first);
    expect(second?.paths).toEqual([DUMP_A, DUMP_B]);
  });
});

describe("reset", () => {
  it("empties every cache", async () => {
    fetchMock.mockResolvedValue(windowResponse([{ path: DUMP_A, bytes: [1] }], [0]));
    load([DUMP_A]);
    await flush();

    useMultiHexStore.getState().reset();

    const state = useMultiHexStore.getState();
    expect(state.byPath.size).toBe(0);
    expect(state.classChunks.size).toBe(0);
    expect(state.chunkVersionByPath.size).toBe(0);
    expect(state.pending.size).toBe(0);
    expect(state.identity).toBeNull();
    expect(state.alignment).toBeNull();
    expect(state.getByteAt(DUMP_A, 0)).toBeUndefined();
  });
});
