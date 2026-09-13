import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { useMultiHexStore } from "@/stores/multi-hex-store";
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
    // Each pane-chunk costs data(4) + mask(4) = 8 bytes; three chunk offsets
    // across two panes = 48. A 20-byte budget keeps only the two newest.
    useMultiHexStore.setState({ budgetBytes: 20 });

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

  it("clears the chunk error once that window arrives", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));
    load([DUMP_A]);
    await flush();
    expect(useMultiHexStore.getState().getChunkError(0)).toBe("boom");

    fetchMock.mockReset();
    fetchMock.mockResolvedValue(windowResponse([{ path: DUMP_A, bytes: [7] }], [0]));
    load([DUMP_A]);
    await flush();

    expect(useMultiHexStore.getState().getChunkError(0)).toBeNull();
    expect(useMultiHexStore.getState().getByteAt(DUMP_A, 0)).toBe(7);
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
