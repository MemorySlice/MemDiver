import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useMultiHexStore } from "@/stores/multi-hex-store";
import { useDumpStore } from "@/stores/dump-store";
import { CHUNK_SIZE } from "@/components/hex/multi-window-utils";
import type {
  AlignedWindowPageStateRun,
  AlignedWindowResponse,
} from "@/api/aligned-window";

/**
 * `dumps[d].page_states` -> `pageStateAt(path, offset)`.
 *
 * The runs arrive in WINDOW index space, per dump, so the store must place
 * them by chunk + index alone (invariant W1) and keep them with the chunk
 * they describe: same identity check, same eviction.
 */

const ANCHOR = "/dumps/anchor.msl";
const PEER = "/dumps/peer.msl";

interface Spec {
  path: string;
  valid: [number, number][];
  pageStates?: AlignedWindowPageStateRun[];
}

function body(specs: Spec[], length = CHUNK_SIZE, spanStart = 0): AlignedWindowResponse {
  return {
    consensus_id: "c1",
    classified: true,
    alignment: {
      method: "virtual_address",
      bytes_compared: length,
      bytes_discarded: 0,
      sizes_differed: false,
      n_sources: specs.length,
      warnings: [],
    },
    anchor: {
      kind: "dump",
      dump_path: specs[0].path,
      dump_index: 0,
      view: "va",
      offset: 0,
      va: 0,
      va_span_start: spanStart,
      slab_offset: 0,
    },
    requested_length: length,
    length,
    truncated: false,
    classes: new Array<number>(length).fill(0),
    variants: new Array<number>(length).fill(1),
    gaps: [],
    segments: [],
    dumps: specs.map((spec, index) => ({
      dump_index: index,
      dump_path: spec.path,
      format: "msl",
      view: "va",
      bytes: btoa(String.fromCharCode(...new Array<number>(length).fill(0))),
      bytes_valid: spec.valid,
      ...(spec.pageStates ? { page_states: spec.pageStates } : {}),
      key_status: { decrypted: true, hint: null, tag_status: "not_encrypted" as const },
    })),
  };
}

const fetchMock = vi.fn();

function respondWith(make: (offset: number) => AlignedWindowResponse) {
  fetchMock.mockImplementation(async (_url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as { offset: number };
    return { ok: true, text: async () => JSON.stringify(make(req.offset)) };
  });
}

function load(paths: string[], startRow = 0, endRow = 0, anchorSize = CHUNK_SIZE) {
  useMultiHexStore.getState().ensureLoaded({
    anchorPath: paths[0],
    view: "va",
    paths,
    startRow,
    endRow,
    consensusId: "c1",
    anchorSize,
  });
}

function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
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

describe("pageStateAt", () => {
  it("answers the anchor's runs by window index, and nothing for the peer", async () => {
    respondWith(() =>
      body([
        {
          path: ANCHOR,
          valid: [[0, 2048]],
          pageStates: [
            [2048, 4096, "FAILED"],
            [6144, 1024, "UNMAPPED"],
            [7168, 1024, "NOT_RESIDENT"],
          ],
        },
        { path: PEER, valid: [[0, 2048]], pageStates: [] },
      ]),
    );
    load([ANCHOR, PEER]);
    await flush();

    const store = useMultiHexStore.getState();
    expect(store.pageStateAt(ANCHOR, 0)).toBeUndefined();
    expect(store.pageStateAt(ANCHOR, 2047)).toBeUndefined();
    expect(store.pageStateAt(ANCHOR, 2048)).toBe("FAILED");
    expect(store.pageStateAt(ANCHOR, 6143)).toBe("FAILED");
    expect(store.pageStateAt(ANCHOR, 6144)).toBe("UNMAPPED");
    expect(store.pageStateAt(ANCHOR, 7168)).toBe("NOT_RESIDENT");
    expect(store.pageStateAt(ANCHOR, 8191)).toBe("NOT_RESIDENT");
    for (const offset of [0, 2048, 6144, 7168]) {
      expect(store.pageStateAt(PEER, offset)).toBeUndefined();
    }
  });

  it("places runs relative to EACH chunk's start", async () => {
    respondWith((offset) =>
      body([
        {
          path: ANCHOR,
          valid: [],
          pageStates: offset === CHUNK_SIZE ? [[16, 16, "UNMAPPED"]] : [[0, 16, "FAILED"]],
        },
      ]),
    );
    load([ANCHOR], 0, 1023, 2 * CHUNK_SIZE);
    await flush();

    const store = useMultiHexStore.getState();
    expect(store.pageStateAt(ANCHOR, 0)).toBe("FAILED");
    expect(store.pageStateAt(ANCHOR, 16)).toBeUndefined();
    expect(store.pageStateAt(ANCHOR, CHUNK_SIZE)).toBeUndefined();
    expect(store.pageStateAt(ANCHOR, CHUNK_SIZE + 16)).toBe("UNMAPPED");
  });

  it("treats a response without the field (older server) as no page states", async () => {
    respondWith(() => body([{ path: ANCHOR, valid: [[0, CHUNK_SIZE]] }]));
    load([ANCHOR]);
    await flush();

    expect(useMultiHexStore.getState().pageStateAt(ANCHOR, 0)).toBeUndefined();
  });

  it("hides the runs once the identity moves, like the bytes they describe", async () => {
    respondWith(() =>
      body([{ path: ANCHOR, valid: [], pageStates: [[0, CHUNK_SIZE, "FAILED"]] }]),
    );
    load([ANCHOR]);
    await flush();
    expect(useMultiHexStore.getState().pageStateAt(ANCHOR, 0)).toBe("FAILED");

    fetchMock.mockImplementation(() => new Promise(() => {}));
    load([ANCHOR, PEER]);
    expect(useMultiHexStore.getState().pageStateAt(ANCHOR, 0)).toBeUndefined();
  });

  it("drops the runs with their chunk when the byte budget evicts it", async () => {
    respondWith(() =>
      body([{ path: ANCHOR, valid: [], pageStates: [[0, 16, "FAILED"]] }]),
    );
    // Room for exactly one chunk offset: its bytes + mask + runs, plus the
    // shared class and variant arrays (~4 x CHUNK_SIZE), but not two.
    useMultiHexStore.setState({ budgetBytes: 5 * CHUNK_SIZE });
    load([ANCHOR], 0, 1023, 2 * CHUNK_SIZE);
    await flush();

    const store = useMultiHexStore.getState();
    const held = [0, CHUNK_SIZE].filter((o) => store.pageStateAt(ANCHOR, o) === "FAILED");
    expect(held.length).toBe(1);
    expect(store.byPath.get(ANCHOR)?.chunks.size).toBe(1);
  });

  it("is cleared by reset()", async () => {
    respondWith(() =>
      body([{ path: ANCHOR, valid: [], pageStates: [[0, 16, "FAILED"]] }]),
    );
    load([ANCHOR]);
    await flush();
    useMultiHexStore.getState().reset();
    expect(useMultiHexStore.getState().pageStateAt(ANCHOR, 0)).toBeUndefined();
  });
});


describe("anchorVaLabel", () => {
  it("keeps the server-given va_span_start of a va window under the live identity", async () => {
    respondWith(() => body([{ path: ANCHOR, valid: [[0, CHUNK_SIZE]] }], CHUNK_SIZE, 0x7f0000001000));
    load([ANCHOR]);
    await flush();
    const state = useMultiHexStore.getState();
    expect(state.anchorVaLabel).toEqual({ identity: state.identity, spanStart: 0x7f0000001000 });
  });

  it("is cleared by reset", async () => {
    respondWith(() => body([{ path: ANCHOR, valid: [[0, CHUNK_SIZE]] }], CHUNK_SIZE, 0x1000));
    load([ANCHOR]);
    await flush();
    useMultiHexStore.getState().reset();
    expect(useMultiHexStore.getState().anchorVaLabel).toBeNull();
  });

  it("ignores a slab anchor's -1", async () => {
    respondWith(() => {
      const r = body([{ path: ANCHOR, valid: [[0, CHUNK_SIZE]] }]);
      return { ...r, anchor: { ...r.anchor, kind: "slab", va_span_start: -1 } };
    });
    load([ANCHOR]);
    await flush();
    expect(useMultiHexStore.getState().anchorVaLabel).toBeNull();
  });
});
