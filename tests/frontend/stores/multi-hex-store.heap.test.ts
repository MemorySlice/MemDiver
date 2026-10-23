import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useMultiHexStore } from "@/stores/multi-hex-store";
import { useDumpStore } from "@/stores/dump-store";
import type { AlignedWindowResponse } from "@/api/aligned-window";

/**
 * The aligned window's heap fields (`heap_status`, `heap_roles`) as the
 * overlay's `Heap` render mode reads them through `multi-hex-store`.
 */

const DUMP_A = "/dumps/a.msl";
const DUMP_B = "/dumps/b.msl";

function body(length: number, overrides: Partial<AlignedWindowResponse> = {}): AlignedWindowResponse {
  const bytes = btoa(String.fromCharCode(...new Array(length).fill(0)));
  return {
    consensus_id: "c1",
    classified: true,
    alignment: {
      method: "virtual_address",
      bytes_compared: length,
      bytes_discarded: 0,
      sizes_differed: false,
      n_sources: 2,
      warnings: [],
    },
    anchor: {
      kind: "dump",
      dump_path: DUMP_A,
      dump_index: 0,
      view: "va",
      offset: 0,
      va: 0,
      va_span_start: 0,
      slab_offset: 0,
    },
    requested_length: length,
    length,
    truncated: false,
    classes: new Array(length).fill(0),
    variants: new Array(length).fill(1),
    gaps: [],
    segments: [],
    dumps: [DUMP_A, DUMP_B].map((path, index) => ({
      dump_index: index,
      dump_path: path,
      format: "msl",
      view: "va",
      bytes,
      bytes_valid: [[0, length]] as [number, number][],
      key_status: { decrypted: true, hint: null, tag_status: "not_encrypted" as const },
    })),
    ...overrides,
  };
}

const fetchMock = vi.fn();

function respond(payload: AlignedWindowResponse): void {
  fetchMock.mockResolvedValue({
    ok: true,
    text: async () => JSON.stringify(payload),
  } as unknown as Response);
}

function load(): void {
  useMultiHexStore.getState().ensureLoaded({
    anchorPath: DUMP_A,
    view: "va",
    paths: [DUMP_A, DUMP_B],
    startRow: 0,
    endRow: 0,
    consensusId: "c1",
    anchorSize: 4,
  });
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  useMultiHexStore.getState().reset();
  useDumpStore.setState({ dumps: [] });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("multi-hex-store heap roles", () => {
  it("decodes heap_roles per window index and records heap_status", async () => {
    respond(body(4, { heap_status: "ok", heap_roles: [1, 2, 254, 255] }));
    load();
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.heapStatus).toBe("ok");
    expect(state.heapRoleAt(0)).toBe(1);
    expect(state.heapRoleAt(1)).toBe(2);
    expect(state.heapRoleAt(2)).toBe(254);
    expect(state.heapRoleAt(3)).toBe(255);
  });

  it("answers undefined, not 'no role', when the server sent no roles", async () => {
    respond(body(4));
    load();
    await flush();

    const state = useMultiHexStore.getState();
    expect(state.heapStatus).toBeNull();
    expect(state.heapRoleAt(0)).toBeUndefined();
  });

  it("records a non-ok status verbatim", async () => {
    respond(body(4, { heap_status: "no_va_coordinate" }));
    load();
    await flush();
    expect(useMultiHexStore.getState().heapStatus).toBe("no_va_coordinate");
  });

  it("clears roles and status on reset", async () => {
    respond(body(4, { heap_status: "ok", heap_roles: [1, 1, 1, 1] }));
    load();
    await flush();
    useMultiHexStore.getState().reset();

    const state = useMultiHexStore.getState();
    expect(state.heapStatus).toBeNull();
    expect(state.heapRoleChunks.size).toBe(0);
    expect(state.heapRoleAt(0)).toBeUndefined();
  });
});
