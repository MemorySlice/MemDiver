import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  EMPTY_HEAP_DUMP,
  HEAP_MAX_ROLE_WINDOWS,
  HEAP_ROLE_WINDOW_SIZE,
  __resetHeapStoreBookkeeping,
  roleWindowKey,
  roleWindowStart,
  selectHeapDump,
  selectHeapLayerEnabled,
  useHeapStore,
} from "@/stores/heap-store";
import type { HeapRoleRun, HeapRolesResponse } from "@/api/types";
import { HEAP_CHUNK_START_BIT, HEAP_ROLE_CODE, HEAP_ROLE_NONE } from "@/utils/heap-roles";

const DUMP = "/dumps/a.msl";
const W = HEAP_ROLE_WINDOW_SIZE;
const fetchMock = vi.fn();

function ok(body: unknown): Response {
  return { ok: true, status: 200, text: async () => JSON.stringify(body) } as unknown as Response;
}

function fail(status: number, error: string): Response {
  return {
    ok: false,
    status,
    text: async () => JSON.stringify({ error, code: "E", category: "heap" }),
  } as unknown as Response;
}

function rolesBody(runs: HeapRoleRun[], chunkStarts: number[] = []): HeapRolesResponse {
  return {
    allocator: "ptmalloc2",
    view: "raw",
    offset: 0,
    length: W,
    runs,
    chunk_starts: chunkStarts,
    partial: false,
    heuristic: false,
  };
}

function urls(): URL[] {
  return fetchMock.mock.calls.map((c) => new URL(String(c[0]), "http://x"));
}

/** Answer every role request with runs derived from its own window offset. */
function serveRolesByOffset(runsFor: (start: number) => HeapRoleRun[], starts: (s: number) => number[] = () => []) {
  fetchMock.mockImplementation(async (input: string) => {
    const url = new URL(input, "http://x");
    const start = Number(url.searchParams.get("offset"));
    return ok(rolesBody(runsFor(start), starts(start)));
  });
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  __resetHeapStoreBookkeeping();
  useHeapStore.setState({ dumps: {}, roleWindows: {}, roleWindowsVersion: 0 });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("heap-store per-dump state", () => {
  it("hands an unseen dump the shared empty entry", () => {
    const s = useHeapStore.getState();
    expect(selectHeapDump(DUMP)(s)).toBe(EMPTY_HEAP_DUMP);
    expect(selectHeapDump(null)(s)).toBe(EMPTY_HEAP_DUMP);
    expect(selectHeapLayerEnabled(DUMP)(s)).toBe(false);
  });

  it("loads detection and summary", async () => {
    fetchMock
      .mockResolvedValueOnce(ok({ best: "scudo", confidence: 0.9, candidates: [] }))
      .mockResolvedValueOnce(ok({ allocator: "scudo", chunk_count: 3 }));
    await useHeapStore.getState().loadDetection(DUMP);
    await useHeapStore.getState().loadSummary(DUMP);
    const entry = selectHeapDump(DUMP)(useHeapStore.getState());
    expect(entry.detectionStatus).toBe("ready");
    expect(entry.detection?.best).toBe("scudo");
    expect(entry.summary?.chunk_count).toBe(3);
    expect(urls().map((u) => u.pathname)).toEqual(["/api/heap/detect", "/api/heap/summary"]);
  });

  it("surfaces a failure as a localized message with the envelope's text", async () => {
    fetchMock.mockResolvedValueOnce(fail(500, "parser exploded"));
    await useHeapStore.getState().loadSummary(DUMP);
    const entry = selectHeapDump(DUMP)(useHeapStore.getState());
    expect(entry.summaryStatus).toBe("error");
    expect(entry.summaryError).toBe("Heap summary failed: parser exploded");
  });

  it("uses the not-found message for a 404", async () => {
    fetchMock.mockResolvedValueOnce(fail(404, "no heap"));
    await useHeapStore.getState().loadDetection(DUMP);
    expect(selectHeapDump(DUMP)(useHeapStore.getState()).detectionError).toBe(
      "No heap data for this dump: no heap",
    );
  });

  it("caches chunk pages per filters/page and refetches after a filter change", async () => {
    fetchMock.mockImplementation(async () => ok({ chunks: [], total: 0, page: 0 }));
    const store = useHeapStore.getState();
    await store.loadChunkPage(DUMP, { page: 0, view: "raw" });
    await store.loadChunkPage(DUMP, { page: 0, view: "raw" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    useHeapStore.getState().setFilters(DUMP, { state: "free" });
    await useHeapStore.getState().loadChunkPage(DUMP, { page: 0, view: "raw" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(urls()[1].searchParams.get("state")).toBe("free");
  });

  it("ignores a response that lands after the allocator changed", async () => {
    let resolve!: (r: Response) => void;
    fetchMock.mockReturnValueOnce(new Promise<Response>((r) => (resolve = r)));
    const pending = useHeapStore.getState().loadSummary(DUMP);
    useHeapStore.getState().setAllocator(DUMP, "jemalloc");
    resolve(ok({ allocator: "ptmalloc2" }));
    await pending;
    const entry = selectHeapDump(DUMP)(useHeapStore.getState());
    expect(entry.allocator).toBe("jemalloc");
    expect(entry.summary).toBeNull();
  });

  it("sends the chosen allocator on later requests", async () => {
    fetchMock.mockResolvedValue(ok({ allocator: "mallocng" }));
    useHeapStore.getState().setAllocator(DUMP, "mallocng");
    await useHeapStore.getState().loadSummary(DUMP);
    expect(urls()[0].searchParams.get("allocator")).toBe("mallocng");
  });

  it("selects a chunk", () => {
    const chunk = { va: 1, size: 32 } as never;
    useHeapStore.getState().selectChunk(DUMP, chunk);
    expect(selectHeapDump(DUMP)(useHeapStore.getState()).selectedChunk).toBe(chunk);
  });
});

describe("heap-store role windows", () => {
  it("aligns window starts", () => {
    expect(roleWindowStart(0)).toBe(0);
    expect(roleWindowStart(W - 1)).toBe(0);
    expect(roleWindowStart(W)).toBe(W);
    expect(roleWindowStart(3 * W + 5)).toBe(3 * W);
  });

  it("fetches nothing while the layer is off", async () => {
    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 100);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fetches each aligned window covering the range once", async () => {
    serveRolesByOffset((s) => [{ offset: s, length: W, role: "user_data" }]);
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", W - 16, W + 16);
    expect(urls().map((u) => Number(u.searchParams.get("offset")))).toEqual([0, W]);
    expect(urls().every((u) => u.searchParams.get("length") === String(W))).toBe(true);

    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 2 * W);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(useHeapStore.getState().roleWindowsVersion).toBe(2);
  });

  it("dedupes an in-flight window across scroll bursts", async () => {
    serveRolesByOffset(() => []);
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    const a = useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 16);
    const b = useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 16, 32);
    await Promise.all([a, b]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keys windows by view", async () => {
    serveRolesByOffset(() => [{ offset: 0, length: 16, role: "chunk_header" }]);
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 16);
    await useHeapStore.getState().ensureRoleWindows(DUMP, "va", 0, 16);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const windows = useHeapStore.getState().roleWindows;
    expect(windows[roleWindowKey(DUMP, "raw", 0)]).toBeDefined();
    expect(windows[roleWindowKey(DUMP, "va", 0)]).toBeDefined();
    expect(useHeapStore.getState().roleAt(DUMP, "vas", 0)).toBe(HEAP_ROLE_NONE);
  });

  it("answers roleAt / isChunkStart / heapCellAt at run boundaries", async () => {
    serveRolesByOffset(
      () => [
        { offset: 0, length: 16, role: "chunk_header" },
        { offset: 16, length: 16, role: "free_link" },
        { offset: 32, length: 32, role: "free_data" },
      ],
      () => [0, 64],
    );
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 64);
    const s = useHeapStore.getState();
    expect(s.roleAt(DUMP, "raw", 15)).toBe(HEAP_ROLE_CODE.chunk_header);
    expect(s.roleAt(DUMP, "raw", 16)).toBe(HEAP_ROLE_CODE.free_link);
    expect(s.roleAt(DUMP, "raw", 63)).toBe(HEAP_ROLE_CODE.free_data);
    expect(s.roleAt(DUMP, "raw", 64)).toBe(HEAP_ROLE_NONE);
    expect(s.isChunkStart(DUMP, "raw", 0)).toBe(true);
    expect(s.isChunkStart(DUMP, "raw", 16)).toBe(false);
    expect(s.heapCellAt(DUMP, "raw", 0)).toBe(HEAP_ROLE_CODE.chunk_header | HEAP_CHUNK_START_BIT);
    expect(s.heapCellAt(DUMP, "raw", 64)).toBe(HEAP_CHUNK_START_BIT);
    // A window that never loaded answers "nothing", not an error.
    expect(s.heapCellAt(DUMP, "raw", 5 * W)).toBe(HEAP_ROLE_NONE);
  });

  it("assembles roleRunsForWindow across windows, clipped to the request", async () => {
    // One top chunk spanning both windows; the backend clips it per window.
    serveRolesByOffset((s) => [{ offset: s === 0 ? 100 : s, length: s === 0 ? W - 100 : 50, role: "top" }]);
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 2 * W);
    const runs = useHeapStore.getState().roleRunsForWindow(DUMP, "raw", 200, W + 10);
    expect(runs).toEqual([
      { offset: 200, length: W - 200, role: "top" },
      { offset: W, length: 10, role: "top" },
    ]);
    expect(useHeapStore.getState().roleRunsForWindow(DUMP, "raw", 0, 100)).toEqual([]);
  });

  it("evicts the oldest windows beyond the cap", async () => {
    serveRolesByOffset(() => []);
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    for (let i = 0; i <= HEAP_MAX_ROLE_WINDOWS; i++) {
      await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", i * W, i * W + 1);
    }
    const windows = useHeapStore.getState().roleWindows;
    expect(Object.keys(windows)).toHaveLength(HEAP_MAX_ROLE_WINDOWS);
    expect(windows[roleWindowKey(DUMP, "raw", 0)]).toBeUndefined();
    expect(windows[roleWindowKey(DUMP, "raw", HEAP_MAX_ROLE_WINDOWS * W)]).toBeDefined();
  });

  it("records a localized layer error and does not retry until re-enabled", async () => {
    fetchMock.mockResolvedValue(fail(500, "boom"));
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 16);
    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 16);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(selectHeapDump(DUMP)(useHeapStore.getState()).layerError).toBe(
      "Loading heap roles failed: boom",
    );

    useHeapStore.getState().setLayerEnabled(DUMP, false);
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    expect(selectHeapDump(DUMP)(useHeapStore.getState()).layerError).toBeNull();
    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 16);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("drops a dump's windows when its allocator changes", async () => {
    serveRolesByOffset(() => [{ offset: 0, length: 8, role: "top" }]);
    useHeapStore.getState().setLayerEnabled(DUMP, true);
    await useHeapStore.getState().ensureRoleWindows(DUMP, "raw", 0, 8);
    useHeapStore.getState().setAllocator(DUMP, "generic");
    expect(useHeapStore.getState().roleAt(DUMP, "raw", 0)).toBe(HEAP_ROLE_NONE);
    // The layer stays on across the allocator switch.
    expect(selectHeapLayerEnabled(DUMP)(useHeapStore.getState())).toBe(true);
  });
});
