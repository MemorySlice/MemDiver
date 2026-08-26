import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// Vite's `?raw` suffix hands us HexViewer's own source text, which the
// dependency-array guard at the bottom of this file asserts against.
import hexViewerSource from "../components/hex/HexViewer.tsx?raw";

import { useHexStore } from "./hex-store";

/**
 * The chunk-loading seam of the hex viewer:
 *
 *   setViewMode / setDumpPath  ->  clear chunks
 *   HexViewer visible-range effect  ->  ensureChunksLoaded
 *   ensureChunksLoaded  ->  fetch /api/inspect/hex-raw  ->  chunks  ->  getByteAt
 *
 * Every byte the user sees comes through here, and the store half of it had no
 * test at all. These cases pin the four failure modes that were live bugs:
 * a cleared cache that never refills (blank "--" cells), a stale response
 * landing in the wrong dump (WRONG bytes, silently), a stale response landing
 * in the wrong view, and a swallowed fetch error.
 */

// getPageStates is only reached via the "va" view; stub it so no test touches
// the network through the api client.
vi.mock("@/api/client", () => ({
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

const DUMP_A = "/dumps/a.msl";
const DUMP_B = "/dumps/b.msl";
// One CHUNK_SIZE (8192) file: ensureChunksLoaded(0, N) then needs exactly one
// chunk at offset 0, which keeps fetch-call counting unambiguous.
const FILE_SIZE = 8192;
const BYTES = [0xde, 0xad, 0xbe, 0xef];

function toBase64(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes));
}

function hexResponse(bytes: number[] = BYTES): Response {
  return {
    ok: true,
    json: async () => ({ bytes: toBase64(bytes), file_size: FILE_SIZE }),
  } as unknown as Response;
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

/** Drains the microtask queue behind fetch -> json -> .then(set). */
function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockResolvedValue(hexResponse());
  vi.stubGlobal("fetch", fetchMock);
  useHexStore.getState().reset();
  // reset() intentionally preserves the user's persisted view mode; pin it so
  // each case starts from a known view.
  useHexStore.setState({ viewMode: "raw" });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Loads dump A in the "raw" view and waits for its first chunk to land. */
async function loadDumpA(): Promise<void> {
  useHexStore.getState().setDumpPath(DUMP_A, FILE_SIZE, "msl");
  useHexStore.getState().ensureChunksLoaded(0, 10);
  await flush();
}

function viewsRequested(): string[] {
  return fetchMock.mock.calls.map((call) => {
    const url = String(call[0]);
    return new URL(url, "http://localhost").searchParams.get("view") ?? "";
  });
}

describe("hex-store chunk loading", () => {
  it("fills chunks so getByteAt returns real bytes", async () => {
    await loadDumpA();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(viewsRequested()).toEqual(["raw"]);
    expect(useHexStore.getState().chunks.size).toBe(1);
    expect(useHexStore.getState().getByteAt(0)).toBe(0xde);
    expect(useHexStore.getState().getByteAt(3)).toBe(0xef);
    expect(useHexStore.getState().pendingFetches.size).toBe(0);
  });

  it("does not re-fetch a chunk it already holds", async () => {
    await loadDumpA();
    useHexStore.getState().ensureChunksLoaded(0, 10);
    await flush();

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("setViewMode", () => {
  it("clears chunks and bumps chunkVersion", async () => {
    await loadDumpA();
    const versionBefore = useHexStore.getState().chunkVersion;
    expect(useHexStore.getState().chunks.size).toBe(1);

    useHexStore.getState().setViewMode("vas");

    const state = useHexStore.getState();
    expect(state.viewMode).toBe("vas");
    expect(state.chunks.size).toBe(0);
    expect(state.pendingFetches.size).toBe(0);
    expect(state.chunkVersion).toBeGreaterThan(versionBefore);
    // Nothing in the store refills the cache — the viewer's effect must.
    expect(state.getByteAt(0)).toBeUndefined();
  });

  it("re-issues the fetch for the SAME visible rows after a view flip (Bug 1)", async () => {
    await loadDumpA();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    useHexStore.getState().setViewMode("vas");
    // Exactly what HexViewer's effect does when it re-runs: identical row
    // range, because at scrollTop 0 the visible indices never moved. If the
    // cleared cache did not force a refetch here, every cell would render the
    // "--" placeholder permanently.
    useHexStore.getState().ensureChunksLoaded(0, 10);
    await flush();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(viewsRequested()).toEqual(["raw", "vas"]);
    expect(useHexStore.getState().chunks.size).toBe(1);
    expect(useHexStore.getState().getByteAt(0)).toBe(0xde);
  });

  it("requests view=va for the virtual-address view", async () => {
    await loadDumpA();

    useHexStore.getState().setViewMode("va");
    useHexStore.getState().ensureChunksLoaded(0, 10);
    await flush();

    expect(viewsRequested()).toEqual(["raw", "va"]);
    expect(useHexStore.getState().getByteAt(0)).toBe(0xde);
  });
});

describe("resolved-chunk staleness guard", () => {
  it("drops a response whose dump changed mid-flight (Bug 3)", async () => {
    const pending = createDeferred<Response>();
    fetchMock.mockReturnValueOnce(pending.promise);

    useHexStore.getState().setDumpPath(DUMP_A, FILE_SIZE, "msl");
    useHexStore.getState().ensureChunksLoaded(0, 10);
    expect(useHexStore.getState().pendingFetches.has(0)).toBe(true);

    // The user switches dumps while A's chunk is still in flight.
    useHexStore.getState().setDumpPath(DUMP_B, FILE_SIZE, "msl");
    pending.resolve(hexResponse());
    await flush();

    // A's bytes must NOT be shown while the viewer claims to be on B.
    const state = useHexStore.getState();
    expect(state.dumpPath).toBe(DUMP_B);
    expect(state.chunks.size).toBe(0);
    expect(state.getByteAt(0)).toBeUndefined();
    expect(state.pendingFetches.has(0)).toBe(false);
  });

  it("drops a response whose view mode changed mid-flight", async () => {
    const pending = createDeferred<Response>();
    fetchMock.mockReturnValueOnce(pending.promise);

    useHexStore.getState().setDumpPath(DUMP_A, FILE_SIZE, "msl");
    useHexStore.getState().ensureChunksLoaded(0, 10);

    useHexStore.getState().setViewMode("vas");
    pending.resolve(hexResponse());
    await flush();

    const state = useHexStore.getState();
    expect(state.viewMode).toBe("vas");
    expect(state.chunks.size).toBe(0);
    expect(state.getByteAt(0)).toBeUndefined();
  });

  it("keeps a response that resolves while dump and view are unchanged", async () => {
    const pending = createDeferred<Response>();
    fetchMock.mockReturnValueOnce(pending.promise);

    useHexStore.getState().setDumpPath(DUMP_A, FILE_SIZE, "msl");
    useHexStore.getState().ensureChunksLoaded(0, 10);
    pending.resolve(hexResponse());
    await flush();

    expect(useHexStore.getState().getByteAt(1)).toBe(0xad);
  });
});

describe("chunkError", () => {
  it("records a failed chunk fetch instead of swallowing it (Bug 4)", async () => {
    fetchMock.mockRejectedValueOnce(new Error("Hex fetch failed: 500"));

    useHexStore.getState().setDumpPath(DUMP_A, FILE_SIZE, "msl");
    useHexStore.getState().ensureChunksLoaded(0, 10);
    await flush();

    const state = useHexStore.getState();
    expect(state.chunkError).toBe("Hex fetch failed: 500");
    expect(state.pendingFetches.size).toBe(0);
    expect(state.chunks.size).toBe(0);
  });

  it("clears on a later successful chunk load", async () => {
    fetchMock.mockRejectedValueOnce(new Error("boom"));
    useHexStore.getState().setDumpPath(DUMP_A, FILE_SIZE, "msl");
    useHexStore.getState().ensureChunksLoaded(0, 10);
    await flush();
    expect(useHexStore.getState().chunkError).toBe("boom");

    useHexStore.getState().ensureChunksLoaded(0, 10);
    await flush();

    expect(useHexStore.getState().chunkError).toBeNull();
    expect(useHexStore.getState().getByteAt(0)).toBe(0xde);
  });

  it("clears on setViewMode, setDumpPath and reset", async () => {
    const failThenClear = async (clear: () => void) => {
      fetchMock.mockRejectedValueOnce(new Error("boom"));
      useHexStore.getState().ensureChunksLoaded(0, 10);
      await flush();
      expect(useHexStore.getState().chunkError).toBe("boom");
      clear();
      expect(useHexStore.getState().chunkError).toBeNull();
    };

    useHexStore.getState().setDumpPath(DUMP_A, FILE_SIZE, "msl");
    await failThenClear(() => useHexStore.getState().setViewMode("vas"));
    await failThenClear(() =>
      useHexStore.getState().setDumpPath(DUMP_B, FILE_SIZE, "msl"),
    );
    await failThenClear(() => useHexStore.getState().reset());
  });
});

describe("HexViewer chunk-fetch effect dependencies", () => {
  /**
   * `viewMode` and `format` are SEMANTIC dependencies of HexViewer's
   * visible-range effect: neither appears in the effect body (the view is read
   * through getState() inside ensureChunksLoaded), so eslint's exhaustive-deps
   * rule can neither add nor defend them, and a well-meaning "remove the unused
   * dep" cleanup silently reintroduces the permanently-blank viewer. A full
   * HexViewer render is not a practical guard here — it needs a real scroll
   * container for TanStack Virtual to report any visible rows at all, so the
   * effect is a no-op under jsdom. This source-level assertion is the cheap
   * regression net for the one thing the linter cannot see.
   */
  it("keeps viewMode and format in the ensureChunksLoaded dep array", () => {
    const effect = hexViewerSource.slice(
      hexViewerSource.indexOf(".ensureChunksLoaded("),
    );
    const depArray = effect.slice(effect.indexOf("}, ["), effect.indexOf("]", effect.indexOf("}, [")));

    expect(depArray).toContain("viewMode");
    expect(depArray).toContain("format");
    expect(depArray).toContain("dumpPath");
  });
});
