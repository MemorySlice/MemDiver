import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { useConsensusIncrementalStore } from "@/stores/consensus-incremental-store";

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

function errorResponse(status: number, detail: string): Response {
  return {
    ok: false,
    status,
    json: async () => ({ detail }),
    text: async () => detail,
  } as unknown as Response;
}

const store = () => useConsensusIncrementalStore.getState();

describe("consensus-incremental-store.addPath", () => {
  beforeEach(() => {
    store().reset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts the server-side path to the open session", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        session_id: "s1",
        num_dumps: 1,
        live_stats: { mean_variance: 1, max_variance: 4, top_offsets: [] },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    useConsensusIncrementalStore.setState({ sessionId: "s1", status: "building" });

    await store().addPath("/srv/pre.msl");

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/consensus/s1/add-path");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ path: "/srv/pre.msl" });
  });

  it("folds each add's live_stats into the sparkline history", async () => {
    let n = 0;
    const maxima = [4, 7, 2];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const max = maxima[n];
        n += 1;
        return jsonResponse({
          session_id: "s1",
          num_dumps: n,
          live_stats: { mean_variance: max / 2, max_variance: max, top_offsets: [] },
        });
      }),
    );
    useConsensusIncrementalStore.setState({ sessionId: "s1", status: "building" });

    await store().addPath("/srv/a.msl");
    await store().addPath("/srv/b.msl");
    await store().addPath("/srv/c.msl");

    expect(store().history).toEqual(maxima);
    expect(store().numDumps).toBe(3);
    expect(store().liveStats?.max_variance).toBe(2);
  });

  it("is a no-op without an open session", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await store().addPath("/srv/a.msl");

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("captures a rejected dump in `error` without wedging `status`", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => errorResponse(400, "dump shorter than consensus size")),
    );
    useConsensusIncrementalStore.setState({ sessionId: "s1", status: "building" });

    await store().addPath("/srv/short.msl");

    expect(store().error).toContain("dump shorter than consensus size");
    // One rejected dump must not tear the session down: the remaining dumps
    // still have to be foldable.
    expect(store().status).toBe("building");
    expect(store().sessionId).toBe("s1");
  });

  it("clears a stale error once a later add succeeds", async () => {
    let first = true;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        if (first) {
          first = false;
          return errorResponse(400, "nope");
        }
        return jsonResponse({
          session_id: "s1",
          num_dumps: 1,
          live_stats: { mean_variance: 1, max_variance: 1, top_offsets: [] },
        });
      }),
    );
    useConsensusIncrementalStore.setState({ sessionId: "s1", status: "building" });

    await store().addPath("/srv/short.msl");
    expect(store().error).not.toBeNull();
    await store().addPath("/srv/good.msl");
    expect(store().error).toBeNull();
  });
});

describe("consensus-incremental-store.begin", () => {
  beforeEach(() => {
    store().reset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("does not leave a stale session id behind after a failed begin", async () => {
    useConsensusIncrementalStore.setState({ sessionId: "old", status: "building" });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => errorResponse(500, "boom")),
    );

    await store().begin(4096);

    expect(store().sessionId).toBeNull();
    expect(store().status).toBe("error");
  });
});
