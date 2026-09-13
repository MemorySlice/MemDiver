import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx` — needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { ConsensusBuilder } from "@/components/analysis/ConsensusBuilder";
import { useDumpStore } from "@/stores/dump-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useConsensusIncrementalStore } from "@/stores/consensus-incremental-store";

const ANCHOR_SIZE = 231_000_000;

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

interface RecordedCall {
  url: string;
  body: unknown;
}

let calls: RecordedCall[];

function installFetch() {
  calls = [];
  let folded = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : init?.body;
    calls.push({ url, body });
    if (url.endsWith("/api/consensus/begin")) {
      return jsonResponse({ session_id: "sess-1", size: (body as { size: number }).size });
    }
    if (url.includes("/add-path")) {
      folded += 1;
      return jsonResponse({
        session_id: "sess-1",
        num_dumps: folded,
        live_stats: { mean_variance: 1.5, max_variance: 9.5, top_offsets: [] },
      });
    }
    if (url.includes("/finalize")) {
      return jsonResponse({
        session_id: "sess-1",
        num_dumps: 2,
        size: ANCHOR_SIZE,
        classification_counts: { static: 10, volatile: 2 },
        variance_summary: { mean: 1.5, max: 9.5, min: 0 },
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function seedDumps(entries: Array<{ path: string; name: string; size: number; format: "raw" | "msl" }>) {
  act(() => {
    for (const entry of entries) useDumpStore.getState().addDump(entry);
  });
}

const TWO_MSL = [
  { path: "/srv/pre.msl", name: "pre.msl", size: ANCHOR_SIZE, format: "msl" as const },
  { path: "/srv/post.msl", name: "post.msl", size: ANCHOR_SIZE, format: "msl" as const },
];

describe("ConsensusBuilder is driven by the session's one dump set", () => {
  beforeEach(() => {
    installFetch();
    act(() => {
      useDumpStore.getState().clearAll();
      useConsensusIncrementalStore.getState().reset();
      useConsensusStore.getState().reset();
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("lists the selected dumps instead of starting an empty session", () => {
    seedDumps(TWO_MSL);
    render(<ConsensusBuilder />);

    const seed = screen.getByTestId("consensus-seed-list");
    expect(seed).toHaveTextContent("pre.msl");
    expect(seed).toHaveTextContent("post.msl");
  });

  it("defaults the consensus size to the anchor dump, not 1 MiB", () => {
    seedDumps(TWO_MSL);
    render(<ConsensusBuilder />);

    const input = screen.getByTestId("consensus-size-input") as HTMLInputElement;
    expect(input.value).toBe(String(ANCHOR_SIZE));
    expect(input.value).not.toBe("1048576");
  });

  it("falls back to 1 MiB only when there is no dump to size from", () => {
    render(<ConsensusBuilder />);
    const input = screen.getByTestId("consensus-size-input") as HTMLInputElement;
    expect(input.value).toBe("1048576");
  });

  it("begins with the selected dump paths, folding one add-path per dump", async () => {
    seedDumps(TWO_MSL);
    const addPath = vi.fn(useConsensusIncrementalStore.getState().addPath);
    act(() => {
      useConsensusIncrementalStore.setState({ addPath });
    });
    render(<ConsensusBuilder />);

    await act(async () => {
      screen.getByRole("button", { name: /start session/i }).click();
    });

    await waitFor(() => expect(addPath).toHaveBeenCalledTimes(2));
    expect(addPath.mock.calls.map((c) => c[0])).toEqual([
      "/srv/pre.msl",
      "/srv/post.msl",
    ]);

    const begin = calls.find((c) => c.url.endsWith("/api/consensus/begin"));
    expect(begin?.body).toEqual({ size: ANCHOR_SIZE });
    const addPathCalls = calls.filter((c) => c.url.includes("/add-path"));
    expect(addPathCalls.map((c) => c.body)).toEqual([
      { path: "/srv/pre.msl" },
      { path: "/srv/post.msl" },
    ]);
  });

  it("writes the finalized session id into consensus-store so the overlay can read it", async () => {
    seedDumps(TWO_MSL);
    act(() => {
      useConsensusIncrementalStore.setState({
        sessionId: "sess-1",
        size: ANCHOR_SIZE,
        numDumps: 2,
        status: "building",
      });
    });
    render(<ConsensusBuilder />);

    await act(async () => {
      screen.getByRole("button", { name: /finalize/i }).click();
    });

    await waitFor(() =>
      expect(useConsensusStore.getState().consensusId).toBe("sess-1"),
    );
    expect(useConsensusStore.getState().available).toBe(true);
    expect(useConsensusStore.getState().numDumps).toBe(2);
    expect(useConsensusStore.getState().counts).toEqual({ static: 10, volatile: 2 });
  });

  it("arms the hex overlay from the finalized view", async () => {
    seedDumps(TWO_MSL);
    act(() => {
      useConsensusIncrementalStore.setState({
        sessionId: "sess-1",
        size: ANCHOR_SIZE,
        numDumps: 2,
        status: "finalized",
        finalResult: {
          session_id: "sess-1",
          num_dumps: 2,
          size: ANCHOR_SIZE,
          classification_counts: { static: 10 },
          variance_summary: { mean: 1, max: 2, min: 0 },
        },
      });
    });
    render(<ConsensusBuilder />);

    expect(useConsensusStore.getState().overlayEnabled).toBe(false);
    await act(async () => {
      screen.getByTestId("consensus-show-overlay").click();
    });
    expect(useConsensusStore.getState().overlayEnabled).toBe(true);
  });
});

describe("ConsensusBuilder is honest about alignment", () => {
  beforeEach(() => {
    installFetch();
    act(() => {
      useDumpStore.getState().clearAll();
      useConsensusIncrementalStore.getState().reset();
      useConsensusStore.getState().reset();
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("warns that an .msl fold is not ASLR-corrected", () => {
    seedDumps(TWO_MSL);
    render(<ConsensusBuilder />);
    expect(screen.getByTestId("consensus-msl-note")).toBeInTheDocument();
  });

  it("stays quiet for raw dumps of equal size", () => {
    seedDumps([
      { path: "/srv/a.dump", name: "a.dump", size: 4096, format: "raw" },
      { path: "/srv/b.dump", name: "b.dump", size: 4096, format: "raw" },
    ]);
    render(<ConsensusBuilder />);
    expect(screen.queryByTestId("consensus-msl-note")).toBeNull();
    expect(screen.queryByTestId("consensus-truncation-note")).toBeNull();
    expect(screen.queryByTestId("consensus-oversize-note")).toBeNull();
  });

  it("surfaces truncation when the selected dumps differ in size", () => {
    seedDumps([
      { path: "/srv/a.dump", name: "a.dump", size: 8192, format: "raw" },
      { path: "/srv/b.dump", name: "b.dump", size: 4096, format: "raw" },
    ]);
    render(<ConsensusBuilder />);
    expect(screen.getByTestId("consensus-truncation-note")).toBeInTheDocument();
    // The anchor is the 8192-byte dump, so the 4096-byte one would be rejected.
    expect(screen.getByTestId("consensus-oversize-note")).toBeInTheDocument();
  });
});
