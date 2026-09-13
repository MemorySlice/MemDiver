import { describe, it, expect, afterEach, vi } from "vitest";

import { consensusCoversSelection, useConsensusStore } from "@/stores/consensus-store";

/**
 * A consensus is a statement ABOUT A SET OF DUMPS.
 *
 * The store used to keep the build's id, size and counts but no record of WHICH
 * dumps produced it, and nothing cleared it when the selection changed — so a
 * build made over {X, Y} kept being projected onto a later selection {A, B}:
 * wrong slab, wrong classes, wrong gaps, bogus cross-dump "Differs" rings, and
 * not one thing on screen saying so. `builtFrom` is what makes that detectable;
 * these tests pin that it is recorded, compared by MEMBERSHIP, and cleared.
 */

const A = "/dumps/a.msl";
const B = "/dumps/b.msl";
const C = "/dumps/c.msl";

function okResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
  useConsensusStore.getState().reset();
});

describe("consensus-store runConsensus provenance", () => {
  it("records the dumps and the normalize flag the server echoed", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        okResponse({
          consensus_id: "c1",
          size: 4096,
          num_dumps: 2,
          counts: { INVARIANT: 4096 },
          dump_paths: [A, B],
          normalize: true,
        }),
      ),
    );

    await useConsensusStore.getState().runConsensus([A, B], true);

    const state = useConsensusStore.getState();
    expect(state.consensusId).toBe("c1");
    expect(state.builtFrom).toEqual([A, B]);
    expect(state.builtNormalized).toBe(true);
  });

  /**
   * A backend that predates the echo must not leave the build unattributable:
   * the paths we ASKED for are the next best record, and they are the ones the
   * selection will be compared against anyway.
   */
  it("falls back to the requested paths when the server does not echo them", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => okResponse({ consensus_id: "c1", size: 16, num_dumps: 2 })),
    );

    await useConsensusStore.getState().runConsensus([A, B], false);

    expect(useConsensusStore.getState().builtFrom).toEqual([A, B]);
    expect(useConsensusStore.getState().builtNormalized).toBe(false);
  });
});

describe("consensus-store thresholds", () => {
  /**
   * The bands a legend prints have to be the bands the build CUT AT.
   *
   * Before the server echoed them the web UI re-derived a region's class from
   * its `mean_variance` against hard-coded `0 / 200 / 3000` literals — a second
   * copy of `core.variance` waiting to drift the moment anyone passed custom
   * thresholds, and drifting silently, because every number on screen stays
   * perfectly plausible.
   */
  it("records the bands the build reported", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        okResponse({
          consensus_id: "c1",
          size: 4096,
          num_dumps: 2,
          thresholds: { invariant_max: 0, structural_max: 512, pointer_max: 9000 },
        }),
      ),
    );

    await useConsensusStore.getState().runConsensus([A, B], false);

    expect(useConsensusStore.getState().thresholds).toEqual({
      invariant_max: 0,
      structural_max: 512,
      pointer_max: 9000,
    });
  });

  /**
   * A backend that does not echo them has NOT said they were the module
   * defaults. `null` means "unknown", and a legend must omit the boundaries
   * rather than print three numbers nothing vouched for.
   */
  it("stays null rather than inventing the module defaults", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => okResponse({ consensus_id: "c1", size: 16, num_dumps: 2 })),
    );

    await useConsensusStore.getState().runConsensus([A, B], false);

    expect(useConsensusStore.getState().thresholds).toBeNull();
  });

  it("is cleared by reset, along with the rest of the build", async () => {
    useConsensusStore.setState({
      thresholds: { invariant_max: 0, structural_max: 200, pointer_max: 3000 },
    });

    useConsensusStore.getState().reset();

    expect(useConsensusStore.getState().thresholds).toBeNull();
  });
});

describe("consensus-store matchesSelection", () => {
  function build(builtFrom: string[]) {
    useConsensusStore.setState({ consensusId: "c1", builtFrom });
  }

  it("accepts the same set in a different order", () => {
    build([A, B]);
    expect(useConsensusStore.getState().matchesSelection([B, A])).toBe(true);
  });

  it("rejects a selection the build never saw", () => {
    build([A, B]);
    expect(useConsensusStore.getState().matchesSelection([A, C])).toBe(false);
  });

  it("rejects a selection that merely CONTAINS the build's dumps", () => {
    build([A, B]);
    expect(useConsensusStore.getState().matchesSelection([A, B, C])).toBe(false);
  });

  it("rejects a strict subset: fewer dumps is a different consensus", () => {
    build([A, B, C]);
    expect(useConsensusStore.getState().matchesSelection([A, B])).toBe(false);
  });

  /**
   * An incremental fold cannot say which files it covers (it folds uploaded
   * BYTES). Reporting "unknown" as "mismatch" would fence off a build that is
   * very likely correct, so an empty `builtFrom` is permissive.
   */
  it("is permissive when the build cannot say which dumps it covers", () => {
    build([]);
    expect(useConsensusStore.getState().matchesSelection([A, B])).toBe(true);
    expect(useConsensusStore.getState().matchesSelection([])).toBe(true);
  });
});

describe("consensus-store adoptIncremental", () => {
  it("records an unattributable build rather than a false provenance", () => {
    useConsensusStore.getState().adoptIncremental({
      consensusId: "session-1",
      size: 256,
      numDumps: 3,
      counts: { INVARIANT: 256 },
    });

    const state = useConsensusStore.getState();
    expect(state.consensusId).toBe("session-1");
    expect(state.builtFrom).toEqual([]);
    expect(state.builtNormalized).toBe(false);
    expect(state.matchesSelection([A, B])).toBe(true);
  });
});

describe("consensus-store reset", () => {
  it("clears the provenance along with the build", () => {
    useConsensusStore.setState({
      consensusId: "c1",
      builtFrom: [A, B],
      builtNormalized: true,
      available: true,
    });

    useConsensusStore.getState().reset();

    const state = useConsensusStore.getState();
    expect(state.consensusId).toBeNull();
    expect(state.builtFrom).toEqual([]);
    expect(state.builtNormalized).toBe(false);
    expect(state.available).toBe(false);
  });
});

describe("consensusCoversSelection", () => {
  it("compares membership, not order or identity", () => {
    expect(consensusCoversSelection([A, B], [B, A])).toBe(true);
    expect(consensusCoversSelection([A, B], [A])).toBe(false);
    expect(consensusCoversSelection([], [A])).toBe(true);
  });
});
