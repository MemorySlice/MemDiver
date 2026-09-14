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

describe("consensus-store generation guard", () => {
  /**
   * `useConsensusRun`'s in-flight flag stops the four UI affordances starting a
   * second build, but it is not the whole answer: `runConsensus` is a store
   * action, and anything holding the store could call it directly — which is
   * how the dump list used to issue a build the flag never saw. Two builds then
   * race, and since the responses land in whatever order the server finishes
   * them, the EARLIER one could overwrite `consensusId` / `builtFrom` /
   * `builtNormalized` and leave the viewers projecting a superseded build.
   */
  function deferredFetch() {
    const settle: ((body: unknown) => void)[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((res) => {
            settle.push((body) => res(okResponse(body)));
          }),
      ),
    );
    return settle;
  }

  it("never lets an earlier build overwrite a later one", async () => {
    const settle = deferredFetch();

    const first = useConsensusStore.getState().runConsensus([A], false);
    const second = useConsensusStore.getState().runConsensus([A, B], true);

    // The NEWER request answers first...
    settle[1]({ consensus_id: "c2", dump_paths: [A, B], normalize: true, size: 8 });
    await second;
    // ...and the older one straggles in behind it.
    settle[0]({ consensus_id: "c1", dump_paths: [A], normalize: false, size: 4 });
    await first;

    const state = useConsensusStore.getState();
    expect(state.consensusId).toBe("c2");
    expect(state.builtFrom).toEqual([A, B]);
    expect(state.builtNormalized).toBe(true);
    expect(state.size).toBe(8);
    // `loading` belongs to whichever run is still going; a superseded one must
    // not clear it either.
    expect(state.loading).toBe(false);
  });

  it("never lets an earlier FAILURE mark a later build broken", async () => {
    const settle: ((ok: boolean) => void)[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((res) => {
            settle.push((ok) =>
              res(
                ok
                  ? okResponse({ consensus_id: "c2", dump_paths: [A, B] })
                  : ({ ok: false, status: 500, text: async () => "boom" } as Response),
              ),
            );
          }),
      ),
    );

    const first = useConsensusStore.getState().runConsensus([A], false);
    const second = useConsensusStore.getState().runConsensus([A, B], false);

    settle[1](true);
    await second;
    settle[0](false);
    await first;

    const state = useConsensusStore.getState();
    expect(state.consensusId).toBe("c2");
    expect(state.error).toBeNull();
    expect(state.available).toBe(true);
  });

  it("keeps a finalized incremental build safe from a straggling run", async () => {
    const settle = deferredFetch();

    const run = useConsensusStore.getState().runConsensus([A, B], false);
    useConsensusStore.getState().adoptIncremental({
      consensusId: "session-1",
      size: 256,
      numDumps: 3,
      counts: null,
    });

    settle[0]({ consensus_id: "c1", dump_paths: [A, B] });
    await run;

    expect(useConsensusStore.getState().consensusId).toBe("session-1");
  });

  it("lets nothing in flight repopulate a store that has been reset", async () => {
    const settle = deferredFetch();

    const run = useConsensusStore.getState().runConsensus([A, B], false);
    useConsensusStore.getState().reset();

    settle[0]({ consensus_id: "c1", dump_paths: [A, B] });
    await run;

    expect(useConsensusStore.getState().consensusId).toBeNull();
  });
});

describe("consensus-store failed rebuild", () => {
  /**
   * A failed rebuild says nothing about the build already in the store: it was
   * computed over real dumps and, where `builtFrom` still covers the selection,
   * it is still the correct answer for them. Clearing `consensusId` here would
   * drop both multi-dump viewers behind `NoConsensusPrompt` and throw away a
   * usable alignment because a LATER request 500'd. What the failure must do is
   * be SAYABLE — `error` is the record `ConsensusErrorBanner` puts on the hex
   * surface, where the bytes it qualifies are.
   */
  it("leaves the previous build standing and records why the rebuild failed", async () => {
    useConsensusStore.setState({
      consensusId: "c1",
      builtFrom: [A, B],
      builtNormalized: false,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 500, text: async () => "boom" }) as Response),
    );

    await useConsensusStore.getState().runConsensus([A, B], true);

    const state = useConsensusStore.getState();
    expect(state.consensusId).toBe("c1");
    expect(state.builtFrom).toEqual([A, B]);
    expect(state.builtNormalized).toBe(false);
    expect(state.error).toMatch(/500/);
    expect(state.loading).toBe(false);
  });

  it("clears the record the moment another build starts", async () => {
    useConsensusStore.setState({ error: "boom" });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => okResponse({ consensus_id: "c2", dump_paths: [A, B] })),
    );

    await useConsensusStore.getState().runConsensus([A, B], false);

    expect(useConsensusStore.getState().error).toBeNull();
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
