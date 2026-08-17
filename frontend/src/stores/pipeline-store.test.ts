import { describe, it, expect } from "vitest";

import {
  reducePipelineEvent,
  usePipelineStore,
  type PipelineState,
} from "./pipeline-store";
import type {
  TaskProgressEvent,
  TaskProgressEventType,
} from "@/api/websocket";

/**
 * A complete, default PipelineState to reduce against. Grabbing the live
 * store's initial state gives every field (incl. the action closures) so we
 * only override the few slots each case exercises.
 */
function baseState(overrides: Partial<PipelineState> = {}): PipelineState {
  return { ...usePipelineStore.getState(), ...overrides };
}

/**
 * Builds one variant of the TaskProgressEvent union. Generic over the
 * ``type`` literal so ``fields`` is checked against that variant's own
 * ``extra`` shape (e.g. passing `{ extra: { survivor_bytes: 1 } }` for
 * "progress" vs. `{ extra: { total_bytes: 1 } }` for a "consensus"
 * `stage_end`) instead of the flattened shape a plain
 * `Partial<TaskProgressEvent>` would produce. The `as` is confined to
 * this test helper: TypeScript can't verify that spreading a
 * `Partial<Variant>` over the four common fields reconstructs exactly
 * `Variant`, but every field on the right of the spread is itself
 * type-checked against that variant, so this can't smuggle in a
 * mismatched shape.
 */
function event<T extends TaskProgressEventType>(
  type: T,
  fields: Partial<Extract<TaskProgressEvent, { type: T }>> = {},
): Extract<TaskProgressEvent, { type: T }> {
  return {
    task_id: "t1",
    type,
    seq: 1,
    ts: 100,
    ...fields,
  } as Extract<TaskProgressEvent, { type: T }>;
}

describe("reducePipelineEvent seq handling", () => {
  it("drops already-seen events (seq <= lastSeq) with an empty patch", () => {
    const patch = reducePipelineEvent(
      baseState({ lastSeq: 5 }),
      event("done", { seq: 3 }),
    );
    expect(patch).toEqual({});
  });

  it("advances lastSeq for newer events", () => {
    const patch = reducePipelineEvent(
      baseState({ lastSeq: 5 }),
      event("done", { seq: 6 }),
    );
    expect(patch.lastSeq).toBe(6);
  });

  it("does not gate seq==0 events on the dedup check", () => {
    // seq 0 skips the `seq > 0 && seq <= lastSeq` guard, and since 0 is not
    // > lastSeq no lastSeq patch is written, but the event still reduces.
    const patch = reducePipelineEvent(
      baseState({ lastSeq: 5 }),
      event("done", { seq: 0 }),
    );
    expect(patch.lastSeq).toBeUndefined();
    expect(patch.status).toBe("succeeded");
  });
});

describe("reducePipelineEvent stage_start", () => {
  it("flips idle -> running and seeds the active stage", () => {
    const patch = reducePipelineEvent(
      baseState({ status: "idle" }),
      event("stage_start", { stage: "consensus", msg: "starting" }),
    );
    expect(patch.status).toBe("running");
    expect(patch.activeStage).toBe("consensus");
    expect(patch.activeStagePct).toBe(0);
    expect(patch.activeStageMsg).toBe("starting");
  });

  it("does not overwrite status when already running", () => {
    const patch = reducePipelineEvent(
      baseState({ status: "running" }),
      event("stage_start", { stage: "reduce" }),
    );
    expect(patch.status).toBeUndefined();
    expect(patch.activeStageMsg).toBe("");
  });
});

describe("reducePipelineEvent progress", () => {
  it("updates active stage, pct and message", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("progress", { stage: "reduce", pct: 0.5, msg: "half" }),
    );
    expect(patch.activeStage).toBe("reduce");
    expect(patch.activeStagePct).toBe(0.5);
    expect(patch.activeStageMsg).toBe("half");
  });

  it("ignores negative pct sentinels", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("progress", { stage: "reduce", pct: -1 }),
    );
    expect(patch.activeStagePct).toBeUndefined();
  });

  it("folds search_reduce:variance survivor/input bytes into the funnel", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("progress", {
        stage: "search_reduce:variance",
        extra: { survivor_bytes: 400, input_bytes: 1000 },
      }),
    );
    expect(patch.funnel?.variance).toBe(400);
    expect(patch.funnel?.raw).toBe(1000);
  });

  it("maps search_reduce:entropy survivors into both high_entropy and candidates", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("progress", {
        stage: "search_reduce:entropy",
        extra: { survivor_bytes: 128 },
      }),
    );
    expect(patch.funnel?.high_entropy).toBe(128);
    expect(patch.funnel?.candidates).toBe(128);
  });
});

describe("reducePipelineEvent stage_end", () => {
  it("marks the stage complete (pct=1)", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", { stage: "reduce", msg: "done reduce" }),
    );
    expect(patch.activeStage).toBe("reduce");
    expect(patch.activeStagePct).toBe(1);
    expect(patch.activeStageMsg).toBe("done reduce");
  });

  it("records verified count and maps hits from a brute_force stage_end", () => {
    const patch = reducePipelineEvent(
      baseState({ consensusNumDumps: 4 }),
      event("stage_end", {
        stage: "brute_force",
        extra: {
          verified_count: 2,
          variance_threshold: 100,
          hits: [
            {
              offset: 16,
              length: 32,
              region_index: 1,
              key_hex: "deadbeef",
              neighborhood_start: 8,
              neighborhood_variance: [50, 200, 50],
            },
          ],
        },
      }),
    );
    expect(patch.funnel?.verified).toBe(2);
    expect(patch.hits).toEqual([
      {
        offset: 16,
        size: 32,
        region_index: 1,
        key_hex: "deadbeef",
        neighborhood_start: 8,
        neighborhood_variance: [50, 200, 50],
      },
    ]);
    // Two of three neighborhood values (50, 50) are <= threshold 100 -> static.
    expect(patch.convergenceHistory).toEqual([
      { n: 4, staticCount: 2, dynamicCount: 1 },
    ]);
  });

  it("seeds funnel.raw and consensusNumDumps from a consensus stage_end", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", {
        stage: "consensus",
        extra: { total_bytes: 4096, num_dumps: 5 },
      }),
    );
    expect(patch.funnel?.raw).toBe(4096);
    expect(patch.consensusNumDumps).toBe(5);
  });

  it("captures inferred fields from an emit_plugin stage_end", () => {
    const fields = [
      {
        offset: 0,
        length: 4,
        type: "static" as const,
        label: "magic",
        mean_variance: 0,
      },
    ];
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", { stage: "emit_plugin", extra: { fields } }),
    );
    expect(patch.inferredFields).toEqual(fields);
  });
});

describe("reducePipelineEvent nsweep_point", () => {
  it("appends a normalized point with defaulted fields", () => {
    const patch = reducePipelineEvent(
      baseState({ nsweepPoints: [] }),
      event("nsweep_point", {
        extra: { n: 3, stages: { variance: 10 }, candidates_tried: 7, hits: 1 },
      }),
    );
    expect(patch.nsweepPoints).toEqual([
      {
        n: 3,
        stages: { variance: 10 },
        candidates: 7,
        hits: 1,
        hit_offset: null,
        timing_ms: {},
      },
    ]);
  });

  it("ignores a point missing its n", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("nsweep_point", { extra: { stages: {} } }),
    );
    expect(patch.nsweepPoints).toBeUndefined();
  });
});

describe("reducePipelineEvent oracle_hit", () => {
  it("appends a hit onto the existing hits", () => {
    const existing = baseState({
      hits: [
        {
          offset: 0,
          size: 0,
          region_index: 0,
          key_hex: "",
          neighborhood_start: 0,
          neighborhood_variance: [],
        },
      ],
    });
    const patch = reducePipelineEvent(
      existing,
      event("oracle_hit", {
        extra: { offset: 64, size: 32, key_hex: "cafe" },
      }),
    );
    expect(patch.hits).toHaveLength(2);
    expect(patch.hits?.[1]).toMatchObject({
      offset: 64,
      size: 32,
      key_hex: "cafe",
    });
  });
});

describe("reducePipelineEvent artifact", () => {
  it("registers an artifact with defaulted metadata and the event ts", () => {
    const patch = reducePipelineEvent(
      baseState({ artifacts: [] }),
      event("artifact", {
        ts: 999,
        artifact: { name: "keys.json", relpath: "out/keys.json" },
      }),
    );
    expect(patch.artifacts).toEqual([
      {
        name: "keys.json",
        relpath: "out/keys.json",
        media_type: "application/octet-stream",
        size: 0,
        sha256: null,
        registered_at: 999,
      },
    ]);
  });

  it("ignores an artifact event without a name", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("artifact", { artifact: { name: "" } }),
    );
    expect(patch.artifacts).toBeUndefined();
  });
});

describe("reducePipelineEvent terminal events", () => {
  it("marks done as succeeded with a full progress bar", () => {
    const patch = reducePipelineEvent(baseState(), event("done"));
    expect(patch.status).toBe("succeeded");
    expect(patch.activeStagePct).toBe(1);
  });

  it("discriminates a cancelled error from a real failure", () => {
    const cancelled = reducePipelineEvent(
      baseState(),
      event("error", { error: "cancelled" }),
    );
    expect(cancelled.status).toBe("cancelled");
    expect(cancelled.error).toBeUndefined();

    const failed = reducePipelineEvent(
      baseState(),
      event("error", { error: "boom" }),
    );
    expect(failed.status).toBe("failed");
    expect(failed.error).toBe("boom");
  });

  it("defaults a failure with no message to 'unknown error'", () => {
    const patch = reducePipelineEvent(baseState(), event("error", {}));
    expect(patch.status).toBe("failed");
    expect(patch.error).toBe("unknown error");
  });
});
