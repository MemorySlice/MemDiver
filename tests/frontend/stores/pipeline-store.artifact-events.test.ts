import { afterEach, describe, it, expect } from "vitest";

import { usePipelineStore } from "@/stores/pipeline-store";
import type {
  ProgressArtifact,
  TaskProgressEvent,
  TaskProgressEventType,
} from "@/api/websocket";

/**
 * Live ``artifact`` events, end to end through ``ingestEvent``.
 *
 * The reducer's ``case "artifact"`` branch was unreachable for as long as no
 * backend producer emitted ``type: "artifact"`` -- every artifact the UI
 * showed arrived via ``hydrateFromRecord`` folding a finished
 * ``TaskRecord``. A producer now emits them mid-run, so these cases pin the
 * mapping the branch performs on the wire payload (the ``relpath``/``path``
 * fallback, the three defaults, the ``registered_at`` = ``event.ts`` clock),
 * that it appends rather than replaces, and that the ``done`` event which
 * follows does not wipe what was collected.
 *
 * Driven through the store action rather than the pure reducer on purpose:
 * the accumulation and the done-event interaction are only observable once
 * successive patches are actually applied to the store.
 */

/**
 * Builds one variant of the TaskProgressEvent union. Generic over the
 * ``type`` literal so ``fields`` is checked against that variant's own
 * shape. Mirrors the helper in ``pipeline-store.test.ts``; the ``as`` is
 * confined here because TypeScript cannot verify that spreading a
 * ``Partial<Variant>`` over the four common fields reconstructs exactly
 * ``Variant``, though every field on the right of the spread is itself
 * checked against that variant.
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

describe("pipeline-store live artifact events", () => {
  const PRISTINE = usePipelineStore.getState();

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
    localStorage.clear();
  });

  it("appends one fully-mapped artifact for a complete payload", () => {
    usePipelineStore.getState().ingestEvent(
      event("artifact", {
        seq: 1,
        ts: 1712345678.5,
        artifact: {
          name: "keylog",
          relpath: "emit/keys.keylog",
          media_type: "text/plain",
          size: 512,
          sha256: "abc123",
        },
      }),
    );

    const { artifacts, lastSeq } = usePipelineStore.getState();
    expect(artifacts).toEqual([
      {
        name: "keylog",
        relpath: "emit/keys.keylog",
        media_type: "text/plain",
        size: 512,
        sha256: "abc123",
        // Stamped from the event clock, not from Date.now(), so a replayed
        // event registers the time the producer saw.
        registered_at: 1712345678.5,
      },
    ]);
    expect(lastSeq).toBe(1);
  });

  it("falls back to ``path`` when the payload has no ``relpath``", () => {
    usePipelineStore.getState().ingestEvent(
      event("artifact", {
        seq: 1,
        artifact: { name: "plugin", path: "emit/plugin.py" },
      }),
    );

    expect(usePipelineStore.getState().artifacts[0].relpath).toBe(
      "emit/plugin.py",
    );
  });

  it("prefers ``relpath`` when the payload carries both", () => {
    usePipelineStore.getState().ingestEvent(
      event("artifact", {
        seq: 1,
        artifact: {
          name: "plugin",
          relpath: "emit/plugin.py",
          path: "/abs/run-1/emit/plugin.py",
        },
      }),
    );

    expect(usePipelineStore.getState().artifacts[0].relpath).toBe(
      "emit/plugin.py",
    );
  });

  it("yields an empty relpath when the payload carries neither", () => {
    usePipelineStore
      .getState()
      .ingestEvent(event("artifact", { seq: 1, artifact: { name: "orphan" } }));

    expect(usePipelineStore.getState().artifacts[0].relpath).toBe("");
  });

  it("defaults media_type, size and sha256 for a minimal payload", () => {
    usePipelineStore.getState().ingestEvent(
      event("artifact", {
        seq: 1,
        ts: 42,
        artifact: { name: "variance" },
      }),
    );

    expect(usePipelineStore.getState().artifacts[0]).toEqual({
      name: "variance",
      relpath: "",
      media_type: "application/octet-stream",
      size: 0,
      sha256: null,
      registered_at: 42,
    });
  });

  it("accumulates successive artifacts in arrival order", () => {
    const store = usePipelineStore.getState();
    store.ingestEvent(
      event("artifact", {
        seq: 1,
        ts: 10,
        artifact: { name: "variance", relpath: "consensus/variance.npy" },
      }),
    );
    store.ingestEvent(
      event("artifact", {
        seq: 2,
        ts: 20,
        artifact: { name: "keylog", relpath: "emit/keys.keylog" },
      }),
    );

    const { artifacts, lastSeq } = usePipelineStore.getState();
    expect(artifacts.map((a) => a.name)).toEqual(["variance", "keylog"]);
    expect(artifacts.map((a) => a.registered_at)).toEqual([10, 20]);
    expect(lastSeq).toBe(2);
  });

  it("ignores an artifact event with no artifact payload at all", () => {
    usePipelineStore.getState().ingestEvent(event("artifact", { seq: 1 }));
    expect(usePipelineStore.getState().artifacts).toEqual([]);

    usePipelineStore
      .getState()
      .ingestEvent(event("artifact", { seq: 2, artifact: null }));
    expect(usePipelineStore.getState().artifacts).toEqual([]);
  });

  it("ignores an artifact payload with no usable name", () => {
    const store = usePipelineStore.getState();
    // The wire type declares ``name`` required, so the empty string is the
    // shape a real producer can actually deliver; the missing-key case is
    // cast in to prove the ``?.`` guard covers it too rather than throwing.
    store.ingestEvent(event("artifact", { seq: 1, artifact: { name: "" } }));
    store.ingestEvent(
      event("artifact", {
        seq: 2,
        artifact: { relpath: "emit/nameless" } as ProgressArtifact,
      }),
    );

    expect(usePipelineStore.getState().artifacts).toEqual([]);
  });

  it("keeps live artifacts across the terminal done event", () => {
    const store = usePipelineStore.getState();
    store.ingestEvent(
      event("artifact", {
        seq: 1,
        ts: 10,
        artifact: { name: "variance", relpath: "consensus/variance.npy" },
      }),
    );
    store.ingestEvent(
      event("artifact", {
        seq: 2,
        ts: 20,
        artifact: { name: "keylog", relpath: "emit/keys.keylog" },
      }),
    );
    store.ingestEvent(event("done", { seq: 3, ts: 30 }));

    const s = usePipelineStore.getState();
    expect(s.status).toBe("succeeded");
    expect(s.activeStagePct).toBe(1);
    expect(s.artifacts.map((a) => a.name)).toEqual(["variance", "keylog"]);
  });

  it("drops a replayed artifact event whose seq was already seen", () => {
    const store = usePipelineStore.getState();
    store.ingestEvent(
      event("artifact", {
        seq: 4,
        ts: 10,
        artifact: { name: "variance", relpath: "consensus/variance.npy" },
      }),
    );
    // Same seq back off the WebSocket ring buffer on reconnect.
    store.ingestEvent(
      event("artifact", {
        seq: 4,
        ts: 10,
        artifact: { name: "variance", relpath: "consensus/variance.npy" },
      }),
    );

    expect(usePipelineStore.getState().artifacts).toHaveLength(1);
  });
});
