import { describe, expect, it } from "vitest";

import { snapshotDigest } from "@/utils/session-digest";

describe("snapshotDigest", () => {
  it("ignores the fields that say which save this is", () => {
    const before = snapshotDigest({
      session_name: "monday",
      schema_version: 1,
      memdiver_version: "0.1.0",
      created_at: "2026-01-01T00:00:00",
      input_path: "/dumps/a.msl",
    });
    const after = snapshotDigest({
      session_name: "tuesday",
      schema_version: 2,
      memdiver_version: "0.2.0",
      created_at: "2026-09-14T12:00:00",
      input_path: "/dumps/a.msl",
    });

    expect(after).toBe(before);
  });

  it("is stable across key order, including nested objects", () => {
    // A snapshot that has been round-tripped through the API comes back with
    // its nested analysis_result keys reordered; that must not read as a change.
    const built = snapshotDigest({
      input_path: "/dumps/a.msl",
      analysis_result: { hits: [{ offset: 16, length: 32 }], algorithm: "entropy" },
    } as never);
    const roundTripped = snapshotDigest({
      analysis_result: { algorithm: "entropy", hits: [{ length: 32, offset: 16 }] },
      input_path: "/dumps/a.msl",
    } as never);

    expect(roundTripped).toBe(built);
  });

  it("keeps array order significant", () => {
    // Selection order is meaningful in the workspace, unlike key order.
    const ab = snapshotDigest({ selected_libraries: ["a", "b"] } as never);
    const ba = snapshotDigest({ selected_libraries: ["b", "a"] } as never);

    expect(ba).not.toBe(ab);
  });

  it("treats an absent key and an undefined value as the same thing", () => {
    const absent = snapshotDigest({ input_path: "/dumps/a.msl" });
    const undefinedValue = snapshotDigest({
      input_path: "/dumps/a.msl",
      dataset_root: undefined,
    } as never);

    expect(undefinedValue).toBe(absent);
  });

  it("notices a field it has never been told about", () => {
    // The denylist contract: anything not explicitly volatile counts, so the
    // payload can grow without this module knowing.
    const without = snapshotDigest({ input_path: "/dumps/a.msl" });
    const with_ = snapshotDigest({
      input_path: "/dumps/a.msl",
      some_future_field: ["a", "b"],
    } as never);

    expect(with_).not.toBe(without);
  });

  it("notices real changes to the workspace", () => {
    const one = snapshotDigest({ bookmarks: [{ offset: 0, length: 4, label: "x" }] });
    const two = snapshotDigest({
      bookmarks: [
        { offset: 0, length: 4, label: "x" },
        { offset: 8, length: 4, label: "y" },
      ],
    });

    expect(two).not.toBe(one);
  });

  it("reads an undigestable snapshot as changed rather than as clean", () => {
    // Uncertainty must resolve toward "dirty": a false positive costs one
    // dialog, a false negative costs the analyst their work.
    const cyclic: Record<string, unknown> = { input_path: "/dumps/a.msl" };
    cyclic.self = cyclic;

    const first = snapshotDigest(cyclic as never);
    const second = snapshotDigest(cyclic as never);

    expect(first).not.toBe(second);
  });
});
