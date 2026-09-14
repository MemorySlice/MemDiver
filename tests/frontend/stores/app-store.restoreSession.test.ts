import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PathInfo, SessionSnapshot } from "@/api/types";

// Only the network edge is stubbed. `getPathInfo` is the one that matters
// here: the endpoint answers HTTP 200 with `exists: false` for a deleted file,
// so these cases drive it by RESOLVING, not by rejecting.
vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
  extractStrings: vi.fn(() => new Promise(() => {})),
}));

const { getPathInfo } = await import("@/api/client");
const { useAppStore } = await import("@/stores/app-store");
const { useDumpStore } = await import("@/stores/dump-store");
const { useDumpRailStore } = await import("@/stores/dump-rail-store");

const mockedGetPathInfo = vi.mocked(getPathInfo);

const A = "/dumps/a.msl";
const B = "/dumps/b.msl";
const C = "/dumps/c.raw";

function pathInfo(over: Partial<PathInfo> = {}): PathInfo {
  return {
    exists: true,
    is_file: true,
    is_directory: false,
    file_size: 4096,
    extension: ".msl",
    has_keylog: false,
    dump_count: 1,
    detected_mode: "single_file",
    ...over,
  };
}

/** A v1 snapshot: every multi-dump field absent, exactly as on disk. */
function v1Snapshot(over: Partial<SessionSnapshot> = {}): SessionSnapshot {
  return {
    schema_version: 1,
    memdiver_version: "0.0.0",
    created_at: "2026-01-01T00:00:00Z",
    session_name: "legacy",
    input_mode: "single_file",
    input_path: A,
    dataset_root: "",
    keylog_filename: "keylog.csv",
    template_name: "Auto-detect",
    protocol_name: "TLS",
    protocol_version: "1.3",
    scenario: "",
    selected_libraries: [],
    selected_phase: "",
    algorithm: "",
    mode: "verification",
    max_runs: 10,
    normalize_phases: false,
    selected_algorithms: [],
    single_file_format: "",
    ground_truth_mode: "auto",
    analysis_result: null,
    bookmarks: [],
    investigation_offset: null,
    ...over,
  };
}

function dumpEntry(path: string) {
  const name = path.split("/").pop() as string;
  return {
    path,
    name,
    size: 1234,
    format: name.endsWith(".msl") ? "msl" : "raw",
  };
}

/** A v2 snapshot carrying a real multi-dump workspace. */
function v2Snapshot(over: Partial<SessionSnapshot> = {}): SessionSnapshot {
  return v1Snapshot({
    schema_version: 2,
    session_name: "workspace",
    dumps: [dumpEntry(A), dumpEntry(B), dumpEntry(C)],
    active_dump_path: B,
    selected_dump_paths: [A, B],
    collapsed_dump_paths: [A],
    origin_dump_path: B,
    main_view: "sideBySide",
    aslr_normalize: true,
    dump_weights: { [B]: 1.5 },
    excluded_dump_paths: [A],
    solo_dump_path: B,
    rail_collapsed: true,
    ...over,
  });
}

const dumps = () => useDumpStore.getState().dumps;
const pathOf = (id: string | null) =>
  dumps().find((d) => d.id === id)?.path ?? null;

/** Lets the fire-and-forget resolution pass settle. */
async function flush(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await Promise.resolve();
}

beforeEach(() => {
  mockedGetPathInfo.mockReset();
  mockedGetPathInfo.mockResolvedValue(pathInfo());
  useDumpStore.getState().clearAll();
  useDumpRailStore.getState().reset();
  useAppStore.setState({ inputPath: "", lastLoadedSnapshot: null });
});

describe("restoreSession: legacy v1 snapshots", () => {
  it("still adds the single input_path dump", async () => {
    useAppStore.getState().restoreSession(v1Snapshot());

    expect(dumps().map((d) => d.path)).toEqual([A]);
    expect(pathOf(useDumpStore.getState().activeDumpId)).toBe(A);
    expect(pathOf(useDumpStore.getState().originDumpId)).toBe(A);

    await flush();
    expect(dumps()[0].size).toBe(4096);
    expect(dumps()[0].missing).toBe(false);
  });

  it("takes the legacy branch for a v2 file saved before any dump existed", () => {
    // Branching on `schema_version` instead of on the dump list would leave
    // this session with no dumps at all.
    useAppStore
      .getState()
      .restoreSession(v1Snapshot({ schema_version: 2, dumps: [] }));

    expect(dumps().map((d) => d.path)).toEqual([A]);
  });

  it("loads no dump for a dataset-mode session", () => {
    useAppStore
      .getState()
      .restoreSession(v1Snapshot({ input_mode: "dataset", input_path: "" }));

    expect(dumps()).toEqual([]);
    expect(mockedGetPathInfo).not.toHaveBeenCalled();
  });
});

describe("restoreSession: v2 multi-dump snapshots", () => {
  it("rehydrates every dump with the saved selection, focus, origin and view", () => {
    useAppStore.getState().restoreSession(v2Snapshot());

    const state = useDumpStore.getState();
    expect(state.dumps.map((d) => d.path)).toEqual([A, B, C]);
    expect(state.selectedDumpIds.map((id) => pathOf(id))).toEqual([A, B]);
    expect(pathOf(state.activeDumpId)).toBe(B);
    expect(pathOf(state.originDumpId)).toBe(B);
    expect([...state.visibleDumps].map((id) => pathOf(id))).toEqual([A]);
    expect(state.mainView).toBe("sideBySide");
    expect(state.aslrNormalize).toBe(true);
  });

  it("rehydrates the rail, storing the default weight as absence", () => {
    useAppStore.getState().restoreSession(v2Snapshot());

    const rail = useDumpRailStore.getState();
    expect(rail.weightAt(B)).toBe(1.5);
    expect(rail.weightByPath.has(A)).toBe(false);
    expect(rail.isIncluded(A)).toBe(false);
    expect(rail.soloPath).toBe(B);
    expect(rail.collapsed).toBe(true);
  });

  it("repairs a snapshot whose origin and view no longer make sense", () => {
    useAppStore.getState().restoreSession(
      v2Snapshot({
        dumps: [dumpEntry(A)],
        active_dump_path: "/dumps/deleted.msl",
        selected_dump_paths: ["/dumps/deleted.msl"],
        origin_dump_path: "/dumps/deleted.msl",
        main_view: "overlay",
      }),
    );

    const state = useDumpStore.getState();
    // I2/I3/I4/I6: the file is repaired rather than trusted.
    expect(pathOf(state.activeDumpId)).toBe(A);
    expect(state.selectedDumpIds.map((id) => pathOf(id))).toEqual([A]);
    expect(pathOf(state.originDumpId)).toBe(A);
    expect(state.mainView).toBe("single");
  });

  it("coerces an unknown main_view to single", () => {
    useAppStore
      .getState()
      .restoreSession(v2Snapshot({ main_view: "kaleidoscope" }));

    expect(useDumpStore.getState().mainView).toBe("single");
  });

  it("does not merge session B into session A", async () => {
    useAppStore.getState().restoreSession(v2Snapshot());
    await flush();

    useAppStore
      .getState()
      .restoreSession(v2Snapshot({ dumps: [dumpEntry(C)], active_dump_path: C, selected_dump_paths: [C], origin_dump_path: C, dump_weights: {}, excluded_dump_paths: [], solo_dump_path: "", rail_collapsed: false }));

    expect(dumps().map((d) => d.path)).toEqual([C]);
    // The rail is cleared too, or B's weight would silently reweight C's
    // consensus in a session that never mentioned it.
    expect(useDumpRailStore.getState().weightByPath.size).toBe(0);
    expect(useDumpRailStore.getState().soloPath).toBeNull();
  });
});

describe("restoreSession: missing files", () => {
  it("marks a dump missing when getPathInfo RESOLVES with exists:false", async () => {
    mockedGetPathInfo.mockResolvedValue(pathInfo({ exists: false, file_size: 0 }));

    useAppStore.getState().restoreSession(v2Snapshot({ dumps: [dumpEntry(A)] }));
    await flush();

    // The endpoint returns 200 for a deleted file, so a `catch` alone never
    // fires. The dump is KEPT — dropping it would let the next Ctrl+S autosave
    // quietly rewrite the analyst's workspace.
    expect(dumps()).toHaveLength(1);
    expect(dumps()[0].missing).toBe(true);
    expect(dumps()[0].size).toBe(1234);
    expect(useDumpStore.getState().selectedDumpIds).toHaveLength(1);
  });

  it("marks a dump missing when the path names a directory", async () => {
    mockedGetPathInfo.mockResolvedValue(
      pathInfo({ is_file: false, is_directory: true }),
    );

    useAppStore.getState().restoreSession(v2Snapshot({ dumps: [dumpEntry(A)] }));
    await flush();

    expect(dumps()[0].missing).toBe(true);
  });

  it("marks a dump missing when the request rejects outright", async () => {
    mockedGetPathInfo.mockRejectedValue(new Error("network down"));

    useAppStore.getState().restoreSession(v2Snapshot({ dumps: [dumpEntry(A)] }));
    await flush();

    expect(dumps()[0].missing).toBe(true);
    expect(dumps()[0].size).toBe(1234);
  });

  it("resolves a mixed workspace in one pass", async () => {
    mockedGetPathInfo.mockImplementation((path: string) =>
      Promise.resolve(
        path === B ? pathInfo({ exists: false }) : pathInfo({ file_size: 999 }),
      ),
    );

    useAppStore.getState().restoreSession(v2Snapshot());
    await flush();

    expect(dumps().map((d) => [d.path, d.missing, d.size])).toEqual([
      [A, false, 999],
      [B, true, 1234],
      [C, false, 999],
    ]);
    expect(mockedGetPathInfo).toHaveBeenCalledTimes(3);
  });
});

describe("restoreSession: the bare-return regression", () => {
  /**
   * `if (store.dumps.some(...)) return;` exited restoreSession ITSELF, so a
   * session whose input_path was already loaded skipped everything after it —
   * including the resolution pass added below it.
   */
  it("still runs the resolution pass when the path is already loaded", async () => {
    useDumpStore
      .getState()
      .addDump({ path: A, name: "a.msl", size: 1, format: "msl" });

    useAppStore.getState().restoreSession(v1Snapshot());
    await flush();

    expect(mockedGetPathInfo).toHaveBeenCalledWith(A);
    // Replaced wholesale, never duplicated.
    expect(dumps().map((d) => d.path)).toEqual([A]);
    expect(dumps()[0].size).toBe(4096);
  });

  it("dedupes a snapshot that lists the same path twice", () => {
    useAppStore
      .getState()
      .restoreSession(v2Snapshot({ dumps: [dumpEntry(A), dumpEntry(A)] }));

    expect(dumps().map((d) => d.path)).toEqual([A]);
  });
});
