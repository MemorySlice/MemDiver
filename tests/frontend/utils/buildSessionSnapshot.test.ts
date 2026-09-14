import { beforeEach, describe, expect, it, vi } from "vitest";

// Only the network edge is stubbed; every store stays real, so these cases
// fail if the payload builder ever stops translating ids or starts trusting
// JSON.stringify with a Set or a Map.
vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
  extractStrings: vi.fn(() => new Promise(() => {})),
}));

const { useDumpStore } = await import("@/stores/dump-store");
const { useDumpRailStore } = await import("@/stores/dump-rail-store");
const { useAppStore } = await import("@/stores/app-store");
const { buildSessionSnapshot } = await import("@/utils/buildSessionSnapshot");

const A = "/dumps/a.msl";
const B = "/dumps/b.msl";
const GONE = "/dumps/gone.msl";

/** Loads two dumps and returns their ids. */
function seed(): { a: string; b: string } {
  const store = useDumpStore.getState();
  const a = store.addDump({ path: A, name: "a.msl", size: 10, format: "msl" });
  const b = store.addDump({ path: B, name: "b.msl", size: 20, format: "msl" });
  return { a, b };
}

beforeEach(() => {
  useDumpStore.getState().clearAll();
  useDumpRailStore.getState().reset();
  useAppStore.setState({ inputPath: "", lastLoadedSnapshot: null });
});

describe("buildSessionSnapshot dump list", () => {
  it("writes dumps by path with only the four persistable fields", () => {
    seed();

    const snap = buildSessionSnapshot("s");

    expect(snap.dumps).toEqual([
      { path: A, name: "a.msl", size: 10, format: "msl" },
      { path: B, name: "b.msl", size: 20, format: "msl" },
    ]);
    // The destructure is the redaction: no id leaks either, because an id is
    // meaningless in a file that outlives the session that minted it.
    for (const entry of snap.dumps ?? []) {
      expect(Object.keys(entry).sort()).toEqual([
        "format",
        "name",
        "path",
        "size",
      ]);
    }
  });

  it("translates the active, origin and selected ids into paths", () => {
    const { b } = seed();
    useDumpStore.getState().setSelectedDumps([b]);

    const snap = buildSessionSnapshot("s");

    expect(snap.active_dump_path).toBe(B);
    expect(snap.selected_dump_paths).toEqual([B]);
    // The origin is still the first dump; it never follows the selection.
    expect(snap.origin_dump_path).toBe(A);
  });

  it("serializes the collapsed Set as an array, not as `{}`", () => {
    const { a } = seed();
    useDumpStore.getState().toggleDumpVisibility(a);

    const snap = buildSessionSnapshot("s");

    // `visibleDumps` is a Set and is really the COLLAPSED set; both facts are
    // load-bearing. JSON.stringify would have turned a Set into `{}`.
    expect(snap.collapsed_dump_paths).toEqual([A]);
    const wire = JSON.parse(JSON.stringify(snap)) as Record<string, unknown>;
    expect(wire.collapsed_dump_paths).toEqual([A]);
  });

  it("carries the main view and the ASLR toggle", () => {
    seed();
    useDumpStore.getState().setMainView("sideBySide");
    useDumpStore.getState().toggleAslrNormalize();

    const snap = buildSessionSnapshot("s");

    expect(snap.main_view).toBe("sideBySide");
    expect(snap.aslr_normalize).toBe(true);
  });
});

describe("buildSessionSnapshot rail state", () => {
  it("serializes the weight Map as an object, not as `{}`", () => {
    seed();
    useDumpRailStore.getState().setWeight(A, 1.5);

    const snap = buildSessionSnapshot("s");

    expect(snap.dump_weights).toEqual({ [A]: 1.5 });
    const wire = JSON.parse(JSON.stringify(snap)) as Record<string, unknown>;
    expect(wire.dump_weights).toEqual({ [A]: 1.5 });
  });

  it("serializes exclusions as an array and keeps the solo and collapse", () => {
    seed();
    useDumpRailStore.getState().toggleIncluded(B);
    useDumpRailStore.getState().setSolo(A);
    useDumpRailStore.getState().setCollapsed(true);

    const wire = JSON.parse(JSON.stringify(buildSessionSnapshot("s"))) as Record<
      string,
      unknown
    >;

    expect(wire.excluded_dump_paths).toEqual([B]);
    expect(wire.solo_dump_path).toBe(A);
    expect(wire.rail_collapsed).toBe(true);
  });

  it("prunes rail entries whose dump is no longer loaded", () => {
    seed();
    const rail = useDumpRailStore.getState();
    rail.setWeight(GONE, 0.5);
    rail.toggleIncluded(GONE);
    rail.setSolo(GONE);

    const snap = buildSessionSnapshot("s");

    // Stale keys would otherwise accumulate forever across save/load cycles.
    expect(snap.dump_weights).toEqual({});
    expect(snap.excluded_dump_paths).toEqual([]);
    // "" and not null: the wire contract declares a plain string, and the
    // backend answers a null here with a 422.
    expect(snap.solo_dump_path).toBe("");
  });
});

describe("buildSessionSnapshot input_path fallback", () => {
  it("keeps an explicit input_path", () => {
    seed();
    useAppStore.setState({ inputPath: "/dumps/wizard.msl" });

    expect(buildSessionSnapshot("s").input_path).toBe("/dumps/wizard.msl");
  });

  it("falls back to the origin dump for an AddDumpButton-only workspace", () => {
    seed();

    // SessionLanding renders `input_path`; without the fallback a workspace
    // assembled entirely through AddDumpButton would list as blank.
    expect(buildSessionSnapshot("s").input_path).toBe(A);
  });

  it("stays empty when there are no dumps at all", () => {
    expect(buildSessionSnapshot("s").input_path).toBe("");
  });
});

describe("buildSessionSnapshot secret redaction", () => {
  /**
   * Sessions are unprotected gzipped JSON under `~/.memdiver/sessions/`. The
   * explicit four-field destructure in the builder is the ONLY thing keeping
   * recovered key material off disk, so this is the case that fails the moment
   * someone replaces it with `dumps: dumpState.dumps`.
   */
  it("never writes keyMaterial or tagStatus into the payload", () => {
    const { a } = seed();
    useDumpStore.setState((state) => ({
      dumps: state.dumps.map((d) =>
        d.id === a
          ? {
              ...d,
              tagStatus: "valid" as const,
              keyMaterial: {
                passphrase: "hunter2-correct-horse",
                key_hex: "deadbeefcafe",
                kem_key_hex: "0badc0de",
              },
            }
          : d,
      ),
    }));

    const serialized = JSON.stringify(buildSessionSnapshot("s"));

    expect(serialized).not.toContain("hunter2-correct-horse");
    expect(serialized).not.toContain("deadbeefcafe");
    expect(serialized).not.toContain("0badc0de");
    expect(serialized).not.toContain("passphrase");
    expect(serialized).not.toContain("keyMaterial");
    // A stored "valid" without its key would make TagStatusBadge claim the
    // dump is unlocked when the key is gone.
    expect(serialized).not.toContain("tagStatus");
  });
});
