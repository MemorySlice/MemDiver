import { describe, it, expect, beforeEach } from "vitest";

import {
  reconcileSelection,
  useDumpStore,
  type SelectionShape,
} from "@/stores/dump-store";

/**
 * The multi-dump SELECTION MODEL.
 *
 * `selectedDumpIds` is the single source of truth for both pane membership and
 * analysis participation; `activeDumpId` is focus (the alignment anchor); and
 * `visibleDumps` is a transient view collapse inside the selection. The UX bug
 * these cases pin is the conflation of the first two: selecting a dump used to
 * move focus, and focusing one used to change what was analysed.
 *
 * Every invariant is restored by ONE pure function (`reconcileSelection`)
 * applied at the end of each action, so each case here is really asking "did
 * this action run the reconcile step?".
 */

function addDump(name: string): string {
  return useDumpStore.getState().addDump({
    path: `/dumps/${name}`,
    name,
    size: 1024,
    format: "raw",
  });
}

/** Adds n dumps and returns their ids in insertion order. */
function addDumps(...names: string[]): string[] {
  return names.map(addDump);
}

const s = () => useDumpStore.getState();

beforeEach(() => {
  useDumpStore.getState().clearAll();
});

describe("invariants", () => {
  it("I1: removeDump prunes the gone id out of selectedDumpIds", () => {
    const [a, b] = addDumps("a", "b");
    expect(s().selectedDumpIds).toEqual([a, b]);

    s().removeDump(b);

    expect(s().selectedDumpIds).toEqual([a]);
    expect(s().selectedDumpIds).not.toContain(b);
  });

  it("I1: an unknown id handed to setSelectedDumps is dropped", () => {
    const [a] = addDumps("a", "b");

    s().setSelectedDumps([a, "not-a-dump"]);

    expect(s().selectedDumpIds).toEqual([a]);
  });

  it("I1: duplicates collapse and the selection follows `dumps` order", () => {
    const [a, b, c] = addDumps("a", "b", "c");

    s().setSelectedDumps([c, a, c]);

    expect(s().selectedDumpIds).toEqual([a, c]);
    expect(b).toBeTruthy();
  });

  it("I2: an empty selection over a non-empty dump list means all of them", () => {
    const ids = addDumps("a", "b", "c");

    s().setSelectedDumps([]);

    expect(s().selectedDumpIds).toEqual(ids);
  });

  it("I2: clearDumpSelection therefore selects everything, not nothing", () => {
    const ids = addDumps("a", "b");

    s().clearDumpSelection();

    expect(s().selectedDumpIds).toEqual(ids);
  });

  it("I2: deselecting the last remaining dump re-selects all of them", () => {
    const [a, b] = addDumps("a", "b");
    s().setSelectedDumps([a]);

    s().toggleDumpSelected(a);

    expect(s().selectedDumpIds).toEqual([a, b]);
  });

  it("I3: activeDumpId is always one of the selected ids", () => {
    const [a, b, c] = addDumps("a", "b", "c");
    s().setActiveDump(a);

    s().setSelectedDumps([b, c]);

    expect(s().selectedDumpIds).toContain(s().activeDumpId);
    expect(s().activeDumpId).toBe(b);
  });

  it("I3 is NOT vacuous: skipping the reconcile step leaves focus dangling", () => {
    const [a, b] = addDumps("a", "b");
    s().setActiveDump(a);

    // What a naive implementation does: write the selection straight into the
    // store with no reconcile pass.
    useDumpStore.setState({ selectedDumpIds: [b] });

    expect(s().activeDumpId).toBe(a);
    expect(s().selectedDumpIds).not.toContain(s().activeDumpId); // I3 broken

    // The same edit through the action restores it.
    s().setSelectedDumps([b]);

    expect(s().activeDumpId).toBe(b);
    expect(s().selectedDumpIds).toContain(s().activeDumpId);
  });

  it("I3 is NOT vacuous: the pure reconcile is what repairs the state", () => {
    const broken: SelectionShape = {
      dumps: [
        { id: "a", path: "/a", name: "a", size: 1, format: "raw", sameProcess: true },
        { id: "b", path: "/b", name: "b", size: 1, format: "raw", sameProcess: true },
      ],
      activeDumpId: "a",
      selectedDumpIds: ["b"],
      visibleDumps: new Set<string>(),
      mainView: "single",
      originDumpId: "a",
    };

    expect(broken.selectedDumpIds).not.toContain(broken.activeDumpId);
    expect(reconcileSelection(broken).activeDumpId).toBe("b");
  });

  it("I4: mainView degrades to single when the selection drops below two", () => {
    const [a, b] = addDumps("a", "b");
    s().setMainView("sideBySide");
    expect(s().mainView).toBe("sideBySide");

    s().setSelectedDumps([a]);

    expect(s().mainView).toBe("single");
    expect(b).toBeTruthy();
  });

  it("I4: a multi-dump layout cannot be set with fewer than two selected", () => {
    addDumps("a");

    s().setMainView("overlay");

    expect(s().mainView).toBe("single");
  });

  it("I4: removing a dump down to one collapses the layout too", () => {
    const [, b] = addDumps("a", "b");
    s().setMainView("overlay");

    s().removeDump(b);

    expect(s().mainView).toBe("single");
  });

  it("I5: visibleDumps is pruned to the selection", () => {
    const [a, b] = addDumps("a", "b");
    s().toggleDumpVisibility(a);
    s().toggleDumpVisibility(b);
    expect(s().visibleDumps).toEqual(new Set([a, b]));

    s().setSelectedDumps([a]);

    expect(s().visibleDumps).toEqual(new Set([a]));
  });

  it("I5: visibility cannot be given to an unselected dump", () => {
    const [a, b] = addDumps("a", "b");
    s().setSelectedDumps([a]);

    s().toggleDumpVisibility(b);

    expect(s().visibleDumps.has(b)).toBe(false);
  });

  it("I6: originDumpId re-points to dumps[0] when its dump is removed", () => {
    const [a, b] = addDumps("a", "b");
    expect(s().originDumpId).toBe(a);

    s().removeDump(a);

    expect(s().originDumpId).toBe(b);
  });

  it("I6: originDumpId is null once there are no dumps", () => {
    const [a] = addDumps("a");

    s().removeDump(a);

    expect(s().originDumpId).toBeNull();
  });
});

describe("orthogonality of selection and focus", () => {
  it("changing the selection does not move focus while focus stays selected", () => {
    const [a, b, c] = addDumps("a", "b", "c");
    s().setActiveDump(b);

    s().setSelectedDumps([a, b]);
    expect(s().activeDumpId).toBe(b);

    s().toggleDumpSelected(c);
    expect(s().activeDumpId).toBe(b);

    s().selectAllDumps();
    expect(s().activeDumpId).toBe(b);
  });

  it("deselecting the focused dump moves focus to the first still-selected one", () => {
    const [a, b, c] = addDumps("a", "b", "c");
    s().setActiveDump(a);

    s().toggleDumpSelected(a);

    expect(s().selectedDumpIds).toEqual([b, c]);
    expect(s().activeDumpId).toBe(b);
  });

  it("changing focus never changes the selection", () => {
    const [a, b, c] = addDumps("a", "b", "c");
    s().setSelectedDumps([a, b, c]);
    const before = s().selectedDumpIds;

    s().setActiveDump(c);

    expect(s().activeDumpId).toBe(c);
    expect(s().selectedDumpIds).toEqual(before);
  });

  it("focusing an unselected dump selects it and keeps the rest of the selection", () => {
    const [a, b, c] = addDumps("a", "b", "c");
    s().setSelectedDumps([b, c]);

    s().setActiveDump(a);

    expect(s().activeDumpId).toBe(a);
    expect(s().selectedDumpIds).toContain(a);
    expect(s().selectedDumpIds).toEqual([a, b, c]);
  });

  it("focusing an id that is not a dump adds nothing and leaves focus on a real dump", () => {
    const [b, c] = addDumps("b", "c");
    s().setSelectedDumps([b, c]);

    s().setActiveDump("not-a-dump");

    expect(s().selectedDumpIds).toEqual([b, c]);
    expect(s().selectedDumpIds).not.toContain("not-a-dump");
    expect(s().activeDumpId).toBe(b);
  });

  it("focusing an already-selected dump leaves selectedDumpIds untouched", () => {
    const [a, b, c] = addDumps("a", "b", "c");
    s().setSelectedDumps([a, b, c]);
    const before = s().selectedDumpIds;

    s().setActiveDump(c);

    expect(s().activeDumpId).toBe(c);
    expect(s().selectedDumpIds).toBe(before);
    expect(s().selectedDumpIds).toEqual([a, b, c]);
  });

  it("changing focus does not change the layout", () => {
    const [a, b] = addDumps("a", "b");
    s().setMainView("sideBySide");

    s().setActiveDump(b);

    expect(s().mainView).toBe("sideBySide");
    expect(a).toBeTruthy();
  });
});

describe("addDump", () => {
  it("auto-selects every newly added dump", () => {
    const a = addDump("a");
    expect(s().selectedDumpIds).toEqual([a]);

    const b = addDump("b");
    expect(s().selectedDumpIds).toEqual([a, b]);
  });

  it("auto-selects a new dump even when the selection was narrowed", () => {
    const [a, b] = addDumps("a", "b");
    s().setSelectedDumps([a]);

    const c = addDump("c");

    expect(s().selectedDumpIds).toEqual([a, c]);
    expect(s().selectedDumpIds).not.toContain(b);
  });

  it("claims focus only when the list was empty", () => {
    const a = addDump("a");
    expect(s().activeDumpId).toBe(a);

    const b = addDump("b");
    expect(s().activeDumpId).toBe(a);
    expect(b).toBeTruthy();
  });

  it("does not move focus away from a dump the user picked", () => {
    const [, b] = addDumps("a", "b");
    s().setActiveDump(b);

    addDump("c");

    expect(s().activeDumpId).toBe(b);
  });
});

describe("removeDump", () => {
  it("prunes the id out of dumps, selectedDumpIds and visibleDumps", () => {
    const [a, b] = addDumps("a", "b");
    s().toggleDumpVisibility(b);
    expect(s().visibleDumps.has(b)).toBe(true);

    s().removeDump(b);

    expect(s().dumps.map((d) => d.id)).toEqual([a]);
    expect(s().selectedDumpIds).toEqual([a]);
    expect(s().visibleDumps.has(b)).toBe(false);
  });

  it("still re-points activeDumpId and drops a stale comparison pair", () => {
    const [a, b] = addDumps("a", "b");
    s().setComparisonPair(a, b);
    s().setActiveDump(a);

    s().removeDump(a);

    expect(s().activeDumpId).toBe(b);
    expect(s().comparisonDumpIds).toBeNull();
  });

  it("empties every collection when the last dump goes", () => {
    const a = addDump("a");

    s().removeDump(a);

    expect(s().dumps).toEqual([]);
    expect(s().selectedDumpIds).toEqual([]);
    expect(s().visibleDumps.size).toBe(0);
    expect(s().activeDumpId).toBeNull();
    expect(s().originDumpId).toBeNull();
  });
});

describe("getSelectedDumpPaths", () => {
  it("returns the selected paths in `dumps` order, not selection order", () => {
    const [a, b, c] = addDumps("a", "b", "c");
    s().setSelectedDumps([c, a]);

    expect(s().getSelectedDumpPaths()).toEqual(["/dumps/a", "/dumps/c"]);
    expect(b).toBeTruthy();
  });

  it("falls back to every dump path when the selection is empty", () => {
    // The invariants keep a non-empty dump list selected, so the empty case is
    // reachable only with no dumps at all -- or by a raw write that bypasses
    // them, which is exactly what the fallback protects against.
    addDumps("a", "b");
    useDumpStore.setState({ selectedDumpIds: [] });

    expect(s().getSelectedDumpPaths()).toEqual(["/dumps/a", "/dumps/b"]);
  });

  it("is empty when there are no dumps", () => {
    expect(s().getSelectedDumpPaths()).toEqual([]);
  });

  it("leaves the deprecated getDumpPaths returning every path", () => {
    const [a] = addDumps("a", "b");
    s().setSelectedDumps([a]);

    expect(s().getDumpPaths()).toEqual(["/dumps/a", "/dumps/b"]);
    expect(s().getSelectedDumpPaths()).toEqual(["/dumps/a"]);
  });
});

describe("originDumpId lifecycle", () => {
  it("is null before any dump is added", () => {
    expect(s().originDumpId).toBeNull();
  });

  it("is the first dump of the session", () => {
    const a = addDump("a");
    expect(s().originDumpId).toBe(a);
  });

  it("is not stolen by later dumps", () => {
    const a = addDump("a");
    addDump("b");
    addDump("c");

    expect(s().originDumpId).toBe(a);
  });

  it("survives selection and focus changes", () => {
    const [a, b, c] = addDumps("a", "b", "c");
    s().setSelectedDumps([b, c]);
    s().setActiveDump(c);

    expect(s().originDumpId).toBe(a);
  });

  it("re-points when its dump is removed, then clears with clearAll", () => {
    const [a, b] = addDumps("a", "b");

    s().removeDump(a);
    expect(s().originDumpId).toBe(b);

    s().clearAll();
    expect(s().originDumpId).toBeNull();
  });
});

describe("clearAll", () => {
  it("resets the selection model along with everything else", () => {
    const [a, b] = addDumps("a", "b");
    s().setMainView("overlay");
    s().toggleDumpVisibility(a);
    s().setComparisonPair(a, b);

    s().clearAll();

    expect(s().dumps).toEqual([]);
    expect(s().selectedDumpIds).toEqual([]);
    expect(s().visibleDumps.size).toBe(0);
    expect(s().activeDumpId).toBeNull();
    expect(s().originDumpId).toBeNull();
    expect(s().mainView).toBe("single");
    expect(s().comparisonDumpIds).toBeNull();
    expect(s().viewMode).toBe("single");
  });
});

describe("mainView", () => {
  it("defaults to single", () => {
    expect(s().mainView).toBe("single");
  });

  it("holds sideBySide and overlay once at least two dumps are selected", () => {
    addDumps("a", "b");

    s().setMainView("sideBySide");
    expect(s().mainView).toBe("sideBySide");

    s().setMainView("overlay");
    expect(s().mainView).toBe("overlay");
  });

  it("is independent of the deprecated pairwise viewMode", () => {
    addDumps("a", "b");

    s().setMainView("overlay");
    s().setViewMode("comparison");

    expect(s().mainView).toBe("overlay");
    expect(s().viewMode).toBe("comparison");
  });
});

describe("reference stability", () => {
  it("keeps the same selection array when an action changes nothing", () => {
    addDumps("a", "b");
    const before = s().selectedDumpIds;

    s().setActiveDump(s().activeDumpId as string);

    expect(s().selectedDumpIds).toBe(before);
  });

  it("keeps the same visibleDumps set when nothing is pruned", () => {
    const [a] = addDumps("a", "b");
    s().toggleDumpVisibility(a);
    const before = s().visibleDumps;

    s().selectAllDumps();

    expect(s().visibleDumps).toBe(before);
  });
});
