import { create } from "zustand";
import { getTagStatus, probeTagStatusWithKey } from "@/api/client";
import type { TagStatus, KeyMaterial } from "@/api/types";

export interface DumpEntry {
  id: string;
  path: string;
  name: string;
  size: number;
  format: "raw" | "msl";
  /**
   * @deprecated Replaced by `selectedDumpIds`, which is the single source of
   * truth for both pane membership and analysis participation. Only `DumpList`
   * writes this flag and nothing reads it. Left in place (together with the
   * pairwise A/B comparison components) so existing callers keep working.
   */
  sameProcess: boolean;
  tagStatus?: TagStatus;
  keyMaterial?: KeyMaterial;
}

/**
 * Layout of the main analysis area over the CURRENT selection.
 *
 * This is deliberately a NEW field rather than a widening of `viewMode`: that
 * field's "overlay" token already means the pairwise `HexOverlay` component
 * driven by `comparisonDumpIds`. Adding an N-dump layout to it would make one
 * token select two different components depending on whether
 * `comparisonDumpIds` happens to be set. `mainView` is the N-dump layout;
 * `viewMode` stays the legacy pairwise switch. Not persisted to localStorage.
 */
export type MainView = "single" | "sideBySide" | "overlay";

/**
 * The slice of state the selection invariants relate to each other.
 *
 * Every invariant lives in `reconcileSelection` below — one pure function
 * applied at the end of every action that can disturb them — rather than in
 * scattered `useEffect`s that fight each other across a render.
 */
export interface SelectionShape {
  dumps: DumpEntry[];
  activeDumpId: string | null;
  selectedDumpIds: string[];
  visibleDumps: Set<string>;
  mainView: MainView;
  originDumpId: string | null;
}

function sameOrder(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}

/**
 * Restores every selection invariant in one place.
 *
 * | I1 | `selectedDumpIds` is a subset of the live dump ids (a pruned id would
 *        render a ghost pane after `removeDump`)                              |
 * | I2 | an empty selection over a non-empty dump list means "everything"      |
 * | I3 | `activeDumpId` is one of the selected ids — the focused pane IS the
 *        alignment anchor, so it cannot point outside the selection           |
 * | I4 | fewer than two selected dumps cannot be laid out side-by-side or
 *        overlaid, so `mainView` degrades to "single"                         |
 * | I5 | `visibleDumps` is a subset of `selectedDumpIds`                       |
 * | I6 | `originDumpId` re-points to `dumps[0]` when its dump is gone, and to
 *        null when there are no dumps                                         |
 *
 * Orthogonality, which the invariants must not break:
 *   - changing the SELECTION never changes FOCUS, except through I3 (the
 *     focused dump was just deselected, so focus moves to the first dump that
 *     is still selected);
 *   - changing FOCUS never changes the SELECTION, with ONE deliberate
 *     exception: focusing a dump that is not selected selects it. I3 would
 *     otherwise silently refuse the focus change, making a row click in
 *     DumpList look broken.
 *
 * Unchanged collections are returned by reference so a no-op action does not
 * wake every subscriber.
 */
export function reconcileSelection(next: SelectionShape): SelectionShape {
  const order = next.dumps.map((d) => d.id);
  const live = new Set(order);

  // I1: drop unknown ids (and duplicates), normalised to `dumps` order so that
  // "the first selected dump" means the same thing everywhere.
  const requested = new Set(next.selectedDumpIds.filter((id) => live.has(id)));
  let selected = order.filter((id) => requested.has(id));

  // I2: an empty selection over a non-empty list means "all of them".
  if (selected.length === 0 && order.length > 0) {
    selected = order;
  }

  // I3: the focused pane must be one of the rendered ones.
  let activeDumpId = next.activeDumpId;
  if (selected.length === 0) {
    activeDumpId = null;
  } else if (activeDumpId === null || !selected.includes(activeDumpId)) {
    activeDumpId = selected[0];
  }

  // I4: a multi-dump layout needs at least two dumps to lay out.
  const mainView: MainView = selected.length < 2 ? "single" : next.mainView;

  // I5: visibility is a view collapse WITHIN the selection, never outside it.
  const stillVisible = [...next.visibleDumps].filter((id) =>
    selected.includes(id),
  );
  const visibleDumps =
    stillVisible.length === next.visibleDumps.size
      ? next.visibleDumps
      : new Set(stillVisible);

  // I6: the ORIGIN badge follows the first surviving dump.
  let originDumpId = next.originDumpId;
  if (originDumpId === null || !live.has(originDumpId)) {
    originDumpId = order.length > 0 ? order[0] : null;
  }

  return {
    dumps: next.dumps,
    activeDumpId,
    selectedDumpIds: sameOrder(next.selectedDumpIds, selected)
      ? next.selectedDumpIds
      : selected,
    visibleDumps,
    mainView,
    originDumpId,
  };
}

interface DumpState extends SelectionShape {
  /**
   * @deprecated Superseded by `mainView`, which lays out the whole selection.
   * Still drives the pairwise A/B components, which are intentionally left in
   * place.
   */
  comparisonDumpIds: [string, string] | null;
  /**
   * @deprecated Superseded by `mainView`. This token set ("overlay" in
   * particular) belongs to the pairwise `HexOverlay` component and is kept for
   * it; new layout work goes through `mainView`.
   */
  viewMode: "single" | "comparison" | "overlay";
  aslrNormalize: boolean;

  addDump: (entry: Omit<DumpEntry, "id" | "sameProcess">) => string;
  removeDump: (id: string) => void;
  setActiveDump: (id: string) => void;
  /**
   * @deprecated Superseded by `setSelectedDumps` / `toggleDumpSelected`. Kept
   * for the pairwise A/B components, which are intentionally left in place.
   */
  setComparisonPair: (a: string, b: string) => void;
  /**
   * @deprecated Superseded by `setMainView`. Kept for the pairwise A/B
   * components, which are intentionally left in place.
   */
  setViewMode: (mode: "single" | "comparison" | "overlay") => void;
  setMainView: (view: MainView) => void;
  toggleAslrNormalize: () => void;
  /**
   * @deprecated `DumpEntry.sameProcess` is read by nothing; membership is
   * expressed by `selectedDumpIds` instead. Kept so existing callers (and the
   * pairwise A/B components) keep working.
   */
  toggleSameProcess: (id: string) => void;
  fetchTagStatus: (id: string) => Promise<void>;
  unlockTagStatus: (
    id: string,
    secret: KeyMaterial,
  ) => Promise<TagStatus>;
  setSelectedDumps: (ids: string[]) => void;
  toggleDumpSelected: (id: string) => void;
  selectAllDumps: () => void;
  clearDumpSelection: () => void;
  toggleDumpVisibility: (id: string) => void;
  clearAll: () => void;
  /**
   * @deprecated Use `getSelectedDumpPaths`, which honours the user's selection
   * instead of always returning every loaded dump.
   */
  getDumpPaths: () => string[];
  getSelectedDumpPaths: () => string[];
  getKeyMaterial: (id: string) => KeyMaterial | undefined;
  getKeyMaterialByPath: (path: string) => KeyMaterial | undefined;
}

/** Applies `patch` on top of the current selection slice, then reconciles it. */
function withInvariants(
  state: SelectionShape,
  patch: Partial<SelectionShape> = {},
): SelectionShape {
  return reconcileSelection({
    dumps: state.dumps,
    activeDumpId: state.activeDumpId,
    selectedDumpIds: state.selectedDumpIds,
    visibleDumps: state.visibleDumps,
    mainView: state.mainView,
    originDumpId: state.originDumpId,
    ...patch,
  });
}

export const useDumpStore = create<DumpState>((set, get) => ({
  dumps: [],
  activeDumpId: null,
  comparisonDumpIds: null,
  viewMode: "single",
  mainView: "single",
  aslrNormalize: false,
  /**
   * The dumps taking part in the analysis. Single source of truth for BOTH
   * pane membership and analysis participation.
   */
  selectedDumpIds: [],
  /**
   * Transient view collapse — NOT analysis membership. A dump hidden here is
   * still selected, still analysed, and still contributes to the comparison;
   * only its pane is folded away. Membership is `selectedDumpIds`.
   */
  visibleDumps: new Set<string>(),
  /**
   * The dump the session started from, for the ORIGIN badge.
   *
   * Stored rather than derived from `app-store.inputPath` because the two
   * genuinely diverge: `FileUpload` and `DatasetOverview.openDump` add dumps
   * that have no relationship to `inputPath`, and `resetWizard` clears
   * `inputPath` while `clearAll` runs separately.
   */
  originDumpId: null,

  addDump: (entry) => {
    const id = crypto.randomUUID();
    const newDump: DumpEntry = { ...entry, id, sameProcess: true };
    set((state) => {
      const wasEmpty = state.dumps.length === 0;
      return withInvariants(state, {
        dumps: [...state.dumps, newDump],
        // Unchanged behaviour: a new dump only claims focus when the list was
        // empty, so adding a dump never yanks the user out of the pane they
        // are reading.
        activeDumpId: wasEmpty ? id : state.activeDumpId,
        // New dumps join the analysis immediately.
        selectedDumpIds: [...state.selectedDumpIds, id],
        // The first dump of a session is its origin; later ones never steal it.
        originDumpId: wasEmpty ? id : state.originDumpId,
      });
    });
    return id;
  },

  removeDump: (id) =>
    set((state) => {
      const remaining = state.dumps.filter((d) => d.id !== id);
      let nextActive = state.activeDumpId;
      if (state.activeDumpId === id) {
        nextActive = remaining.length > 0 ? remaining[0].id : null;
      }
      let nextComparison = state.comparisonDumpIds;
      if (nextComparison && (nextComparison[0] === id || nextComparison[1] === id)) {
        nextComparison = null;
      }
      return {
        comparisonDumpIds: nextComparison,
        // I1/I5/I6 prune the removed id out of `selectedDumpIds` and
        // `visibleDumps` and re-point `originDumpId`; no separate filtering
        // here, so there is exactly one place that knows the rules.
        ...withInvariants(state, { dumps: remaining, activeDumpId: nextActive }),
      };
    }),

  // Focusing a dump implies selecting it. The focused pane IS the alignment
  // anchor (I3), so focusing something outside the selection would otherwise be
  // silently refused -- a row click in `DumpList` that visibly does nothing.
  // Widening the selection is the intent-preserving direction. An id that names
  // no live dump is never added; I3 repairs `activeDumpId` instead.
  setActiveDump: (id) =>
    set((state) => {
      const known = state.dumps.some((d) => d.id === id);
      const selectedDumpIds =
        known && !state.selectedDumpIds.includes(id)
          ? [...state.selectedDumpIds, id]
          : state.selectedDumpIds;
      return withInvariants(state, { activeDumpId: id, selectedDumpIds });
    }),

  setComparisonPair: (a, b) => set({ comparisonDumpIds: [a, b] }),

  setViewMode: (mode) => set({ viewMode: mode }),

  setMainView: (view) => set((state) => withInvariants(state, { mainView: view })),

  toggleAslrNormalize: () =>
    set((state) => ({ aslrNormalize: !state.aslrNormalize })),

  toggleSameProcess: (id) =>
    set((state) => ({
      dumps: state.dumps.map((d) =>
        d.id === id ? { ...d, sameProcess: !d.sameProcess } : d,
      ),
    })),

  fetchTagStatus: async (id) => {
    const dump = get().dumps.find((d) => d.id === id);
    if (!dump || dump.format !== "msl") return;
    try {
      const { tag_status } = await getTagStatus(dump.path);
      set((state) => ({
        dumps: state.dumps.map((d) =>
          d.id === id ? { ...d, tagStatus: tag_status } : d,
        ),
      }));
    } catch {
      // Tag status is advisory; leave undefined on failure.
    }
  },

  unlockTagStatus: async (id, secret) => {
    const dump = get().dumps.find((d) => d.id === id);
    if (!dump) throw new Error("Dump not found");
    const { tag_status } = await probeTagStatusWithKey(dump.path, secret);
    set((state) => ({
      dumps: state.dumps.map((d) =>
        d.id === id
          ? {
              ...d,
              tagStatus: tag_status,
              // Remember the unlocking key only when it actually worked.
              keyMaterial: tag_status === "valid" ? secret : d.keyMaterial,
            }
          : d,
      ),
    }));
    return tag_status;
  },

  setSelectedDumps: (ids) =>
    set((state) => withInvariants(state, { selectedDumpIds: ids })),

  toggleDumpSelected: (id) =>
    set((state) => {
      const selected = state.selectedDumpIds.includes(id)
        ? state.selectedDumpIds.filter((s) => s !== id)
        : [...state.selectedDumpIds, id];
      // Deselecting the last dump leaves an empty selection, which I2 reads as
      // "all of them" rather than as "analyse nothing".
      return withInvariants(state, { selectedDumpIds: selected });
    }),

  selectAllDumps: () =>
    set((state) =>
      withInvariants(state, { selectedDumpIds: state.dumps.map((d) => d.id) }),
    ),

  // Clearing the selection is I2's "everything" on a non-empty dump list.
  clearDumpSelection: () => set((state) => withInvariants(state, { selectedDumpIds: [] })),

  toggleDumpVisibility: (id) =>
    set((state) => {
      const next = new Set(state.visibleDumps);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return withInvariants(state, { visibleDumps: next });
    }),

  clearAll: () =>
    set({
      dumps: [],
      activeDumpId: null,
      comparisonDumpIds: null,
      viewMode: "single",
      mainView: "single",
      aslrNormalize: false,
      selectedDumpIds: [],
      visibleDumps: new Set<string>(),
      originDumpId: null,
    }),

  getDumpPaths: () => get().dumps.map((d) => d.path),

  getSelectedDumpPaths: () => {
    const { dumps, selectedDumpIds } = get();
    // An empty selection means "everything", so nothing regresses for callers
    // that never touch the selection UI.
    if (selectedDumpIds.length === 0) return dumps.map((d) => d.path);
    const chosen = new Set(selectedDumpIds);
    return dumps.filter((d) => chosen.has(d.id)).map((d) => d.path);
  },

  getKeyMaterial: (id) => get().dumps.find((d) => d.id === id)?.keyMaterial,

  getKeyMaterialByPath: (path) =>
    get().dumps.find((d) => d.path === path)?.keyMaterial,
}));
