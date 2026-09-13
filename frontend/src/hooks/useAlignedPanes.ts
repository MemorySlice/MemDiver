/**
 * The two pieces of plumbing the N-pane viewer and the aligned overlay share:
 * WHICH dumps are on screen, and KEEPING THEIR BYTES LOADED.
 *
 * Both layouts anchor on the same dump (`activeDumpId`, invariant I3 - the
 * focused dump IS the alignment anchor) and both feed the same
 * `multi-hex-store`, so extracting this keeps them from drifting into two
 * subtly different definitions of "the selection".
 */

import { useCallback, useEffect, useMemo } from "react";

import { useMslViewSizes } from "@/hooks/useMslViewSizes";
import { consensusCoversSelection, useConsensusStore } from "@/stores/consensus-store";
import { DEFAULT_DUMP_WEIGHT, useDumpRailStore } from "@/stores/dump-rail-store";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";

export interface AlignedSelection {
  /** The alignment anchor: the focused dump, or the first selected one. */
  anchor: DumpEntry | null;
  /** Every dump taking part in the analysis, in `dumps` order. */
  selected: DumpEntry[];
  selectedPaths: string[];
}

/**
 * The current selection, resolved to dump entries.
 *
 * An empty `selectedDumpIds` over a non-empty dump list means "everything"
 * (invariant I2), exactly as `getSelectedDumpPaths` reads it - spelling that
 * rule differently here is how a viewer ends up showing nothing while the
 * analysis runs over every dump.
 */
export function useAlignedSelection(): AlignedSelection {
  const dumps = useDumpStore((s) => s.dumps);
  const selectedDumpIds = useDumpStore((s) => s.selectedDumpIds);
  const activeDumpId = useDumpStore((s) => s.activeDumpId);

  return useMemo(() => {
    const byId = new Map(dumps.map((d) => [d.id, d]));
    const selected =
      selectedDumpIds.length === 0
        ? dumps
        : selectedDumpIds
            .map((id) => byId.get(id))
            .filter((d): d is DumpEntry => d !== undefined);
    const anchor = selected.find((d) => d.id === activeDumpId) ?? selected[0] ?? null;
    return { anchor, selected, selectedPaths: selected.map((d) => d.path) };
  }, [dumps, selectedDumpIds, activeDumpId]);
}

/**
 * Is there a consensus that actually DESCRIBES this selection?
 *
 * Both halves matter, and they were derived three times over — once in
 * `useAlignedWindowLoader`, once in each multi-dump viewer's render guard —
 * with three copies of the reasoning and, by the time this was extracted, two
 * different inputs. No consensus at all and the aligned-window request falls
 * back to `dump_paths`, which makes the server re-derive the whole consensus
 * for every 8 KiB chunk the user scrolls past. A consensus built over OTHER
 * dumps is worse: the server answers, the panes paint, and every class, gap and
 * "Differs" ring on screen is a confident statement about bytes nobody is
 * looking at.
 *
 * An EMPTY `builtFrom` is permissive — see `consensusCoversSelection`.
 */
export function useConsensusUsable(paths: readonly string[]): boolean {
  const consensusId = useConsensusStore((s) => s.consensusId);
  const builtFrom = useConsensusStore((s) => s.builtFrom);
  return consensusId !== null && consensusCoversSelection(builtFrom, paths);
}

/** A path can hold anything but a NUL byte, so this join round-trips exactly. */
const PATH_SEP = "\u0000";

/**
 * How many multi-dump viewers are currently mounted.
 *
 * `multi-hex-store` is module-global and has exactly ONE owner at a time — the
 * three viewers are mutually exclusive branches of a single `return` in
 * `Workspace.renderMain` — but that is a property of one `if` ladder, not
 * something the store enforces. Counting the mounts means the LAST viewer out
 * tears the cache down rather than the first, so a future split layout (or a
 * test that renders both) cannot wipe a live viewer's bytes.
 *
 * Module scope rather than store state for the same reason `retryTimers` is:
 * nothing renders it, and it is bookkeeping about this client, not data.
 */
let mountedLoaders = 0;

/**
 * Keeps both byte caches fed for the rows currently on screen.
 *
 * TWO stores, deliberately:
 *
 *  - `multi-hex-store` holds every selected dump's bytes in the anchor's window
 *    index space - what the panes and the overlay actually render;
 *  - `hex-store` holds the ANCHOR's own bytes, because `HexStatusBar` reads the
 *    byte at the cursor straight out of that store. Nothing else populates it
 *    while `HexViewer` is unmounted, so without this call the status bar's byte
 *    readout silently reads as empty for the whole session. That store's own
 *    `MAX_CHUNKS` eviction bounds the cost.
 *
 * `setDumpPath` runs in its own effect BEFORE the loader so `ensureChunksLoaded`
 * - which reads the live path via `getState()` - never fetches for the previous
 * anchor. It is a no-op when the path and format are unchanged, so re-focusing
 * the pane that is already focused costs nothing.
 *
 * NOTHING is fetched without a consensus that was built over THIS selection -
 * see `consensusUsable`. That is the fence, not the viewers' render guards.
 */
export function useAlignedWindowLoader(args: {
  anchor: DumpEntry | null;
  paths: string[];
  firstRow: number;
  lastRow: number;
}): void {
  const { anchor, paths, firstRow, lastRow } = args;
  const anchorPath = anchor?.path ?? null;
  const anchorFormat = anchor?.format ?? "raw";
  const anchorSize = anchor?.size ?? 0;
  const view = useHexStore((s) => s.viewMode);
  // The anchor's addressable size in the CURRENT view (raw/VAS/VA all differ
  // for an .msl). Subscribed so the loader re-runs when it settles; read live
  // inside the effect so a render in which `hex-store` still describes the
  // PREVIOUS anchor cannot bound this one's window.
  const storeFileSize = useHexStore((s) => s.fileSize);
  const storeDumpPath = useHexStore((s) => s.dumpPath);
  const consensusId = useConsensusStore((s) => s.consensusId);
  // The N-pane layouts never mount `HexViewer`, so this is the only thing that
  // teaches `hex-store` an .msl anchor's per-view sizes here. Until it answers,
  // all three sizes are the CONTAINER's — larger than the VAS projection, and
  // therefore a licence to ask for a window the dump does not hold.
  const sizesResolved = useMslViewSizes(anchorPath, anchorFormat);

  // Joined to a scalar: a fresh array identity on every render would re-fire
  // the loader effect on every tick, and `ensureLoaded`'s own dedupe would then
  // be the only thing standing between a scroll and a request storm.
  const pathKey = paths.join(PATH_SEP);
  const stablePaths = useMemo(
    () => (pathKey.length > 0 ? pathKey.split(PATH_SEP) : []),
    [pathKey],
  );

  // Computed over `stablePaths`, the same joined-and-split identity the fetch
  // itself is keyed by, so the fence and the request cannot disagree about
  // which selection they are talking about.
  const consensusUsable = useConsensusUsable(stablePaths);

  useEffect(() => {
    if (!anchorPath) return;
    useHexStore.getState().setDumpPath(anchorPath, anchorSize, anchorFormat);
  }, [anchorPath, anchorSize, anchorFormat]);

  // Dumps that left the selection keep their chunks alive in a cache keyed by
  // path, so without this a long session accumulates every dump ever selected
  // until the byte budget evicts them one at a time.
  useEffect(() => {
    useMultiHexStore.getState().releasePaths(stablePaths);
  }, [stablePaths]);

  /**
   * Tear the byte cache down when the last multi-dump viewer goes away.
   *
   * `reset()` had NO production caller, and the store outlives every viewer, so
   * two things leaked on unmount. A retry scheduled up to 4 s earlier still
   * fired, still passed every one of `scheduleRetry`'s guards — nothing had
   * been reset, so the identity, the request and the failure all still matched
   * — and issued a real POST that repopulated `byPath` and all three side maps
   * for a viewer that no longer exists. And the cache itself, up to the byte
   * budget, was never released for the rest of the tab's life.
   *
   * `reset()` is the one place every scheduled nudge dies, which is why the
   * teardown is a whole reset rather than a timer sweep: cancelling the timers
   * alone would need an export `multi-hex-store` does not offer.
   *
   * The cost is real and accepted: React runs every cleanup in a commit before
   * any setup, so switching between the side-by-side and overlay layouts does
   * go 1 -> 0 -> 1 and does refetch the visible window once. One request buys
   * back a bounded cache and a guaranteed-quiet unmount.
   */
  useEffect(() => {
    mountedLoaders += 1;
    return () => {
      mountedLoaders -= 1;
      if (mountedLoaders <= 0) {
        mountedLoaders = 0;
        useMultiHexStore.getState().reset();
      }
    };
  }, []);

  useEffect(() => {
    if (!anchorPath || firstRow < 0 || lastRow < firstRow) return;
    // One probe round trip, once per anchor. Firing before it lands would
    // bound the window by the container size and put a guaranteed
    // 400 "anchor offset does not name an addressable byte" on the wire —
    // and, on a re-anchor, would do it for every screen the user visits.
    if (!sizesResolved) return;
    // THE fence, and deliberately here rather than only in the viewers'
    // render guards. `HexOverlayPane` looks protected today only by accident:
    // this hook runs BEFORE its early return, and is saved solely because the
    // scroll element never mounts, so `firstVisibleIndex === -1`. Any
    // virtualizer change turns that accident into a request storm in the
    // wrong coordinate. Say it explicitly instead.
    if (!consensusUsable) return;
    const hex = useHexStore.getState();
    // Bound the prefetch by the anchor's addressable size, or the loader asks
    // for a window past the end of the dump the moment the user reaches the
    // last screen — see `chunkRangeForRows`. `undefined` means "not known
    // yet", which leaves the range unbounded rather than empty.
    const addressable =
      hex.dumpPath === anchorPath && hex.fileSize > 0
        ? hex.fileSize
        : anchorSize > 0
          ? anchorSize
          : undefined;
    useMultiHexStore.getState().ensureLoaded({
      anchorPath,
      view,
      paths: stablePaths,
      startRow: firstRow,
      endRow: lastRow,
      consensusId,
      anchorSize: addressable,
    });
    hex.ensureChunksLoaded(firstRow, lastRow);
  }, [
    anchorPath,
    anchorSize,
    view,
    stablePaths,
    firstRow,
    lastRow,
    consensusId,
    consensusUsable,
    sizesResolved,
    storeFileSize,
    storeDumpPath,
  ]);
}

/**
 * The coordinate an .msl anchor must be navigated in while N panes are on screen.
 *
 * "vas", not "va". Both are coordinate-correct for the aligned-window endpoint;
 * the VAS projection is the DENSE one, so the pane grid stays proportional to
 * the bytes the dump actually captured instead of spanning the whole sparse
 * virtual-address range with holes. The consensus overlay in the SINGLE-dump
 * `HexViewer` is the one path that specifically needs "va" — its per-byte
 * classification fetch is VA-keyed — and it keeps its own effect saying so.
 */
const MSL_PANE_VIEW = "vas" as const;

/**
 * Force an .msl anchor off the "raw" view whenever a multi-pane layout mounts.
 *
 * `POST /api/analysis/consensus/aligned-window` REFUSES `view="raw"` for an
 * .msl anchor, and it is right to: `MslDumpSource.va_to_file_offset` returns
 * the enclosing BLOCK HEADER's offset, so a peer read in raw coordinates would
 * hand back real bytes from the wrong address. But "raw" is the hex viewer's
 * default view, so without this the analyst clicks "Side by side" on the
 * primary file type and gets an error instead of bytes.
 *
 * This mirrors `HexViewer`'s consensus-overlay effect, loop guard included:
 * `setViewMode` is a no-op when the store is already in the target mode, so the
 * write cannot re-trigger the effect that made it.
 */
export function useMslPaneCoordinate(anchor: DumpEntry | null): void {
  const mainView = useDumpStore((s) => s.mainView);
  const viewMode = useHexStore((s) => s.viewMode);
  const setViewMode = useHexStore((s) => s.setViewMode);
  const format = anchor?.format ?? "raw";

  useEffect(() => {
    if (mainView !== "sideBySide" && mainView !== "overlay") return;
    if (format !== "msl") return;
    if (viewMode !== "raw") return;
    setViewMode(MSL_PANE_VIEW);
  }, [mainView, format, viewMode, setViewMode]);
}

/**
 * WHOSE bytes the overlay is painting, and how they are weighted.
 *
 * `HexOverlayPane` owns the grid and `HexStatusBar` writes the caption over it,
 * and both files carried a comment saying the two must not disagree — while
 * each re-derived the answer from `dump-rail-store` its own way: a different
 * solo resolution, a different included-paths expression, and two hardcoded
 * `?? 1`s where `DEFAULT_DUMP_WEIGHT` is the name of that number. The comments
 * are the argument for one source; this is it.
 *
 * Note `dump-rail-store` already exports `weightAt` / `isIncluded`, which look
 * like this hook. They read `get()`, so a component calling them never
 * re-renders when the answer changes — unusable from React, and they have no
 * production callers. This is built on the SUBSCRIBED collections instead.
 */
export interface OverlayComposition {
  /**
   * The soloed dump's path, or `null`.
   *
   * A solo left over from a PREVIOUS selection names a dump that is no longer
   * aligned, and reading its bytes would paint a stream nothing on screen
   * describes. It therefore reads as no solo at all.
   */
  soloPath: string | null;
  /** The same dump as an entry, for anything that needs its name. */
  soloDump: DumpEntry | null;
  /**
   * The dumps the `Σ Overlay` layer is a plurality OF.
   *
   * Exclusion is a rail decision and deliberately does NOT change the aligned
   * window request: the backend still compares every selected dump, so the
   * consensus classes, the `differs` runs and the variant counts keep
   * describing the whole set. Only the byte PAINTED is reduced over the
   * included subset, which is what makes toggling an eye instant instead of a
   * refetch.
   */
  includedPaths: string[];
  /** A path's plurality weight; `DEFAULT_DUMP_WEIGHT` when it has no entry. */
  weightFor: (path: string) => number;
}

export function useOverlayComposition(selected: readonly DumpEntry[]): OverlayComposition {
  const rawSoloPath = useDumpRailStore((s) => s.soloPath);
  const excludedPaths = useDumpRailStore((s) => s.excludedPaths);
  const weightByPath = useDumpRailStore((s) => s.weightByPath);

  const soloDump = useMemo(
    () => selected.find((d) => d.path === rawSoloPath) ?? null,
    [selected, rawSoloPath],
  );

  const includedPaths = useMemo(
    () => selected.map((d) => d.path).filter((path) => !excludedPaths.has(path)),
    [selected, excludedPaths],
  );

  const weightFor = useCallback(
    (path: string) => weightByPath.get(path) ?? DEFAULT_DUMP_WEIGHT,
    [weightByPath],
  );

  return { soloPath: soloDump?.path ?? null, soloDump, includedPaths, weightFor };
}
