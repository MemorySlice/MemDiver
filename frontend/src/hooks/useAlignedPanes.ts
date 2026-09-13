/**
 * The two pieces of plumbing the N-pane viewer and the aligned overlay share:
 * WHICH dumps are on screen, and KEEPING THEIR BYTES LOADED.
 *
 * Both layouts anchor on the same dump (`activeDumpId`, invariant I3 - the
 * focused dump IS the alignment anchor) and both feed the same
 * `multi-hex-store`, so extracting this keeps them from drifting into two
 * subtly different definitions of "the selection".
 */

import { useEffect, useMemo } from "react";

import { useMslViewSizes } from "@/hooks/useMslViewSizes";
import { useConsensusStore } from "@/stores/consensus-store";
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

/** A path can hold anything but a NUL byte, so this join round-trips exactly. */
const PATH_SEP = "\u0000";

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

  useEffect(() => {
    if (!anchorPath || firstRow < 0 || lastRow < firstRow) return;
    // One probe round trip, once per anchor. Firing before it lands would
    // bound the window by the container size and put a guaranteed
    // 400 "anchor offset does not name an addressable byte" on the wire —
    // and, on a re-anchor, would do it for every screen the user visits.
    if (!sizesResolved) return;
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
