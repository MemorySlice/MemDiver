import { useCallback, useEffect, useMemo, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useHexStore } from "@/stores/hex-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { HexRow } from "./HexRow";
import { HexToolbar } from "./HexToolbar";
import { HexLegend } from "./HexLegend";
import { HexStatusBar } from "./HexStatusBar";
import { SearchMinimap } from "./SearchMinimap";
import { ConsensusVarianceMinimap } from "./ConsensusVarianceMinimap";
import { buildRegionIndex } from "./highlight-utils";
import { windowCount, clampWindowStart } from "./window-utils";
import { useHexKeyboard } from "@/hooks/useHexKeyboard";
import { useHexScrollTarget } from "@/hooks/useHexScrollTarget";
import { useMslViewSizes } from "@/hooks/useMslViewSizes";

const BYTES_PER_ROW = 16;

interface Props {
  dumpPath: string;
  fileSize: number;
  format?: string;
  onOffsetClick?: (offset: number) => void;
}

export function HexViewer({ dumpPath, fileSize, format = "raw", onOffsetClick }: Props) {
  const { t } = useTranslation("hex");
  const containerRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Per-field selectors so chunk-load writes (which replace the store
  // object on every set()) do not re-render the TanStack Virtual loop
  // unless a field this component actually reads has changed.
  const setDumpPath = useHexStore((s) => s.setDumpPath);
  const storeFileSize = useHexStore((s) => s.fileSize);
  const viewMode = useHexStore((s) => s.viewMode);
  const setViewMode = useHexStore((s) => s.setViewMode);
  // Base VA that "va"-view offset 0 maps to; consensus overlay in the "va"
  // view keys its per-row fetch/lookup off this affine mapping.
  const vaSpanStart = useHexStore((s) => s.vaSpanStart);
  // Rotates getPageStateAtStable's identity when page-states resolve so
  // HexRow's memo invalidates and "va"-view rows repaint. See chunkVersion.
  const pageStateVersion = useHexStore((s) => s.pageStateVersion);
  const pageStatesLoaded = useHexStore((s) => s.pageStatesLoaded);
  const fetchPageStates = useHexStore((s) => s.fetchPageStates);
  const cursorOffset = useHexStore((s) => s.cursorOffset);
  const selection = useHexStore((s) => s.selection);
  const focusColumn = useHexStore((s) => s.focusColumn);
  const highlightedRegions = useHexStore((s) => s.highlightedRegions);
  const searchOffsets = useHexStore((s) => s.searchOffsets);
  const scrollToOffset = useHexStore((s) => s.scrollToOffset);
  const windowStartRow = useHexStore((s) => s.windowStartRow);
  const setCursor = useHexStore((s) => s.setCursor);
  const startSelection = useHexStore((s) => s.startSelection);
  const extendSelection = useHexStore((s) => s.extendSelection);
  const setFocusColumn = useHexStore((s) => s.setFocusColumn);
  const activeFieldOffset = useHexStore((s) => s.activeFieldOffset);
  const activeOverlay = useHexStore((s) => s.activeStructureOverlay);
  // Drives re-render on chunk arrivals and rotates getByteAtStable's
  // identity so HexRow's memo invalidates. See hex-store.chunkVersion.
  const chunkVersion = useHexStore((s) => s.chunkVersion);

  // Consensus overlay state. When overlayEnabled, visible rows fetch
  // per-byte classifications from the backend; each byte picks up a
  // consensus-* CSS class defined in hex.css:140-156.
  const overlayEnabled = useConsensusStore((s) => s.overlayEnabled);
  const pageClassifications = useConsensusStore((s) => s.pageClassifications);
  // VA-keyed classifications drive the coordinate-correct overlay for .msl
  // dumps in the "va" view. Rotating on this repaints rows as ranges load.
  const vaClassifications = useConsensusStore((s) => s.vaClassifications);
  const consensusId = useConsensusStore((s) => s.consensusId);
  const inFlightClassificationsRef = useRef<Set<number>>(new Set());

  const activeFieldRange = useMemo(() => {
    if (activeFieldOffset === null || !activeOverlay) return null;
    const field = activeOverlay.fields.find((f) => f.offset === activeFieldOffset);
    if (!field) return null;
    return { start: field.offset, end: field.offset + field.length };
  }, [activeFieldOffset, activeOverlay]);

  useEffect(() => {
    setDumpPath(dumpPath, fileSize, format);
  }, [dumpPath, fileSize, format, setDumpPath]);

  // For MSL dumps, probe the backend once to learn both the raw file
  // size and the VAS projection size so the toolbar toggle and the
  // virtualizer row count can switch between them without re-fetching.
  //
  // The probe itself now lives in `useMslViewSizes`, shared with the N-pane
  // layouts: they never mount this component, so while it owned the effect,
  // re-anchoring inside side-by-side left all three sizes at the container
  // placeholder. Behaviour here is unchanged.
  useMslViewSizes(dumpPath, format);

  // On reload the persisted (localStorage) view mode may already be "va"
  // without setViewMode ever firing, so page-state tinting (CAPTURED/
  // FAILED/UNMAPPED) would be silently missing until the user toggles
  // views. Fetch it here whenever the "va" view is active and its page
  // states have not yet loaded. The store's fetchPageStates guards on
  // dumpPath/format/already-loaded, so this is a no-op for non-msl dumps
  // or when the fetch has already run.
  useEffect(() => {
    if (viewMode === "va" && !pageStatesLoaded) {
      fetchPageStates();
    }
  }, [viewMode, pageStatesLoaded, fetchPageStates]);

  // The consensus overlay is only coordinate-correct in the "va" view for
  // .msl dumps (the classification array lives in an aligned-slab coordinate,
  // not the container offset). When the overlay is enabled on an .msl dump in
  // any other view, switch to "va" so the colors land on the right bytes.
  // setViewMode is a no-op when already in "va", so this cannot loop.
  useEffect(() => {
    if (overlayEnabled && format === "msl" && viewMode !== "va") {
      setViewMode("va");
    }
  }, [overlayEnabled, format, viewMode, setViewMode]);

  useHexKeyboard(containerRef);

  // Prefer the store's fileSize once it has been resolved per-view; fall
  // back to the prop while the initial probe is in flight.
  const effectiveFileSize = storeFileSize >= 0 ? storeFileSize : fileSize;
  const totalRows = Math.ceil(effectiveFileSize / BYTES_PER_ROW);

  // Bounded virtualization window: the virtualizer only ever sees `count`
  // rows starting at `safeStart`, so its spacer height stays within browser
  // limits even for multi-GB dumps. `absRow` maps a virtual (window-relative)
  // index back to an absolute file row for byte fetches and offsets.
  const safeStart = clampWindowStart(windowStartRow, totalRows);
  const count = windowCount(safeStart, totalRows);
  const absRow = useCallback((i: number) => safeStart + i, [safeStart]);

  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 20,
    overscan: 10,
  });

  const virtualItems = virtualizer.getVirtualItems();
  const firstVisibleIndex = virtualItems[0]?.index ?? -1;
  const lastVisibleIndex = virtualItems[virtualItems.length - 1]?.index ?? -1;

  // `dumpPath` is a dependency: switching the active dump (e.g. selecting a
  // different dump in the list, or importing one) resets the chunk cache in
  // setDumpPath. If the visible row range happens to be identical for the new
  // dump — the common case, since any dump larger than the viewport shows rows
  // 0..N — this effect would not re-fire on the indices alone and the new
  // dump's bytes would stay stuck on the "loading" placeholder. Re-running on
  // dumpPath guarantees the first chunk loads for the new dump.
  //
  // `viewMode` and `format` are SEMANTIC dependencies: neither is read in
  // this effect's body, so eslint's exhaustive-deps rule can neither add nor
  // validate them — but both change what `ensureChunksLoaded` will do, since
  // it reads the live viewMode via getState() (hex-store.ensureChunksLoaded)
  // and both `setViewMode` and a format-changing `setDumpPath` clear the
  // chunk cache. At windowStartRow 0 / scrollTop 0 the visible indices do not
  // move when the user flips the Raw/VAS/VA toggle, so without these deps the
  // effect never re-runs, `chunks` stays empty forever, and every byte cell
  // renders the "--" placeholder permanently. DO NOT "clean up" these two as
  // unused — they are the re-fetch trigger. Covered by hex-store.test.ts.
  useEffect(() => {
    if (firstVisibleIndex < 0) return;
    // Pass ABSOLUTE rows — the store multiplies startRow*16 internally.
    useHexStore
      .getState()
      .ensureChunksLoaded(absRow(firstVisibleIndex), absRow(lastVisibleIndex));

  }, [firstVisibleIndex, lastVisibleIndex, dumpPath, absRow, viewMode, format]);

  // Fetch per-byte consensus classifications for the currently visible
  // rows whenever the overlay is on and a row's range is not yet cached.
  // Deduped via an in-flight Set so scroll bursts don't multi-fire.
  useEffect(() => {
    if (!overlayEnabled) return;
    if (firstVisibleIndex < 0) return;
    const inFlight = inFlightClassificationsRef.current;

    // .msl dumps: fetch VA-keyed classifications so the overlay is painted in
    // the correct coordinate. Only the "va" view has the affine VA mapping.
    if (format === "msl") {
      if (viewMode !== "va" || !consensusId) return;
      const vaRows = useConsensusStore.getState().vaClassifications;
      for (let idx = firstVisibleIndex; idx <= lastVisibleIndex; idx++) {
        const va = vaSpanStart + absRow(idx) * BYTES_PER_ROW;
        if (vaRows.has(va)) continue;
        if (inFlight.has(va)) continue;
        inFlight.add(va);
        useConsensusStore
          .getState()
          .fetchVaRange(dumpPath, va, BYTES_PER_ROW)
          .catch(() => {
            // Consensus may be unavailable (404 before runConsensus has
            // completed). Silently skip; bytes render without the overlay.
          })
          .finally(() => {
            inFlight.delete(va);
          });
      }
      return;
    }

    // Raw dumps: existing container-offset path (unchanged).
    const pages = useConsensusStore.getState().pageClassifications;
    for (let idx = firstVisibleIndex; idx <= lastVisibleIndex; idx++) {
      const rowOffset = absRow(idx) * BYTES_PER_ROW;
      if (pages.has(rowOffset)) continue;
      if (inFlight.has(rowOffset)) continue;
      inFlight.add(rowOffset);
      useConsensusStore
        .getState()
        .fetchRange(rowOffset, BYTES_PER_ROW)
        .catch(() => {
          // Consensus may be unavailable (404 before runConsensus
          // has completed). Silently skip; bytes render without the
          // overlay class, matching their pre-overlay appearance.
        })
        .finally(() => {
          inFlight.delete(rowOffset);
        });
    }
  }, [
    overlayEnabled,
    firstVisibleIndex,
    lastVisibleIndex,
    pageClassifications,
    vaClassifications,
    absRow,
    format,
    viewMode,
    consensusId,
    vaSpanStart,
    dumpPath,
  ]);

  // Jump-to-row lives in `useHexScrollTarget`, shared with `MultiHexViewer` so
  // bookmarks / search / CandidatePanel behave identically in both layouts.
  useHexScrollTarget(virtualizer, safeStart, totalRows);

  const selectionStart = selection
    ? Math.min(selection.anchor, selection.active)
    : null;
  const selectionEnd = selection
    ? Math.max(selection.anchor, selection.active)
    : null;

  const regionIndex = useMemo(
    () => buildRegionIndex(highlightedRegions),
    [highlightedRegions]
  );

  const getByteAtStable = useCallback(
    // chunkVersion dep rotates this callback's identity on chunk
    // load so HexRow's memo invalidates and the row repaints.
    (offset: number) => {
      void chunkVersion;
      return useHexStore.getState().getByteAt(offset);
    },
    [chunkVersion]
  );

  const getPageStateAtStable = useCallback(
    (offset: number) => {
      void pageStateVersion;
      return useHexStore.getState().getPageStateAt(offset);
    },
    [pageStateVersion]
  );

  const getVarianceAt = useCallback(
    (offset: number): number | undefined => {
      return useHexStore.getState().neighborhoodVarianceMap.get(offset);
    },
    // No dep needed — reads from getState() on each call.
     
    []
  );

  const getClassificationAtStable = useCallback(
    // pageClassifications dep rotates this callback's identity on
    // fetchRange resolution so HexRow's memo invalidates and visible
    // rows repaint with the new overlay classes. Mirrors the
    // getByteAtStable / chunkVersion pattern above.
    (offset: number): number | undefined => {
      void pageClassifications;
      void vaClassifications;
      const byteInRow = offset % BYTES_PER_ROW;
      // .msl "va" view: look up by row-aligned absolute VA. A -1 entry marks a
      // VA gap absent from the consensus → undefined so no class is painted.
      if (format === "msl" && viewMode === "va") {
        const va = vaSpanStart + Math.floor(offset / BYTES_PER_ROW) * BYTES_PER_ROW;
        const row = useConsensusStore.getState().vaClassifications.get(va);
        const c = row?.[byteInRow];
        return c === undefined || c < 0 ? undefined : c;
      }
      // Raw dumps: existing container-offset lookup (unchanged).
      const rowStart = Math.floor(offset / BYTES_PER_ROW) * BYTES_PER_ROW;
      const row = useConsensusStore.getState().pageClassifications.get(rowStart);
      return row?.[byteInRow];
    },
    [pageClassifications, vaClassifications, format, viewMode, vaSpanStart]
  );

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      const target = (e.target as HTMLElement).closest("[data-offset]");
      if (!target) return;
      const offset = parseInt(target.getAttribute("data-offset")!, 10);
      const col = target.getAttribute("data-col") as "hex" | "ascii" | null;
      if (col) setFocusColumn(col);

      if (e.shiftKey && cursorOffset !== null) {
        extendSelection(offset);
      } else {
        setCursor(offset);
        startSelection(offset);
      }
      onOffsetClick?.(offset);
    },
    [cursorOffset, setCursor, startSelection, extendSelection, setFocusColumn, onOffsetClick]
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (!(e.buttons & 1)) return; // not left button
      const target = (e.target as HTMLElement).closest("[data-offset]");
      if (!target) return;
      const offset = parseInt(target.getAttribute("data-offset")!, 10);
      extendSelection(offset);
    },
    [extendSelection]
  );

  if (effectiveFileSize === 0) {
    return (
      <div className="h-full flex items-center justify-center md-text-muted text-sm">
        {t("viewer.emptyFile")}
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      data-tour-id="hex-viewer"
      className="h-full flex flex-col overflow-hidden"
      tabIndex={0}
    >
      <HexToolbar />
      <HexLegend />
      <div className="flex-1 flex min-h-0">
      <div
        ref={scrollRef}
        className="flex-1 overflow-auto"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
      >
        <div
          style={{
            height: virtualizer.getTotalSize(),
            position: "relative",
            width: "fit-content",
            minWidth: "100%",
          }}
        >
          {virtualItems.map((vItem) => (
            // key/data-index stay window-relative: the fixed 20px row height
            // makes DOM node reuse safe across window shifts (every index maps
            // to the same layout slot; only the absolute rowOffset changes).
            <div
              key={vItem.index}
              data-index={vItem.index}
              className="absolute w-full"
              style={{ top: vItem.start, height: 20 }}
            >
              <HexRow
                rowOffset={absRow(vItem.index) * BYTES_PER_ROW}
                getByteAt={getByteAtStable}
                getVarianceAt={getVarianceAt}
                cursorOffset={cursorOffset}
                selectionStart={selectionStart}
                selectionEnd={selectionEnd}
                focusColumn={focusColumn}
                regionIndex={regionIndex}
                activeFieldStart={activeFieldRange?.start ?? null}
                activeFieldEnd={activeFieldRange?.end ?? null}
                overlayEnabled={overlayEnabled}
                getClassificationAt={getClassificationAtStable}
                view={viewMode}
                getPageStateAt={getPageStateAtStable}
              />
            </div>
          ))}
        </div>
      </div>
        {searchOffsets.length > 0 && (
          <div className="shrink-0 flex items-stretch py-1 pr-1">
            <SearchMinimap
              fileSize={effectiveFileSize}
              offsets={searchOffsets}
              currentOffset={absRow(Math.max(0, firstVisibleIndex)) * BYTES_PER_ROW}
              onClickOffset={scrollToOffset}
            />
          </div>
        )}
        {overlayEnabled && format === "msl" && viewMode === "va" && consensusId && (
          <div className="shrink-0 flex items-stretch py-1 pr-1">
            <ConsensusVarianceMinimap
              dumpPath={dumpPath}
              firstVisibleOffset={absRow(Math.max(0, firstVisibleIndex)) * BYTES_PER_ROW}
            />
          </div>
        )}
      </div>
      <HexStatusBar />
    </div>
  );
}
