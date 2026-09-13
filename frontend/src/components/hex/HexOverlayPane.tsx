import { useCallback, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useVirtualizer } from "@tanstack/react-virtual";

import {
  useAlignedSelection,
  useAlignedWindowLoader,
  useMslPaneCoordinate,
} from "@/hooks/useAlignedPanes";
import { useHexKeyboard } from "@/hooks/useHexKeyboard";
import { useHexScrollTarget } from "@/hooks/useHexScrollTarget";
import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { HexAlignmentChip } from "./HexAlignmentChip";
import { HexRow } from "./HexRow";
import { HexStatusBar } from "./HexStatusBar";
import { HexToolbar } from "./HexToolbar";
import { buildRegionIndex } from "./highlight-utils";
import { BYTES_PER_ROW, clampWindowStart, windowCount } from "./window-utils";

/**
 * ONE byte stream, four layers: the aligned overlay.
 *
 * Showing N streams is side-by-side; showing ONE is an overlay. The stream is
 * the anchor's, and everything the other dumps contribute arrives as styling on
 * top of it:
 *
 *   1. bytes         - the anchor's own
 *   2. consensus class - the SAME `consensus-*` classes and colours the single
 *                        view uses, so the analyst learns one legend, not two
 *   3. cross-dump differs - an inset ring, not a background, so it composes
 *                        with the class colour rather than replacing it
 *   4. page state    - unchanged from the single view
 *
 * `NDumpOverlay` is deliberately untouched; its legend strings are REUSED here
 * rather than duplicated, so the two overlays cannot end up calling the same
 * class two different things.
 */
export function HexOverlayPane() {
  const { t } = useTranslation("hex");
  const containerRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const { anchor, selected, selectedPaths } = useAlignedSelection();

  // An .msl anchor cannot be aligned in the "raw" view at all; this takes the
  // overlay off it before the first request goes out.
  useMslPaneCoordinate(anchor);

  const viewMode = useHexStore((s) => s.viewMode);
  const storeFileSize = useHexStore((s) => s.fileSize);
  const windowStartRow = useHexStore((s) => s.windowStartRow);
  const cursorOffset = useHexStore((s) => s.cursorOffset);
  const selection = useHexStore((s) => s.selection);
  const focusColumn = useHexStore((s) => s.focusColumn);
  const highlightedRegions = useHexStore((s) => s.highlightedRegions);
  const pageStateVersion = useHexStore((s) => s.pageStateVersion);
  const setCursor = useHexStore((s) => s.setCursor);
  const startSelection = useHexStore((s) => s.startSelection);
  const extendSelection = useHexStore((s) => s.extendSelection);
  const setFocusColumn = useHexStore((s) => s.setFocusColumn);

  const consensusId = useConsensusStore((s) => s.consensusId);
  const runConsensus = useConsensusStore((s) => s.runConsensus);
  const aslrNormalize = useDumpStore((s) => s.aslrNormalize);
  const toggleAslrNormalize = useDumpStore((s) => s.toggleAslrNormalize);

  const chunkVersionByPath = useMultiHexStore((s) => s.chunkVersionByPath);
  const alignment = useMultiHexStore((s) => s.alignment);
  const chunkErrors = useMultiHexStore((s) => s.chunkErrors);

  const [running, setRunning] = useState(false);

  useHexKeyboard(containerRef);

  const effectiveFileSize = storeFileSize > 0 ? storeFileSize : (anchor?.size ?? 0);
  const totalRows = Math.ceil(effectiveFileSize / BYTES_PER_ROW);
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

  useHexScrollTarget(virtualizer, safeStart, totalRows);

  useAlignedWindowLoader({
    anchor,
    paths: selectedPaths,
    firstRow: firstVisibleIndex < 0 ? -1 : absRow(firstVisibleIndex),
    lastRow: lastVisibleIndex < 0 ? -1 : absRow(lastVisibleIndex),
  });

  const selectionStart = selection ? Math.min(selection.anchor, selection.active) : null;
  const selectionEnd = selection ? Math.max(selection.anchor, selection.active) : null;

  // Chunk-scoped, and only for the window on screen — see the same note in
  // `MultiHexViewer`.
  const windowError = useMemo(() => {
    void chunkErrors;
    if (firstVisibleIndex < 0) return null;
    const store = useMultiHexStore.getState();
    return (
      store.getChunkError(absRow(firstVisibleIndex) * BYTES_PER_ROW) ??
      store.getChunkError(absRow(lastVisibleIndex) * BYTES_PER_ROW)
    );
  }, [chunkErrors, firstVisibleIndex, lastVisibleIndex, absRow]);

  const regionIndex = useMemo(
    () => buildRegionIndex(highlightedRegions),
    [highlightedRegions],
  );

  // The anchor's version alone rotates these getters: this pane paints exactly
  // one byte stream, so a neighbour's chunk arriving cannot change a byte here
  // (it can change the DIFFERS ring, which the same rotation covers because the
  // whole selection's chunks land in one response).
  const anchorVersion = anchor ? (chunkVersionByPath.get(anchor.path) ?? 0) : 0;
  const anchorPath = anchor?.path ?? null;

  const getByteAt = useCallback(
    (offset: number) => {
      void anchorVersion;
      if (!anchorPath) return undefined;
      const store = useMultiHexStore.getState();
      // `getByteAt` reports the stored `0` for an absent byte; `isPresentAt` is
      // the sole authority on presence, so an unmapped byte must render as
      // "--" rather than as a confident 0x00.
      if (!store.isPresentAt(anchorPath, offset)) return undefined;
      return store.getByteAt(anchorPath, offset);
    },
    [anchorPath, anchorVersion],
  );

  const getClassificationAt = useCallback(
    (offset: number) => {
      void anchorVersion;
      return useMultiHexStore.getState().getClassAt(offset);
    },
    [anchorVersion],
  );

  const getDiffersAt = useCallback(
    (offset: number) => {
      void anchorVersion;
      return useMultiHexStore.getState().differsAt(offset);
    },
    [anchorVersion],
  );

  const getPageStateAt = useCallback(
    (offset: number) => {
      void pageStateVersion;
      return useHexStore.getState().getPageStateAt(offset);
    },
    [pageStateVersion],
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
    },
    [cursorOffset, extendSelection, setCursor, setFocusColumn, startSelection],
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (!(e.buttons & 1)) return;
      const target = (e.target as HTMLElement).closest("[data-offset]");
      if (!target) return;
      extendSelection(parseInt(target.getAttribute("data-offset")!, 10));
    },
    [extendSelection],
  );

  if (!anchor || selected.length < 2) {
    return (
      <div className="h-full flex items-center justify-center md-text-muted text-sm">
        {t("overlayPane.noAnchor")}
      </div>
    );
  }

  /**
   * No consensus is an EMPTY STATE with the action in it, not a toast and not a
   * blank grid. Without a consensus every byte is unclassified, so the overlay
   * would render a plain hex dump that silently looks like "nothing varies" -
   * the single most misleading thing this pane could show.
   */
  if (!consensusId) {
    return (
      <div
        data-testid="hex-overlay-no-consensus"
        className="h-full flex items-center justify-center p-6"
      >
        <div className="text-center max-w-md space-y-2">
          <p className="text-sm font-medium">{t("overlayPane.noConsensusTitle")}</p>
          <p className="text-xs md-text-secondary">{t("overlayPane.noConsensusBody")}</p>
          <button
            type="button"
            data-testid="hex-overlay-run-consensus"
            disabled={running}
            className="px-3 py-1 rounded md-bg-accent md-text-on-accent text-xs disabled:opacity-50"
            onClick={() => {
              setRunning(true);
              void runConsensus(selectedPaths, aslrNormalize).finally(() =>
                setRunning(false),
              );
            }}
          >
            {running ? t("overlayPane.running") : t("overlayPane.runConsensus")}
          </button>
        </div>
      </div>
    );
  }

  // A consensus built in raw file offsets cannot answer a virtual-address
  // question. The bytes are still real, so this is a banner over a live pane
  // rather than a replacement for it - but it names the fix.
  const rawOffsetConsensus = alignment?.method === "file_offset";

  return (
    <div
      ref={containerRef}
      data-testid="hex-overlay-pane"
      className="h-full flex flex-col overflow-hidden"
      tabIndex={0}
    >
      <HexToolbar />
      <HexAlignmentChip
        paths={selectedPaths}
        hasMsl={selected.some((d) => d.format === "msl")}
      />

      {windowError && (
        <div
          data-testid="hex-overlay-window-error"
          role="status"
          className="px-3 py-1 text-xs md-text-error"
          title={windowError}
        >
          {t("multiHex.windowError", { error: windowError })}
        </div>
      )}

      {rawOffsetConsensus && (
        <div
          data-testid="hex-overlay-raw-offset"
          role="status"
          className="px-3 py-1.5 text-xs md-bg-warning-subtle space-y-1"
        >
          <p className="font-medium">{t("overlayPane.rawOffsetTitle")}</p>
          <p>{t("overlayPane.rawOffsetBody")}</p>
          <button
            type="button"
            data-testid="hex-overlay-enable-aslr"
            disabled={running}
            className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50"
            onClick={() => {
              // Toggle first, then re-run with the value the user is asking
              // for: `aslrNormalize` in this closure is the pre-click value.
              if (!aslrNormalize) toggleAslrNormalize();
              setRunning(true);
              void runConsensus(selectedPaths, true).finally(() => setRunning(false));
            }}
          >
            {running ? t("overlayPane.running") : t("overlayPane.enableAslrAndRerun")}
          </button>
        </div>
      )}

      <div
        data-testid="hex-overlay-legend"
        className="flex items-center gap-3 px-3 py-1 text-xs border-b border-[var(--md-border)] md-bg-secondary"
      >
        <span className="md-text-muted">
          {t("overlayPane.anchorLabel", { name: anchor.name })}
        </span>
        <span className="consensus-invariant">{t("ndump.legendInvariant")}</span>
        <span className="consensus-structural">{t("ndump.legendStructural")}</span>
        <span className="consensus-pointer">{t("ndump.legendPointer")}</span>
        <span className="consensus-key-candidate">{t("ndump.legendKeyCandidate")}</span>
        <span className="cross-dump-differs px-1">{t("ndump.legendDiffers")}</span>
      </div>

      <div
        ref={scrollRef}
        data-testid="hex-overlay-scroll"
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
            <div
              key={vItem.index}
              data-index={vItem.index}
              className="absolute w-full"
              style={{ top: vItem.start, height: 20 }}
            >
              <HexRow
                rowOffset={absRow(vItem.index) * BYTES_PER_ROW}
                getByteAt={getByteAt}
                cursorOffset={cursorOffset}
                selectionStart={selectionStart}
                selectionEnd={selectionEnd}
                focusColumn={focusColumn}
                regionIndex={regionIndex}
                overlayEnabled
                getClassificationAt={getClassificationAt}
                getDiffersAt={getDiffersAt}
                view={viewMode}
                getPageStateAt={getPageStateAt}
              />
            </div>
          ))}
        </div>
      </div>

      <HexStatusBar />
    </div>
  );
}
