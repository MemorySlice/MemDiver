import { useCallback, useEffect, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useHexStore } from "@/stores/hex-store";
import { HexRow } from "./HexRow";
import { HexToolbar } from "./HexToolbar";
import { HexLegend } from "./HexLegend";
import { HexStatusBar } from "./HexStatusBar";
import { buildRegionIndex } from "./highlight-utils";
import { useHexKeyboard } from "@/hooks/useHexKeyboard";

const BYTES_PER_ROW = 16;

interface Props {
  dumpPath: string;
  fileSize: number;
  format?: string;
  onOffsetClick?: (offset: number) => void;
}

export function HexViewer({ dumpPath, fileSize, format = "raw", onOffsetClick }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Per-field selectors so chunk-load writes (which replace the store
  // object on every set()) do not re-render the TanStack Virtual loop
  // unless a field this component actually reads has changed.
  const setDumpPath = useHexStore((s) => s.setDumpPath);
  const setViewSizes = useHexStore((s) => s.setViewSizes);
  const storeFileSize = useHexStore((s) => s.fileSize);
  const cursorOffset = useHexStore((s) => s.cursorOffset);
  const selection = useHexStore((s) => s.selection);
  const focusColumn = useHexStore((s) => s.focusColumn);
  const highlightedRegions = useHexStore((s) => s.highlightedRegions);
  const scrollTarget = useHexStore((s) => s.scrollTarget);
  const clearScrollTarget = useHexStore((s) => s.clearScrollTarget);
  const setCursor = useHexStore((s) => s.setCursor);
  const startSelection = useHexStore((s) => s.startSelection);
  const extendSelection = useHexStore((s) => s.extendSelection);
  const setFocusColumn = useHexStore((s) => s.setFocusColumn);
  const activeFieldOffset = useHexStore((s) => s.activeFieldOffset);
  const activeOverlay = useHexStore((s) => s.activeStructureOverlay);
  // Drives re-render on chunk arrivals and rotates getByteAtStable's
  // identity so HexRow's memo invalidates. See hex-store.chunkVersion.
  const chunkVersion = useHexStore((s) => s.chunkVersion);

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
  useEffect(() => {
    if (!dumpPath || format !== "msl") return;
    let cancelled = false;
    const base = `/api/inspect/hex-raw?dump_path=${encodeURIComponent(dumpPath)}&offset=0&length=1`;
    (async () => {
      try {
        const [rawJson, vasJson] = await Promise.all([
          fetch(`${base}&view=raw`).then((r) => r.json()),
          fetch(`${base}&view=vas`).then((r) => r.json()),
        ]);
        if (cancelled) return;
        setViewSizes(rawJson.file_size ?? 0, vasJson.file_size ?? 0);
      } catch {
        /* leave sizes at defaults on network failure */
      }
    })();
    return () => { cancelled = true; };
  }, [dumpPath, format, setViewSizes]);

  useHexKeyboard(containerRef);

  // Prefer the store's fileSize once it has been resolved per-view; fall
  // back to the prop while the initial probe is in flight.
  const effectiveFileSize = storeFileSize || fileSize;
  const totalRows = Math.ceil(effectiveFileSize / BYTES_PER_ROW);

  const virtualizer = useVirtualizer({
    count: totalRows,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 20,
    overscan: 10,
  });

  const virtualItems = virtualizer.getVirtualItems();
  const firstVisibleIndex = virtualItems[0]?.index ?? -1;
  const lastVisibleIndex = virtualItems[virtualItems.length - 1]?.index ?? -1;

  useEffect(() => {
    if (firstVisibleIndex < 0) return;
    useHexStore.getState().ensureChunksLoaded(firstVisibleIndex, lastVisibleIndex);
  }, [firstVisibleIndex, lastVisibleIndex]);

  useEffect(() => {
    if (scrollTarget !== null) {
      virtualizer.scrollToIndex(scrollTarget, { align: "center" });
      clearScrollTarget();
    }
  }, [scrollTarget, virtualizer, clearScrollTarget]);

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

  const getVarianceAt = useCallback(
    (offset: number): number | undefined => {
      return useHexStore.getState().neighborhoodVarianceMap.get(offset);
    },
    // No dep needed — reads from getState() on each call.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    []
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
        Empty file
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
            <div
              key={vItem.index}
              data-index={vItem.index}
              className="absolute w-full"
              style={{ top: vItem.start, height: 20 }}
            >
              <HexRow
                rowOffset={vItem.index * BYTES_PER_ROW}
                getByteAt={getByteAtStable}
                getVarianceAt={getVarianceAt}
                cursorOffset={cursorOffset}
                selectionStart={selectionStart}
                selectionEnd={selectionEnd}
                focusColumn={focusColumn}
                regionIndex={regionIndex}
                activeFieldStart={activeFieldRange?.start ?? null}
                activeFieldEnd={activeFieldRange?.end ?? null}
              />
            </div>
          ))}
        </div>
      </div>
      <HexStatusBar />
    </div>
  );
}
