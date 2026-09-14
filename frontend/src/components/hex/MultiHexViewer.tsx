import { useCallback, useMemo, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useVirtualizer } from "@tanstack/react-virtual";

import {
  useAlignedSelection,
  useAlignedWindowLoader,
  useConsensusUsable,
  useMslPaneCoordinate,
} from "@/hooks/useAlignedPanes";
import { useHexKeyboard } from "@/hooks/useHexKeyboard";
import { useHexScrollTarget } from "@/hooks/useHexScrollTarget";
import type { AbsenceKind } from "@/utils/absence-classes";
import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { AbsenceLegend } from "./AbsenceLegend";
import { HexAlignmentChip } from "./HexAlignmentChip";
import { HexPaneHeader } from "./HexPaneHeader";
import { HexRow } from "./HexRow";
import { HexStatusBar } from "./HexStatusBar";
import { HexToolbar } from "./HexToolbar";
import { NoConsensusPrompt } from "./NoConsensusPrompt";
import { WindowErrorBanner } from "./WindowErrorBanner";
import { chunkErrorSignature } from "./chunk-error-signal";
import { ConsensusErrorBanner } from "./ConsensusErrorBanner";
import { buildRegionIndex } from "./highlight-utils";
import { MAX_PANES, PANE_COLUMN_WIDTH_PX, visiblePanes } from "./multi-window-utils";
import { BYTES_PER_ROW, clampWindowStart, windowCount } from "./window-utils";

/**
 * N dumps, one row grid: the side-by-side layout.
 *
 * ── Why ONE virtualizer ──────────────────────────────────────────────────────
 * There is exactly one scroll container and exactly one `useVirtualizer`, and
 * each virtual row renders N columns. Byte alignment is then a STRUCTURAL
 * property of the DOM: every pane's row for a given virtual index literally IS
 * the same `<div>`, so no amount of scrolling, momentum or reflow can slide one
 * pane a row out of step with another.
 *
 * The alternative — a virtualizer per pane with mirrored `scrollTop`, which is
 * what `HexComparison.tsx` does for the pairwise case — needs a re-entrancy
 * guard to stop the mirror feeding itself, and still visibly jitters under
 * momentum scrolling because each pane applies the mirrored offset a frame
 * late. Alignment you can only assert at runtime is alignment you cannot trust.
 *
 * The virtualizer config (`estimateSize: () => 20`, `overscan: 10`) is the same
 * as `HexViewer`'s, and `windowStartRow` is read from the SHARED `hex-store`, so
 * switching Single <-> Side-by-side preserves the scroll position and every
 * existing `scrollToOffset` caller (bookmarks, search, `CandidatePanel`) keeps
 * working through `useHexScrollTarget`.
 */
/** One pane's byte reader and the reason its reads come back empty. */
interface PaneReaders {
  version: number;
  /**
   * The failed-chunk signature these readers were built under.
   *
   * `version` alone is not enough: it is bumped in `applyResponse` only, so a
   * chunk whose request FAILED leaves it untouched and the cached reader keeps
   * answering "still loading" for bytes the store now calls `"error"`. See
   * `chunk-error-signal`.
   */
  errorKey: string;
  read: (offset: number) => number | undefined;
  /**
   * WHY that read came back empty. Paired with `read` and rotated with it,
   * because a cell that says "--" while its reason says something else is
   * exactly the confusion this vocabulary exists to remove.
   */
  absence: (offset: number) => AbsenceKind | undefined;
}

export function MultiHexViewer() {
  const { t } = useTranslation("hex");
  const containerRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const { anchor, selected, selectedPaths } = useAlignedSelection();

  // An .msl anchor cannot be aligned in the "raw" view at all; this takes the
  // viewer off it before the first request goes out.
  useMslPaneCoordinate(anchor);

  /**
   * `visibleDumps` is a COLLAPSE set, not a visibility set.
   *
   * The store's own comment is the authority: "Transient view collapse - NOT
   * analysis membership. A dump hidden here is still selected". It starts EMPTY
   * while every pane is showing, and `toggleDumpVisibility` ADDS an id — so
   * membership means "folded away", and `visiblePanes(selected, collapsed)`
   * takes it as the `collapsed` argument unchanged. Reading the name literally
   * and inverting it here would render exactly the panes the user just hid.
   */
  const collapsedDumpIds = useDumpStore((s) => s.visibleDumps);
  const originDumpId = useDumpStore((s) => s.originDumpId);
  const activeDumpId = useDumpStore((s) => s.activeDumpId);
  const setActiveDump = useDumpStore((s) => s.setActiveDump);
  const toggleDumpVisibility = useDumpStore((s) => s.toggleDumpVisibility);

  const viewMode = useHexStore((s) => s.viewMode);
  const storeFileSize = useHexStore((s) => s.fileSize);
  const windowStartRow = useHexStore((s) => s.windowStartRow);
  const cursorOffset = useHexStore((s) => s.cursorOffset);
  const selection = useHexStore((s) => s.selection);
  const highlightedRegions = useHexStore((s) => s.highlightedRegions);
  const setCursor = useHexStore((s) => s.setCursor);
  const startSelection = useHexStore((s) => s.startSelection);
  const extendSelection = useHexStore((s) => s.extendSelection);
  const setFocusColumn = useHexStore((s) => s.setFocusColumn);

  const chunkVersionByPath = useMultiHexStore((s) => s.chunkVersionByPath);
  const byPath = useMultiHexStore((s) => s.byPath);
  // A scalar, NOT the `chunkErrors` map: the map is copied on every successful
  // response too, so subscribing to it would repaint every pane on every chunk
  // that lands. See `chunk-error-signal` for why that distinction is the whole
  // point of this value.
  const chunkErrorKey = useMultiHexStore((s) => chunkErrorSignature(s.chunkErrors));

  // Only to tell the two fences apart: "nothing built yet" and "built over
  // other dumps" are different facts and need different sentences.
  const consensusId = useConsensusStore((s) => s.consensusId);

  useHexKeyboard(containerRef);

  const selectedIds = useMemo(() => selected.map((d) => d.id), [selected]);
  const openIds = useMemo(
    () => visiblePanes(selectedIds, collapsedDumpIds, Number.MAX_SAFE_INTEGER),
    [selectedIds, collapsedDumpIds],
  );
  const paneIds = useMemo(
    () => visiblePanes(selectedIds, collapsedDumpIds, MAX_PANES),
    [selectedIds, collapsedDumpIds],
  );
  const panes = useMemo(() => {
    const byId = new Map(selected.map((d) => [d.id, d]));
    return paneIds
      .map((id) => byId.get(id))
      .filter((d): d is (typeof selected)[number] => d !== undefined);
  }, [paneIds, selected]);
  const collapsed = useMemo(
    () => selected.filter((d) => collapsedDumpIds.has(d.id)),
    [selected, collapsedDumpIds],
  );

  /**
   * Is there a consensus that describes THIS selection?
   *
   * A build made over another set of dumps would put the panes in a slab this
   * selection never produced — real bytes at the wrong address, which is the
   * one failure the aligned-window endpoint exists to prevent. One hook, shared
   * with the overlay and with the loader that is the actual fence.
   */
  const consensusUsable = useConsensusUsable(selectedPaths);

  // The anchor's own size governs the row count: every pane is rendered in the
  // ANCHOR's coordinate (invariant W1), so a longer or shorter neighbour does
  // not add or remove rows.
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

  // Bytes are fetched for the WHOLE selection, not just the rendered panes:
  // the consensus classes and `differsAt` are computed across every selected
  // dump, so dropping a collapsed pane from the request would change the
  // answer, not just the picture.
  useAlignedWindowLoader({
    anchor,
    paths: selectedPaths,
    firstRow: firstVisibleIndex < 0 ? -1 : absRow(firstVisibleIndex),
    lastRow: lastVisibleIndex < 0 ? -1 : absRow(lastVisibleIndex),
  });

  const selectionStart = selection ? Math.min(selection.anchor, selection.active) : null;
  const selectionEnd = selection ? Math.max(selection.anchor, selection.active) : null;

  const regionIndex = useMemo(
    () => buildRegionIndex(highlightedRegions),
    [highlightedRegions],
  );

  /**
   * One byte reader per pane, re-created when THAT pane's chunks change.
   *
   * `chunkVersionByPath` is per path precisely so a response for one pane does
   * not rotate every other pane's `HexRow` memo identity; keeping that property
   * means keying each getter on its own path's version and nothing else.
   *
   * `isPresentAt` gates the read: `getByteAt` hands back the stored `0` for a
   * byte the dump does not hold, which is indistinguishable from a real `0x00`.
   * Returning `undefined` instead makes `HexRow` draw "--", which is the truth.
   */
  const readerCacheRef = useRef(new Map<string, PaneReaders>());
  const byteReaders = useMemo(() => {
    const cache = readerCacheRef.current;
    const readers = new Map<string, PaneReaders>();
    for (const pane of panes) {
      const version = chunkVersionByPath.get(pane.path) ?? 0;
      const cached = cache.get(pane.path);
      if (cached && cached.version === version && cached.errorKey === chunkErrorKey) {
        readers.set(pane.path, cached);
        continue;
      }
      const read = (offset: number) => {
        const store = useMultiHexStore.getState();
        if (!store.isPresentAt(pane.path, offset)) return undefined;
        return store.getByteAt(pane.path, offset);
      };
      const absence = (offset: number) =>
        useMultiHexStore.getState().absenceAt(pane.path, offset) ?? undefined;
      const entry = { version, errorKey: chunkErrorKey, read, absence };
      cache.set(pane.path, entry);
      readers.set(pane.path, entry);
    }
    return readers;
  }, [panes, chunkVersionByPath, chunkErrorKey]);

  /**
   * A click anywhere in a pane focuses it; only a click in the ALREADY focused
   * pane moves the cursor.
   *
   * Focusing re-anchors the alignment, and `hex-store.setDumpPath` clears the
   * cursor when the dump changes — so setting a cursor in the same gesture
   * would paint a selection and then immediately drop it. Two clicks, two
   * distinct outcomes, is the honest behaviour: the first says "read this
   * dump's coordinate", the second picks a byte in it.
   */
  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      const paneEl = (e.target as HTMLElement).closest("[data-pane-id]");
      const paneId = paneEl?.getAttribute("data-pane-id") ?? null;
      if (paneId && paneId !== activeDumpId) {
        setActiveDump(paneId);
        return;
      }
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
    [
      activeDumpId,
      cursorOffset,
      extendSelection,
      setActiveDump,
      setCursor,
      setFocusColumn,
      startSelection,
    ],
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (!(e.buttons & 1)) return;
      const paneEl = (e.target as HTMLElement).closest("[data-pane-id]");
      if (paneEl && paneEl.getAttribute("data-pane-id") !== activeDumpId) return;
      const target = (e.target as HTMLElement).closest("[data-offset]");
      if (!target) return;
      extendSelection(parseInt(target.getAttribute("data-offset")!, 10));
    },
    [activeDumpId, extendSelection],
  );

  if (!anchor || panes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center md-text-muted text-sm">
        {t("multiHex.noAnchor")}
      </div>
    );
  }

  /**
   * The same fence the overlay draws, and for a second reason on top of the
   * shared one.
   *
   * Without a `consensus_id` the store falls back to posting `dump_paths`, and
   * `classify` defaults to true — so the server rebuilds the ENTIRE consensus
   * for every 8 KiB chunk the analyst scrolls past. Sending `classify: false`
   * instead is NOT the fix: that takes the raw-file-offset path, where an
   * `.msl` peer read lands on a block header and hands back plausible bytes
   * from the wrong address.
   */
  if (!consensusUsable) {
    return (
      <NoConsensusPrompt
        paths={selectedPaths}
        variant={consensusId ? "stale" : "missing"}
      />
    );
  }

  const gridWidth = panes.length * PANE_COLUMN_WIDTH_PX;
  const cappedOut = openIds.length - paneIds.length;

  return (
    <div
      ref={containerRef}
      data-testid="multi-hex-viewer"
      className="h-full flex flex-col overflow-hidden"
      tabIndex={0}
    >
      <HexToolbar />
      <HexAlignmentChip
        paths={selectedPaths}
        hasMsl={selected.some((d) => d.format === "msl")}
      />

      {/*
        Side-by-side had no legend at all, so the hatched cells it now paints
        would have been a private notation. It carries the ABSENCE vocabulary
        only: these panes paint no consensus class, and a class legend over a
        grid that never shows one teaches a colour the analyst will not find.
      */}
      <div
        data-testid="multi-hex-legend"
        className="flex items-center gap-3 px-3 py-1 text-xs border-b border-[var(--md-border)] md-bg-secondary"
      >
        <AbsenceLegend />
      </div>

      {/*
        Chunk-scoped rather than pane-scoped (see `multi-hex-store.chunkErrors`):
        one request carries every pane, so a failure is a fact about a window,
        not about a dump. Restricting it to the visible window is also what keeps
        it from lingering — scroll away and the note goes with the rows it
        described. Shared with the overlay, which reports the same failure.
      */}
      <WindowErrorBanner
        testIdPrefix="multi-hex"
        firstRow={firstVisibleIndex < 0 ? -1 : absRow(firstVisibleIndex)}
        lastRow={lastVisibleIndex < 0 ? -1 : absRow(lastVisibleIndex)}
      />

      {/*
        A failed REBUILD is a different failure from a failed window fetch, and
        it is the quieter of the two: the panes keep painting, in the previous
        build's alignment, with nothing else on screen saying the coordinate the
        analyst asked for was never applied. Past the fence above, so "still the
        previous build" is true wherever this renders.
      */}
      <ConsensusErrorBanner testIdPrefix="multi-hex" paths={selectedPaths} />

      {cappedOut > 0 && (
        <div
          data-testid="multi-hex-pane-cap"
          role="status"
          className="px-3 py-1 text-xs md-bg-warning-subtle"
        >
          {t("multiHex.paneCap", { shown: paneIds.length, selected: selectedIds.length })}{" "}
          {t("multiHex.paneCapHint")}
        </div>
      )}

      {collapsed.length > 0 && (
        <div
          data-testid="multi-hex-collapsed-rail"
          role="group"
          aria-label={t("pane.collapsedLabel")}
          className="flex items-center gap-1 px-3 py-1 text-xs border-b border-[var(--md-border)]"
        >
          {collapsed.map((d) => (
            <button
              key={d.id}
              type="button"
              data-testid={`hex-pane-restore-${d.id}`}
              aria-label={t("pane.restore", { name: d.name })}
              title={d.path}
              className="px-1.5 py-0.5 rounded border border-[var(--md-border)] font-mono hover:bg-[var(--md-bg-hover)]"
              onClick={() => toggleDumpVisibility(d.id)}
            >
              {d.name}
            </button>
          ))}
        </div>
      )}

      <div
        ref={scrollRef}
        data-testid="multi-hex-scroll"
        className="flex-1 overflow-auto"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
      >
        <div style={{ width: gridWidth, minWidth: "100%" }}>
          {/*
            The headers live INSIDE the scroll container so they track the
            panes horizontally; `sticky` pins them vertically. That leaves the
            virtualized block offset by the header's height, which the
            virtualizer does not know about — an error of under two rows, fully
            absorbed by `overscan: 10`, and the alternative (mirroring
            `scrollLeft` onto a header outside the scroller) reintroduces
            exactly the desync this component exists to avoid.
          */}
          <div
            className="sticky top-0 z-10 flex"
            style={{ width: gridWidth }}
            role="row"
            aria-label={t("multiHex.label")}
          >
            {panes.map((pane) => (
              <HexPaneHeader
                key={pane.id}
                dump={pane}
                isOrigin={pane.id === originDumpId}
                isFocused={pane.id === activeDumpId}
                widthPx={PANE_COLUMN_WIDTH_PX}
                error={byPath.get(pane.path)?.error ?? null}
                onFocus={() => setActiveDump(pane.id)}
                onCollapse={() => toggleDumpVisibility(pane.id)}
              />
            ))}
          </div>

          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualItems.map((vItem) => {
              // ONE row offset, computed ONCE, handed to every pane on this
              // virtual row. This single binding is the alignment guarantee.
              const rowOffset = absRow(vItem.index) * BYTES_PER_ROW;
              return (
                <div
                  key={vItem.index}
                  data-index={vItem.index}
                  data-row-offset={rowOffset}
                  className="absolute flex"
                  style={{ top: vItem.start, height: 20, width: gridWidth }}
                >
                  {panes.map((pane) => (
                    <div
                      key={pane.id}
                      data-pane-id={pane.id}
                      data-testid={`hex-pane-${pane.id}`}
                      className="shrink-0"
                      style={{
                        width: PANE_COLUMN_WIDTH_PX,
                        borderRight: "1px solid var(--md-border)",
                        borderLeft:
                          pane.id === activeDumpId
                            ? "2px solid var(--md-accent-blue)"
                            : "2px solid transparent",
                      }}
                    >
                      <HexRow
                        rowOffset={rowOffset}
                        getByteAt={byteReaders.get(pane.path)!.read}
                        getAbsenceAt={byteReaders.get(pane.path)!.absence}
                        cursorOffset={cursorOffset}
                        selectionStart={selectionStart}
                        selectionEnd={selectionEnd}
                        regionIndex={regionIndex}
                        view={viewMode}
                      />
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <HexStatusBar />
    </div>
  );
}
