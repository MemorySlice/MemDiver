import { useCallback, useMemo, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useVirtualizer } from "@tanstack/react-virtual";

import {
  useAlignedSelection,
  useAlignedWindowLoader,
  useConsensusUsable,
  useMslPaneCoordinate,
  useOverlayComposition,
} from "@/hooks/useAlignedPanes";
import { useHexKeyboard } from "@/hooks/useHexKeyboard";
import { useHexScrollTarget } from "@/hooks/useHexScrollTarget";
import { absenceForPageState, type AbsenceKind } from "@/utils/absence-classes";
import { useConsensusRun, useConsensusStore } from "@/stores/consensus-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { useOverlayRenderStore } from "@/stores/overlay-render-store";
import { overlayAbsenceAt, pluralityAt } from "./consensus-byte";
import { DumpRail } from "./DumpRail";
import { OverlayAlignSwitch } from "./OverlayAlignSwitch";
import { OverlayModeLegend } from "./OverlayModeLegend";
import { OverlayRenderModeSwitch } from "./OverlayRenderModeSwitch";
import { HexAlignmentChip } from "./HexAlignmentChip";
import { HexRow } from "./HexRow";
import { HexStatusBar } from "./HexStatusBar";
import { HexToolbar } from "./HexToolbar";
import { NoConsensusPrompt } from "./NoConsensusPrompt";
import { WindowErrorBanner } from "./WindowErrorBanner";
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
 * Layer 2 has THREE readings, chosen with the `Class | Variants | Glyph` switch
 * in the toolbar (`overlay-render-store`): the consensus bands, the count of
 * distinct values across the dumps, or a colour-free mark per byte. They are
 * mutually exclusive on a cell — `HexRow` enforces that — because two
 * vocabularies on one colour is exactly what the switch exists to avoid.
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
  const highlightedRegions = useHexStore((s) => s.highlightedRegions);
  const pageStateVersion = useHexStore((s) => s.pageStateVersion);
  const setCursor = useHexStore((s) => s.setCursor);
  const startSelection = useHexStore((s) => s.startSelection);
  const extendSelection = useHexStore((s) => s.extendSelection);
  const setFocusColumn = useHexStore((s) => s.setFocusColumn);

  // A consensus built over ANOTHER set of dumps is not a weaker answer to this
  // question, it is an answer to a different one — so it is treated exactly as
  // "no consensus" rather than projected onto bytes it never saw.
  const consensusUsable = useConsensusUsable(selectedPaths);
  // Only to tell the two fences apart: "nothing built yet" and "built over
  // other dumps" are different facts and need different sentences.
  const consensusId = useConsensusStore((s) => s.consensusId);
  // ONE in-flight flag, shared with `HexAlignmentChip` and `OverlayAlignSwitch`,
  // which render alongside this pane — see `useConsensusRun`.
  const { running, run } = useConsensusRun();

  const chunkVersionByPath = useMultiHexStore((s) => s.chunkVersionByPath);
  const alignment = useMultiHexStore((s) => s.alignment);

  const renderMode = useOverlayRenderStore((s) => s.renderMode);

  // WHOSE bytes this pane paints. `soloPath` swaps the whole stream for one
  // dump's own bytes; the weights and the exclusions change what the overlay
  // layer reduces to. All three therefore belong in the byte getters' deps,
  // not merely in the rail's own render. Resolved by `useOverlayComposition`,
  // the SAME source `HexStatusBar` reads — so the caption and the grid cannot
  // disagree about which dumps are on screen or how they are weighted.
  const { soloPath, includedPaths, weightFor } = useOverlayComposition(selected);

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

  /**
   * WHICH byte the grid prints — the substantive thing the rail changed.
   *
   * SOLO reads one dump's own bytes. The `Σ Overlay` layer reads the weighted
   * plurality across the included dumps, which is NOT the anchor's byte any
   * more: where the dumps agree it is that agreed byte (identical to what this
   * pane always painted), and where they disagree it is a computed value that
   * may exist in no single dump. That is stated in the rail, named in the
   * status footer, and left unreduced in `OverlayByteInspector`, which stays
   * the ground-truth surface.
   *
   * In both branches `isPresentAt` is the sole authority on presence —
   * `getByteAt` reports the stored `0` for an absent byte, so a reader that
   * skipped the mask would print a confident `00` over a hole.
   */
  const getByteAt = useCallback(
    (offset: number) => {
      void anchorVersion;
      if (soloPath) {
        const store = useMultiHexStore.getState();
        if (!store.isPresentAt(soloPath, offset)) return undefined;
        return store.getByteAt(soloPath, offset);
      }
      if (!anchorPath) return undefined;
      return pluralityAt(offset, includedPaths, weightFor).byte;
    },
    [anchorPath, anchorVersion, includedPaths, soloPath, weightFor],
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

  // How many DISTINCT values the aligned dumps hold here. Rotated by the same
  // anchor version as the other getters: the whole selection's chunks land in
  // one response, so a neighbour's bytes arriving cannot change this without
  // changing that.
  const getVariantsAt = useCallback(
    (offset: number) => {
      void anchorVersion;
      return useMultiHexStore.getState().variantsAt(offset);
    },
    [anchorVersion],
  );

  /**
   * WHY the anchor has no byte here — the store first, the page state second.
   *
   * The store knows the specific causes (this window failed, this window has
   * not arrived, the alignment holds nothing here, this dump does not hold it)
   * and they outrank a page state, which can only say something about a byte
   * the anchor DOES have. The page-state lookup stays gated on the "va"
   * coordinate because `getPageStateAt` reads `vaSpanStart + offset`; feeding
   * it a "vas" or "raw" offset would tint a byte by another byte's page.
   */
  const getAbsenceAt = useCallback(
    (offset: number): AbsenceKind | undefined => {
      void anchorVersion;
      void pageStateVersion;
      if (!anchorPath) return "loading";
      // Solo asks the one dump on screen; the overlay asks the whole included
      // set, because a byte three dumps hold and the anchor does not is real
      // data that the plurality paints — so it must not also report an absence.
      const absence = soloPath
        ? useMultiHexStore.getState().absenceAt(soloPath, offset)
        : overlayAbsenceAt(offset, includedPaths);
      if (absence) return absence;
      if (viewMode !== "va") return undefined;
      // `undefined` on fall-through, NOT "loading": the store has already said
      // the byte is present, so hatching it would void a byte the grid prints.
      return absenceForPageState(useHexStore.getState().getPageStateAt(offset));
    },
    [anchorPath, anchorVersion, includedPaths, pageStateVersion, soloPath, viewMode],
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

  // No usable consensus is an EMPTY STATE with the action in it, not a toast
  // and not a blank grid — see `NoConsensusPrompt`, which both multi-dump
  // viewers share so the fence reads the same either side of the layout switch.
  if (!consensusUsable) {
    return (
      <NoConsensusPrompt
        paths={selectedPaths}
        variant={consensusId ? "stale" : "missing"}
      />
    );
  }

  // A consensus built in raw file offsets cannot answer a virtual-address
  // question. The bytes are still real, so this is a banner over a live pane
  // rather than a replacement for it - but it names the fix.
  const rawOffsetConsensus = alignment?.method === "file_offset";

  /**
   * How many dumps the aligned window ACTUALLY compared.
   *
   * Not `selected.length`: alignment can discard a source (different module,
   * no overlap), and all three render modes describe a relationship BETWEEN
   * dumps — with one left they are the same picture. `n_sources` is the
   * honest count, and the switch dims rather than vanishes when it drops.
   */
  const alignedDumpCount = alignment?.n_sources ?? selected.length;

  return (
    <div
      ref={containerRef}
      data-testid="hex-overlay-pane"
      className="h-full flex flex-col overflow-hidden"
      tabIndex={0}
    >
      <HexToolbar />
      {/*
        Its own bar rather than a child of `HexAlignmentChip`: the chip already
        IS a bordered toolbar row, and nesting would double its rule and its
        padding. Sits directly under `HexToolbar` so the two segmented groups —
        the coordinate the bytes are addressed in, then the reading they are
        painted with — read top to bottom in the order the question is asked.
      */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-1 text-xs border-b border-[var(--md-border)] md-bg-secondary">
        {/*
          `Align` sits FIRST, because it is the question the other switch's
          answer depends on: what the render mode paints is only meaningful
          once you know what put the bytes in correspondence. Same segmented
          idiom as the three groups already in this area, deliberately.
        */}
        <OverlayAlignSwitch paths={selectedPaths} />
        {/*
          Dimmed in SOLO for the same reason it is dimmed below two dumps: all
          three modes describe a relationship BETWEEN dumps, and solo is showing
          exactly one. The existing condition is extended rather than a second
          one added, so there is still one rule for "this control has nothing to
          say right now".
        */}
        <OverlayRenderModeSwitch enabled={alignedDumpCount >= 2 && soloPath === null} />
      </div>
      <HexAlignmentChip
        paths={selectedPaths}
        hasMsl={selected.some((d) => d.format === "msl")}
      />

      <WindowErrorBanner
        testIdPrefix="hex-overlay"
        firstRow={firstVisibleIndex < 0 ? -1 : absRow(firstVisibleIndex)}
        lastRow={lastVisibleIndex < 0 ? -1 : absRow(lastVisibleIndex)}
      />

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
            // `useConsensusRun` brings the shared `aslrNormalize` intent along
            // with the coordinate this banner is asking for, so the dump list's
            // checkbox and the align switch agree with what just ran.
            onClick={() => run(selectedPaths, true)}
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
        {/*
          The legend describes the mode that is ON SCREEN, not all three at
          once — see `OverlayModeLegend`.
        */}
        <OverlayModeLegend mode={renderMode} />
      </div>

      {/*
        The rail costs the grid horizontal space, so it sits in a ROW with the
        scroller rather than above it — a full-width band would cost the grid
        vertical space it needs far more — and it collapses to a strip on
        demand.
      */}
      <div className="flex-1 flex overflow-hidden">
        <DumpRail dumps={selected} />

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
            {/*
              No RE-ANCHOR SEAM rules here, and deliberately so: every row is a
              fixed 20px and the virtualizer's `estimateSize` says so. A seam is
              a change of slope in the anchor→peer mapping, which the client can
              only find by differencing `segments[].dumps[].va` — the arithmetic
              invariant W1 forbids — and segment boundaries alone are page
              boundaries far more often than they are seams. Labelling one
              "re-anchor" would manufacture exactly the mapping artefact the
              design's caution warns about. The backend field that would make it
              honest is spec'd on `AlignedWindowSegment` in
              `@/api/aligned-window`.
            */}
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
                  regionIndex={regionIndex}
                  overlayEnabled
                  getClassificationAt={getClassificationAt}
                  getDiffersAt={getDiffersAt}
                  getVariantsAt={getVariantsAt}
                  renderMode={renderMode}
                  soloUnderline={soloPath !== null}
                  view={viewMode}
                  getAbsenceAt={getAbsenceAt}
                />
              </div>
            ))}
          </div>
        </div>
      </div>

      <HexStatusBar />
    </div>
  );
}
