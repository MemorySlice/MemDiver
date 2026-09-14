import { useTranslation } from "react-i18next";
import { useAlignedSelection, useOverlayComposition } from "@/hooks/useAlignedPanes";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { pluralityAt } from "./consensus-byte";
import {
  MAX_WINDOW_ROWS,
  windowCount,
  clampWindowStart,
} from "./window-utils";

/**
 * The always-on footer — and, since the overlay stopped painting the anchor's
 * bytes, the only thing on screen that says WHOSE bytes those are.
 *
 * The layer line is a forensics requirement rather than a nicety. The grid can
 * now be showing one dump's real bytes or a weighted plurality across several,
 * and the two look identical: same monospace hex, same classes, same ring. An
 * analyst who quotes a byte has to be able to say where it came from without
 * remembering which chip they last clicked, so the footer states it on every
 * frame — the same argument `HexAlignmentChip` makes for naming the alignment
 * method every time instead of only when something looks wrong.
 *
 * `Agreement: k/N` is the companion fact: of the N included dumps PRESENT at
 * the cursor, how many actually hold the byte being painted. `N` counts present
 * dumps rather than included ones so that `k/N` is self-consistent (an absent
 * dump agrees with nothing and disagrees with nothing); when nobody is present
 * the ratio has no denominator and the field says `n/a (void)` instead of
 * inventing `0/0`.
 *
 * Both fields are shown only in the aligned overlay. The single-dump and
 * side-by-side viewers mount this same bar and have no layer to name: every
 * pane there is one dump's own bytes, said by the pane header.
 */

/**
 * One dump's OWN byte at `offset`, or `undefined` where it holds none.
 *
 * `isPresentAt` is the sole authority on presence, exactly as in the grid:
 * `getByteAt` hands back the stored `0` for a byte the dump does not hold, and
 * a status bar that printed `Byte: 0x00 (0)` over a hole would be stating a
 * value no dump contains.
 */
function soloByteAt(path: string, offset: number): number | undefined {
  const store = useMultiHexStore.getState();
  if (!store.isPresentAt(path, offset)) return undefined;
  return store.getByteAt(path, offset);
}

export function HexStatusBar() {
  const { t } = useTranslation("hex");
  // Per-field selectors so chunk-load writes (pendingFetches / chunks) do
  // not trigger a re-render on every fetch — only cursor, selection, or
  // metadata changes should.
  const cursorOffset = useHexStore((s) => s.cursorOffset);
  const selection = useHexStore((s) => s.selection);
  const fileSize = useHexStore((s) => s.fileSize);
  const format = useHexStore((s) => s.format);
  const viewMode = useHexStore((s) => s.viewMode);
  const windowStartRow = useHexStore((s) => s.windowStartRow);
  const setWindowStart = useHexStore((s) => s.setWindowStart);
  const chunkError = useHexStore((s) => s.chunkError);

  // The overlay layer, named. `mainView` rather than a prop because this bar is
  // mounted by three different viewers and the layer is a property of which one
  // is on screen, not of who rendered the bar.
  const mainView = useDumpStore((s) => s.mainView);
  // Rotates the agreement figure as the window's bytes land, the same way
  // `OverlayByteInspector` keeps its table filling in.
  const chunkVersionByPath = useMultiHexStore((s) => s.chunkVersionByPath);
  const { selected } = useAlignedSelection();
  // The SAME source `HexOverlayPane` reads for the grid it captions. Both files
  // used to carry a comment saying the two must not disagree while each derived
  // the answer its own way; this is the one source those comments argued for.
  const { soloDump, soloPath, includedPaths, weightFor } = useOverlayComposition(selected);

  const isOverlay = mainView === "overlay";

  void chunkVersionByPath;
  const agreement =
    isOverlay && cursorOffset !== null
      ? pluralityAt(cursorOffset, includedPaths, weightFor)
      : null;

  /**
   * The byte the GRID is painting at the cursor — whoever is painting it.
   *
   * This used to be `hex-store.getByteAt`, the ANCHOR's own cache, in a bar
   * that captions the same cell with `Solo: <name>` and `Agreement: k/N`
   * derived from the plurality over the included dumps. Solo a non-anchor dump
   * and the three disagreed: the grid showed B's bytes, the caption said B, and
   * `Byte:` reported A's. That caption-versus-grid split is the exact failure
   * `useOverlayComposition` was introduced to make impossible, so the readout is
   * resolved from the same composition and the same `pluralityAt` result the
   * agreement figure beside it already uses.
   *
   * Outside the overlay the anchor's cache is still the right answer: the
   * single-dump viewer IS the anchor, and every side-by-side pane says whose
   * bytes it holds in its own header.
   */
  const cursorByte =
    cursorOffset === null
      ? undefined
      : !isOverlay
        ? useHexStore.getState().getByteAt(cursorOffset)
        : soloPath
          ? soloByteAt(soloPath, cursorOffset)
          : agreement?.byte;
  const offsetLabel = format === "msl" && viewMode === "vas" ? t("statusBar.offsetLabelVas") : t("statusBar.offsetLabelOffset");

  // All three MSL view modes need a distinct label. Collapsing "va" into the
  // "raw" branch (as a `viewMode === "vas" ? … : "raw"` ternary does) makes the
  // status bar actively lie about which byte stream is on screen, which is the
  // one place a forensic user checks when the viewer looks wrong.
  const viewModeLabel =
    viewMode === "vas"
      ? t("statusBar.viewModeVas")
      : viewMode === "va"
        ? t("statusBar.viewModeVa")
        : t("statusBar.viewModeRaw");

  const selStart = selection
    ? Math.min(selection.anchor, selection.active)
    : null;
  const selEnd = selection
    ? Math.max(selection.anchor, selection.active)
    : null;
  const selLength = selStart !== null && selEnd !== null ? selEnd - selStart + 1 : 0;

  const totalRows = Math.ceil(fileSize / 16);

  // Bounded-window navigation only matters when the file is larger than a
  // single window; smaller files always render every row at once.
  const windowed = totalRows > MAX_WINDOW_ROWS;
  const safeStart = clampWindowStart(windowStartRow, totalRows);
  const windowRows = windowCount(safeStart, totalRows);
  const atStart = safeStart === 0;
  const atEnd = safeStart + windowRows >= totalRows;

  return (
    <div className="flex items-center justify-between px-3 py-1 border-t border-[var(--md-border)] md-bg-secondary text-xs md-text-muted">
      <div className="flex items-center gap-3">
        {isOverlay && (
          <span data-testid="hex-status-layer">
            {soloDump
              ? t("statusBar.layerSolo", { name: soloDump.name })
              : t("statusBar.layerOverlay", { n: includedPaths.length })}
          </span>
        )}
        {isOverlay && cursorOffset !== null && (
          <span data-testid="hex-status-agreement">
            {agreement && agreement.present > 0
              ? t("statusBar.agreement", {
                  agreeing: agreement.agreeing,
                  present: agreement.present,
                })
              : t("statusBar.agreementVoid")}
          </span>
        )}
        {cursorOffset !== null && (
          <span>{t("statusBar.cursor", { label: offsetLabel, offset: cursorOffset.toString(16).padStart(8, "0") })}</span>
        )}
        {selLength > 0 && (
          <span>
            {t("statusBar.selection", {
              start: selStart!.toString(16).padStart(8, "0"),
              end: selEnd!.toString(16).padStart(8, "0"),
              length: selLength,
            })}
          </span>
        )}
        {cursorOffset !== null && (
          <span data-testid="hex-status-byte">
            {cursorByte === undefined
              ? t("statusBar.byteEmpty")
              : t("statusBar.byte", {
                  value: `0x${cursorByte.toString(16).padStart(2, "0")} (${cursorByte})`,
                })}
          </span>
        )}
        {chunkError && (
          <span className="md-text-error" role="status">
            {t("statusBar.chunkError", { error: chunkError })}
          </span>
        )}
      </div>
      <div className="flex items-center gap-3">
        {windowed && (
          <div className="flex items-center gap-1">
            <span>
              {t("window.range", {
                start: safeStart,
                end: safeStart + windowRows - 1,
                total: totalRows,
              })}
            </span>
            <button
              onClick={() => setWindowStart(clampWindowStart(safeStart - MAX_WINDOW_ROWS, totalRows))}
              disabled={atStart}
              title={t("window.prev")}
              className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50"
            >
              {t("window.prev")}
            </button>
            <button
              onClick={() => setWindowStart(clampWindowStart(safeStart + MAX_WINDOW_ROWS, totalRows))}
              disabled={atEnd}
              title={t("window.next")}
              className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50"
            >
              {t("window.next")}
            </button>
          </div>
        )}
        <span>
          {format.toUpperCase()}
          {format === "msl" ? ` · ${viewModeLabel}` : ""}
          {" | "}{t("statusBar.fileInfo", { size: (fileSize / 1024).toFixed(1), rows: totalRows })}
        </span>
      </div>
    </div>
  );
}
