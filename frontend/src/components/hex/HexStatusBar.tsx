import { useTranslation } from "react-i18next";
import { useHexStore } from "@/stores/hex-store";
import {
  MAX_WINDOW_ROWS,
  windowCount,
  clampWindowStart,
} from "./window-utils";

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
  const offsetLabel = format === "msl" && viewMode === "vas" ? t("statusBar.offsetLabelVas") : t("statusBar.offsetLabelOffset");

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
          <span>
            {(() => {
              const b = useHexStore.getState().getByteAt(cursorOffset);
              if (b === undefined) return t("statusBar.byteEmpty");
              return t("statusBar.byte", { value: `0x${b.toString(16).padStart(2, "0")} (${b})` });
            })()}
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
          {format === "msl" ? ` · ${viewMode === "vas" ? "VAS" : "raw"}` : ""}
          {" | "}{t("statusBar.fileInfo", { size: (fileSize / 1024).toFixed(1), rows: totalRows })}
        </span>
      </div>
    </div>
  );
}
