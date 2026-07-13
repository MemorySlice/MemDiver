import { useTranslation } from "react-i18next";
import { useHexStore } from "@/stores/hex-store";

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
  const offsetLabel = format === "msl" && viewMode === "vas" ? t("statusBar.offsetLabelVas") : t("statusBar.offsetLabelOffset");

  const selStart = selection
    ? Math.min(selection.anchor, selection.active)
    : null;
  const selEnd = selection
    ? Math.max(selection.anchor, selection.active)
    : null;
  const selLength = selStart !== null && selEnd !== null ? selEnd - selStart + 1 : 0;

  const totalRows = Math.ceil(fileSize / 16);

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
      <span>
        {format.toUpperCase()}
        {format === "msl" ? ` · ${viewMode === "vas" ? "VAS" : "raw"}` : ""}
        {" | "}{t("statusBar.fileInfo", { size: (fileSize / 1024).toFixed(1), rows: totalRows })}
      </span>
    </div>
  );
}
