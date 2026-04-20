import { useHexStore } from "@/stores/hex-store";

export function HexStatusBar() {
  // Per-field selectors so chunk-load writes (pendingFetches / chunks) do
  // not trigger a re-render on every fetch — only cursor, selection, or
  // metadata changes should.
  const cursorOffset = useHexStore((s) => s.cursorOffset);
  const selection = useHexStore((s) => s.selection);
  const fileSize = useHexStore((s) => s.fileSize);
  const format = useHexStore((s) => s.format);
  const viewMode = useHexStore((s) => s.viewMode);
  const offsetLabel = format === "msl" && viewMode === "vas" ? "VAS" : "Offset";

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
          <span>{offsetLabel}: 0x{cursorOffset.toString(16).padStart(8, "0")}</span>
        )}
        {selLength > 0 && (
          <span>
            Sel: 0x{selStart!.toString(16).padStart(8, "0")}–0x{selEnd!.toString(16).padStart(8, "0")} ({selLength} bytes)
          </span>
        )}
        {cursorOffset !== null && (
          <span>
            Byte: {(() => {
              const b = useHexStore.getState().getByteAt(cursorOffset);
              if (b === undefined) return "—";
              return `0x${b.toString(16).padStart(2, "0")} (${b})`;
            })()}
          </span>
        )}
      </div>
      <span>
        {format.toUpperCase()}
        {format === "msl" ? ` · ${viewMode === "vas" ? "VAS" : "raw"}` : ""}
        {" | "}{(fileSize / 1024).toFixed(1)} KB | {totalRows} rows
      </span>
    </div>
  );
}
