import { useState, useCallback } from "react";
import { useHexStore } from "@/stores/hex-store";

export function HexToolbar() {
  // Per-field selectors — this component only reads metadata that changes
  // rarely, so keep it out of the chunk-load re-render path.
  const fileSize = useHexStore((s) => s.fileSize);
  const dumpPath = useHexStore((s) => s.dumpPath);
  const format = useHexStore((s) => s.format);
  const viewMode = useHexStore((s) => s.viewMode);
  const setViewMode = useHexStore((s) => s.setViewMode);
  const scrollToOffset = useHexStore((s) => s.scrollToOffset);
  const [offsetInput, setOffsetInput] = useState("");

  const handleGoTo = useCallback(() => {
    const val = offsetInput.trim();
    if (!val) return;
    const offset = val.startsWith("0x") || val.startsWith("0X")
      ? parseInt(val, 16)
      : parseInt(val, 10);
    if (!isNaN(offset) && offset >= 0 && offset < fileSize) {
      scrollToOffset(offset);
      setOffsetInput("");
    }
  }, [offsetInput, fileSize, scrollToOffset]);

  const fileName = dumpPath?.split(/[\\/]/).pop() ?? "";
  const sizeKB = (fileSize / 1024).toFixed(1);
  const isMsl = format === "msl";

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[var(--md-border)] md-bg-secondary text-xs">
      <span className="md-text-secondary truncate flex-1" title={dumpPath ?? ""}>
        {fileName} — {sizeKB} KB
      </span>
      {isMsl && (
        <div
          className="flex items-center shrink-0 rounded border border-[var(--md-border)] overflow-hidden"
          role="tablist"
          aria-label="MSL view mode"
          title="Raw: .msl container bytes. Memory: flattened captured VAS."
        >
          <button
            role="tab"
            aria-selected={viewMode === "raw"}
            onClick={() => setViewMode("raw")}
            className={
              "px-2 py-0.5 " +
              (viewMode === "raw"
                ? "md-bg-accent md-text-on-accent"
                : "hover:bg-[var(--md-bg-hover)]")
            }
          >
            Raw file
          </button>
          <button
            role="tab"
            aria-selected={viewMode === "vas"}
            onClick={() => setViewMode("vas")}
            className={
              "px-2 py-0.5 border-l border-[var(--md-border)] " +
              (viewMode === "vas"
                ? "md-bg-accent md-text-on-accent"
                : "hover:bg-[var(--md-bg-hover)]")
            }
          >
            Memory (VAS)
          </button>
        </div>
      )}
      <div className="flex items-center gap-1 shrink-0">
        <input
          type="text"
          value={offsetInput}
          onChange={(e) => setOffsetInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleGoTo()}
          placeholder="0x offset"
          className="w-24 px-2 py-0.5 rounded border border-[var(--md-border)] bg-transparent text-xs"
        />
        <button
          onClick={handleGoTo}
          className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
        >
          Go
        </button>
      </div>
    </div>
  );
}
