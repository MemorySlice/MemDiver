import { useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useHexStore } from "@/stores/hex-store";
import { HexSearchBox } from "@/components/hex/HexSearchBox";
import { SegmentedControl } from "@/components/common/SegmentedControl";
import type { HexViewMode } from "@/stores/hex-store";

export function HexToolbar() {
  const { t } = useTranslation("hex");
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
    /*
     * `flex-wrap` is load bearing, not cosmetic.
     *
     * The three control groups to the right (view tabs ~201px, go-to ~132px,
     * find ~209px) are all `shrink-0` and together occupy 542px of a 572px
     * toolbar in the default layout. The file-name span was the only flexible
     * item, so it absorbed the entire deficit and measured ZERO pixels wide —
     * in the single-dump viewer as well as the N-pane one. The name is what
     * tells the analyst WHICH dump is on screen, which matters more, not less,
     * once several panes are open.
     *
     * Wrapping lets the widest group drop to a second line instead of eating
     * the label; `min-w-[9rem]` is the floor the label keeps in either case,
     * and `truncate` still handles a long name gracefully.
     */
    <div className="flex flex-wrap items-center gap-2 px-3 py-1.5 border-b border-[var(--md-border)] md-bg-secondary text-xs">
      <span
        className="md-text-secondary truncate flex-1 min-w-[9rem]"
        title={dumpPath ?? ""}
      >
        {t("toolbar.fileLabel", { name: fileName, size: sizeKB })}
      </span>
      {/*
        The same shared segmented group as `MainViewSwitcher` and the overlay's
        two switches, so every radio-style control in the hex area behaves
        identically for a screen reader.
      */}
      {isMsl && (
        <SegmentedControl
          aria-label={t("toolbar.mslViewModeLabel")}
          title={t("toolbar.mslViewModeTitle")}
          selected={viewMode}
          onSelect={(id) => setViewMode(id as HexViewMode)}
          options={[
            { id: "raw", label: t("toolbar.rawFile") },
            { id: "vas", label: t("toolbar.memoryVas") },
            {
              id: "va",
              label: t("toolbar.virtualAddress"),
              title: t("toolbar.mslViewModeVaTitle"),
            },
          ]}
        />
      )}
      <div className="flex items-center gap-1 shrink-0">
        <input
          type="text"
          value={offsetInput}
          onChange={(e) => setOffsetInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleGoTo()}
          placeholder={t("toolbar.offsetPlaceholder")}
          className="w-24 px-2 py-0.5 rounded border border-[var(--md-border)] bg-transparent text-xs"
        />
        <button
          onClick={handleGoTo}
          className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
        >
          {t("toolbar.go")}
        </button>
      </div>
      <HexSearchBox />
    </div>
  );
}
