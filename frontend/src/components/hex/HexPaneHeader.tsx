import { useTranslation } from "react-i18next";

import type { DumpEntry } from "@/stores/dump-store";

/**
 * The sticky identity strip at the top of one side-by-side pane.
 *
 * Every pane shows the SAME row offsets, so the header is the only thing that
 * says which dump a column of bytes belongs to. It therefore never relies on
 * colour alone: ORIGIN and FOCUS are text pills, and the focused pane is marked
 * with `aria-current` as well as an accent border, so the answer to "which pane
 * anchors the alignment?" survives a screen reader and a monochrome display.
 */
export interface HexPaneHeaderProps {
  dump: DumpEntry;
  isOrigin: boolean;
  isFocused: boolean;
  widthPx: number;
  onFocus: () => void;
  onCollapse: () => void;
  /** Per-pane load failure, surfaced in place rather than as a toast. */
  error?: string | null;
}

export function HexPaneHeader({
  dump,
  isOrigin,
  isFocused,
  widthPx,
  onFocus,
  onCollapse,
  error = null,
}: HexPaneHeaderProps) {
  const { t } = useTranslation("hex");
  const sizeKb = Math.max(1, Math.round(dump.size / 1024));

  return (
    <div
      data-testid={`hex-pane-header-${dump.id}`}
      data-pane-id={dump.id}
      aria-current={isFocused ? "true" : undefined}
      className="shrink-0 flex flex-col gap-0.5 px-2 py-1 md-bg-secondary border-b border-r border-[var(--md-border)] text-xs cursor-pointer"
      style={{
        width: widthPx,
        // The accent border is the redundant, non-textual half of the focus
        // signal; the FOCUS pill below carries the same fact in words.
        borderTop: isFocused
          ? "2px solid var(--md-accent-blue)"
          : "2px solid transparent",
      }}
      onClick={onFocus}
    >
      <div className="flex items-center gap-1 min-w-0">
        <button
          type="button"
          data-testid={`hex-pane-focus-${dump.id}`}
          aria-label={t("pane.focusAction", { name: dump.name })}
          onClick={(e) => {
            e.stopPropagation();
            onFocus();
          }}
          className="font-mono truncate max-w-[14rem] text-left"
          title={dump.path}
        >
          {dump.name}
        </button>
        <span
          data-testid={`hex-pane-format-${dump.id}`}
          className="px-1 rounded text-[9px] font-semibold uppercase shrink-0"
          style={{ background: "var(--md-bg-tertiary)" }}
        >
          {dump.format}
        </span>
        {isOrigin && (
          <span
            data-testid={`hex-pane-origin-${dump.id}`}
            title={t("pane.originTitle")}
            className="px-1 rounded text-[9px] font-semibold uppercase shrink-0"
            style={{ background: "var(--md-bg-tertiary)" }}
          >
            {t("pane.origin")}
          </span>
        )}
        {isFocused && (
          <span
            data-testid={`hex-pane-focus-pill-${dump.id}`}
            title={t("pane.focusTitle")}
            className="px-1 rounded text-[9px] font-semibold uppercase shrink-0 md-bg-accent md-text-on-accent"
          >
            {t("pane.focus")}
          </span>
        )}
        <span className="ml-auto shrink-0 md-text-muted">
          {t("pane.size", { size: sizeKb })}
        </span>
        <button
          type="button"
          data-testid={`hex-pane-collapse-${dump.id}`}
          aria-label={t("pane.collapse", { name: dump.name })}
          title={t("pane.collapse", { name: dump.name })}
          onClick={(e) => {
            // Collapsing must not also focus the pane being folded away.
            e.stopPropagation();
            onCollapse();
          }}
          className="shrink-0 px-1 rounded hover:bg-[var(--md-bg-hover)]"
        >
          {"◎"}
        </button>
      </div>
      {error && (
        <span role="status" className="md-text-error truncate" title={error}>
          {t("multiHex.paneError", { name: dump.name, error })}
        </span>
      )}
    </div>
  );
}
