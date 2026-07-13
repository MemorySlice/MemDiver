import { useTranslation } from "react-i18next";

interface FileBrowserPathBarProps {
  value: string;
  onChange: (value: string) => void;
  onFocus: () => void;
  onBlur: () => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  isBookmarked: boolean;
  canBookmark: boolean;
  onToggleBookmark: () => void;
}

export function FileBrowserPathBar({
  value,
  onChange,
  onFocus,
  onBlur,
  onKeyDown,
  isBookmarked,
  canBookmark,
  onToggleBookmark,
}: FileBrowserPathBarProps) {
  const { t } = useTranslation("wizard");
  return (
    <div className="px-3 py-1.5 border-b border-[var(--md-border)] flex items-center gap-2">
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={onFocus}
        onBlur={onBlur}
        onKeyDown={onKeyDown}
        placeholder={t("browser.pathPlaceholder")}
        className="flex-1 min-w-0 text-xs font-mono bg-transparent border-none md-text-muted focus:text-[var(--md-text-primary)]"
      />
      <button
        type="button"
        onClick={onToggleBookmark}
        disabled={!canBookmark}
        title={isBookmarked ? t("browser.bookmark.remove") : t("browser.bookmark.add")}
        className="shrink-0 px-1.5 py-0.5 rounded hover:bg-[var(--md-bg-hover)] transition-colors disabled:opacity-40"
        style={{ color: isBookmarked ? "var(--md-accent-blue)" : "var(--md-text-muted)" }}
      >
        {isBookmarked ? "\u2605" : "\u2606"}
      </button>
    </div>
  );
}
