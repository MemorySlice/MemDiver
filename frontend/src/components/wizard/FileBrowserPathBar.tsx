import { useTranslation } from "react-i18next";

interface FileBrowserPathBarProps {
  value: string;
  onChange: (value: string) => void;
  onFocus: () => void;
  onBlur: () => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  isFavourite: boolean;
  canFavourite: boolean;
  onToggleFavourite: () => void;
}

export function FileBrowserPathBar({
  value,
  onChange,
  onFocus,
  onBlur,
  onKeyDown,
  isFavourite,
  canFavourite,
  onToggleFavourite,
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
        data-testid="file-browser-path"
        className="flex-1 min-w-0 text-xs font-mono bg-transparent border-none md-text-muted focus:text-[var(--md-text-primary)]"
      />
      {/*
        A bare ☆ with a tooltip is what this used to be, and nobody found it:
        the feature was invisible to anyone who did not already know it existed.
        The word carries the affordance, the glyph carries the state, and
        `aria-pressed` carries both to a screen reader.
      */}
      <button
        type="button"
        data-testid="file-browser-favourite-toggle"
        onClick={onToggleFavourite}
        disabled={!canFavourite}
        aria-pressed={isFavourite}
        title={isFavourite ? t("browser.favourites.remove") : t("browser.favourites.add")}
        className="shrink-0 flex items-center gap-1 px-2 py-0.5 rounded text-xs hover:bg-[var(--md-bg-hover)] transition-colors disabled:opacity-40"
        style={{ color: isFavourite ? "var(--md-accent-blue)" : "var(--md-text-muted)" }}
      >
        <span aria-hidden="true">{isFavourite ? "★" : "☆"}</span>
        <span>{isFavourite ? t("browser.favourites.saved") : t("browser.favourites.save")}</span>
      </button>
    </div>
  );
}
