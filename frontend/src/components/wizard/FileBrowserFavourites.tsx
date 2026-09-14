import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useBrowserStore } from "@/stores/browser-store";
import { preventMouseDownFocus } from "./FileBrowserEntryList";

interface FileBrowserFavouritesProps {
  onNavigate: (path: string) => void;
}

/**
 * The saved-directories section of the browse dialog.
 *
 * Renders even when the list is EMPTY, which is the whole point of the empty
 * state below. Hiding it until the first favourite exists made the feature
 * undiscoverable in the only place it could ever have been discovered: a user
 * had to already know about the ☆ to make the thing that explains the ☆ appear.
 */
export function FileBrowserFavourites({ onNavigate }: FileBrowserFavouritesProps) {
  const { t } = useTranslation("wizard");
  const favourites = useBrowserStore((s) => s.favourites);
  const removeFavourite = useBrowserStore((s) => s.removeFavourite);
  const [collapsed, setCollapsed] = useState(false);

  const empty = favourites.length === 0;

  return (
    <div className="border-b border-[var(--md-border)]" data-testid="file-browser-favourites">
      {/*
        A heading, not a disabled button: with nothing saved there is nothing to
        collapse, and a focusable control that announces itself as unavailable
        is a worse first impression of the feature than plain text.
      */}
      {empty ? (
        <div className="px-3 py-1.5 text-xs md-text-muted">
          <p className="flex items-center gap-1.5">
            <span className="text-[var(--md-accent-blue)]" aria-hidden="true">
              {"★"}
            </span>
            <span>{t("browser.favourites.heading")}</span>
          </p>
          <p data-testid="file-browser-favourites-empty" className="mt-0.5">
            {t("browser.favourites.empty")}
          </p>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setCollapsed((c) => !c)}
          aria-expanded={!collapsed}
          className="w-full flex items-center justify-between px-3 py-1.5 text-xs md-text-muted hover:bg-[var(--md-bg-hover)] transition-colors"
          title={collapsed ? t("browser.favourites.expand") : t("browser.favourites.collapse")}
        >
          <span className="flex items-center gap-1.5">
            <span className="text-[var(--md-accent-blue)]" aria-hidden="true">
              {"★"}
            </span>
            <span>{t("browser.favourites.title", { count: favourites.length })}</span>
          </span>
          <span aria-hidden="true">{collapsed ? "▸" : "▾"}</span>
        </button>
      )}

      {!empty && !collapsed && (
        <div className="overflow-y-auto" style={{ maxHeight: "140px" }}>
          {favourites.map((fav) => (
            <div
              key={fav.path}
              data-testid="file-browser-favourite"
              className="group flex items-center text-sm hover:bg-[var(--md-bg-hover)] transition-colors"
            >
              <button
                type="button"
                data-testid="file-browser-favourite-open"
                onMouseDown={preventMouseDownFocus}
                onClick={() => onNavigate(fav.path)}
                title={fav.path}
                className="flex-1 min-w-0 flex items-center gap-2 px-3 py-1.5 text-left"
              >
                <span className="text-[var(--md-accent-blue)] shrink-0" aria-hidden="true">
                  {"★"}
                </span>
                <span className="shrink-0 truncate max-w-[140px]">{fav.label}</span>
                <span className="flex-1 truncate text-xs md-text-muted font-mono">
                  {fav.path}
                </span>
              </button>
              <button
                type="button"
                data-testid="file-browser-favourite-remove"
                onClick={() => void removeFavourite(fav.path)}
                className="shrink-0 px-2 py-1.5 text-xs md-text-muted opacity-0 group-hover:opacity-100 focus:opacity-100 hover:text-[var(--md-accent-red)] transition-opacity"
                title={t("browser.favourites.remove")}
                aria-label={t("browser.favourites.removeNamed", { label: fav.label })}
              >
                {"✕"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
