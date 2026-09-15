import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { browsePath } from "@/api/client";
import type { BrowseEntry } from "@/api/types";
import { useBrowserStore, normalizePath } from "@/stores/browser-store";
import { FileBrowserFavourites } from "./FileBrowserFavourites";
import { FileBrowserPathBar } from "./FileBrowserPathBar";
import { FileBrowserEntryList, ENTRY_ROW_ATTR } from "./FileBrowserEntryList";

interface FileBrowserProps {
  onSelect: (path: string) => void;
  onClose: () => void;
  /**
   * Show every file, not only the dump extensions the endpoint filters to.
   *
   * Off by default so the dump pickers keep the filtered listing they rely on.
   * The oracle config editor turns it on: the sample files a Shape 2 oracle is
   * configured with (a gocryptfs ciphertext, say) carry no extension and are
   * otherwise invisible in this dialog.
   */
  allFiles?: boolean;
}

function deriveFilter(editPath: string | null, currentPath: string): string {
  if (editPath === null || !currentPath) return "";
  const norm = normalizePath(currentPath);
  if (editPath === norm || editPath === norm + "/") return "";
  const prefix = norm + "/";
  if (!editPath.startsWith(prefix)) return "";
  const remainder = editPath.slice(prefix.length);
  if (remainder.includes("/")) return "";
  return remainder.toLowerCase();
}

export function FileBrowser({ onSelect, onClose, allFiles = false }: FileBrowserProps) {
  const { t } = useTranslation("wizard");
  const [currentPath, setCurrentPath] = useState<string>("");
  const [editPath, setEditPath] = useState<string | null>(null);
  const [parentPath, setParentPath] = useState<string | null>(null);
  const [entries, setEntries] = useState<BrowseEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const addFavourite = useBrowserStore((s) => s.addFavourite);
  const removeFavourite = useBrowserStore((s) => s.removeFavourite);
  const rememberLastDir = useBrowserStore((s) => s.rememberLastDir);
  const loadFavourites = useBrowserStore((s) => s.load);
  const favouritesLoaded = useBrowserStore((s) => s.loaded);
  const lastDir = useBrowserStore((s) => s.lastDir);
  const isFavourite = useBrowserStore((s) => s.isFavourite(currentPath));

  /** Browse to `path` (or the server's default). Returns whether it landed. */
  const loadDirectory = useCallback(async (path?: string): Promise<boolean> => {
    setLoading(true);
    setError(null);
    try {
      // Only asked for when the caller wants it: the default browse keeps its
      // single-argument call, so nothing downstream changes behaviour.
      const result = allFiles
        ? await browsePath(path, true)
        : await browsePath(path);
      if (result.error) {
        setError(result.error);
        setEntries([]);
        return false;
      }
      setCurrentPath(result.current);
      setEditPath(null);
      setParentPath(result.parent);
      setEntries(result.entries);
      return true;
    } catch {
      setError(t("browser.browseError"));
      return false;
    } finally {
      setLoading(false);
    }
  }, [t, allFiles]);

  useEffect(() => {
    void loadFavourites();
  }, [loadFavourites]);

  /**
   * Open where the user left off, not at `$HOME` every single time.
   *
   * Deliberately waits for the favourites load rather than browsing home first
   * and jumping afterwards: that would spend two requests to show the user a
   * directory they did not ask for. `loaded` becomes true even when the load
   * FAILED, so a backend that cannot answer still opens the dialog — at home,
   * exactly as before.
   *
   * The remembered directory can also have been deleted or unmounted since,
   * which `browsePath` reports as an error and which would otherwise leave an
   * empty dialog with no way forward. So a failed seed falls back to home.
   */
  const openedRef = useRef(false);
  useEffect(() => {
    if (!favouritesLoaded || openedRef.current) return;
    openedRef.current = true;
    void (async () => {
      const landed = await loadDirectory(lastDir ?? undefined);
      if (!landed && lastDir) await loadDirectory();
    })();
  }, [favouritesLoaded, lastDir, loadDirectory]);

  const handleEntryClick = (entry: BrowseEntry) => {
    if (entry.is_dir) {
      loadDirectory(entry.path);
    } else {
      // The containing directory, not the file: what we reopen on is a place
      // to browse, and a file is not one.
      rememberLastDir(currentPath);
      onSelect(entry.path);
    }
  };

  const handleSelectCurrentDir = () => {
    if (!currentPath) return;
    // Remembered on the way OUT rather than on every navigation: one prefs
    // write per use of the dialog, instead of one per directory glanced at.
    rememberLastDir(currentPath);
    onSelect(currentPath);
  };

  const filter = deriveFilter(editPath, currentPath);
  const displayEntries = useMemo(
    () => (filter ? entries.filter((e) => e.name.toLowerCase().startsWith(filter)) : entries),
    [entries, filter],
  );

  const toggleCurrentFavourite = () => {
    const norm = normalizePath(currentPath);
    if (!norm) return;
    if (isFavourite) void removeFavourite(norm);
    else void addFavourite(norm);
  };

  const focusFirstEntry = () => {
    const first = listRef.current?.querySelector<HTMLButtonElement>(`button[${ENTRY_ROW_ATTR}]`);
    first?.focus();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div
        data-testid="file-browser"
        className="w-full max-w-lg mx-4 rounded-lg shadow-xl border border-[var(--md-border)]"
        style={{ background: "var(--md-bg-secondary)", maxHeight: "70vh" }}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-3 border-b border-[var(--md-border)]">
          <h3 className="text-sm font-semibold md-text-accent">{t("browser.title")}</h3>
          <button
            onClick={onClose}
            className="px-2 py-0.5 text-sm rounded hover:bg-[var(--md-bg-hover)] transition-colors"
            title={t("common:close")}
          >
            x
          </button>
        </div>

        <FileBrowserPathBar
          value={editPath ?? (currentPath || t("browser.loading"))}
          onChange={setEditPath}
          onFocus={() => { if (editPath === null) setEditPath(currentPath); }}
          onBlur={() => { if (editPath === currentPath) setEditPath(null); }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              if (filter && displayEntries.length === 1) {
                handleEntryClick(displayEntries[0]);
                return;
              }
              if (editPath?.trim()) loadDirectory(editPath.trim());
            } else if (e.key === "Tab" && !e.shiftKey && filter && displayEntries.length > 0) {
              e.preventDefault();
              const norm = normalizePath(currentPath);
              const name = displayEntries[0].name;
              setEditPath(norm === "/" ? `/${name}` : `${norm}/${name}`);
            } else if (e.key === "Escape") {
              setEditPath(null);
              (e.target as HTMLInputElement).blur();
            } else if (e.key === "ArrowDown" && displayEntries.length > 0) {
              e.preventDefault();
              focusFirstEntry();
            }
          }}
          isFavourite={isFavourite}
          canFavourite={!!currentPath}
          onToggleFavourite={toggleCurrentFavourite}
        />

        <FileBrowserFavourites onNavigate={loadDirectory} />

        <FileBrowserEntryList
          ref={listRef}
          loading={loading}
          error={error}
          parentPath={parentPath}
          displayEntries={displayEntries}
          filter={filter}
          onNavigateParent={loadDirectory}
          onEntryClick={handleEntryClick}
        />

        {/* Footer */}
        <div className="flex items-center justify-between p-3 border-t border-[var(--md-border)]">
          <button
            onClick={onClose}
            className="px-3 py-1.5 text-sm rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors"
          >
            {t("common:cancel")}
          </button>
          <button
            onClick={handleSelectCurrentDir}
            disabled={!currentPath}
            className="px-3 py-1.5 text-sm rounded bg-[var(--md-accent-blue)] md-text-on-accent hover:opacity-90 transition-opacity disabled:opacity-40"
          >
            {t("browser.selectDirectory")}
          </button>
        </div>
      </div>
    </div>
  );
}
