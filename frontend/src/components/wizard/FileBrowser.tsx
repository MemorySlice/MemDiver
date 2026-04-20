import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { browsePath } from "@/api/client";
import type { BrowseEntry } from "@/api/types";
import { useBrowserStore, normalizePath } from "@/stores/browser-store";
import { FileBrowserBookmarks } from "./FileBrowserBookmarks";
import { FileBrowserPathBar } from "./FileBrowserPathBar";
import { FileBrowserEntryList, ENTRY_ROW_ATTR } from "./FileBrowserEntryList";

interface FileBrowserProps {
  onSelect: (path: string) => void;
  onClose: () => void;
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

export function FileBrowser({ onSelect, onClose }: FileBrowserProps) {
  const [currentPath, setCurrentPath] = useState<string>("");
  const [editPath, setEditPath] = useState<string | null>(null);
  const [parentPath, setParentPath] = useState<string | null>(null);
  const [entries, setEntries] = useState<BrowseEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const addBookmark = useBrowserStore((s) => s.addBookmark);
  const removeBookmark = useBrowserStore((s) => s.removeBookmark);
  const bookmarks = useBrowserStore((s) => s.bookmarks);
  const isBookmarked = useBrowserStore((s) => s.isBookmarked(currentPath));

  const loadDirectory = useCallback(async (path?: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await browsePath(path);
      if (result.error) {
        setError(result.error);
        setEntries([]);
      } else {
        setCurrentPath(result.current);
        setEditPath(null);
        setParentPath(result.parent);
        setEntries(result.entries);
      }
    } catch {
      setError("Could not browse path. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDirectory();
  }, [loadDirectory]);

  const handleEntryClick = (entry: BrowseEntry) => {
    if (entry.is_dir) {
      loadDirectory(entry.path);
    } else {
      onSelect(entry.path);
    }
  };

  const handleSelectCurrentDir = () => {
    if (currentPath) onSelect(currentPath);
  };

  const filter = deriveFilter(editPath, currentPath);
  const displayEntries = useMemo(
    () => (filter ? entries.filter((e) => e.name.toLowerCase().startsWith(filter)) : entries),
    [entries, filter],
  );

  const toggleCurrentBookmark = () => {
    const norm = normalizePath(currentPath);
    if (!norm) return;
    const existing = bookmarks.find((b) => b.path === norm);
    if (existing) removeBookmark(existing.id);
    else addBookmark(norm);
  };

  const focusFirstEntry = () => {
    const first = listRef.current?.querySelector<HTMLButtonElement>(`button[${ENTRY_ROW_ATTR}]`);
    first?.focus();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div
        className="w-full max-w-lg mx-4 rounded-lg shadow-xl border border-[var(--md-border)]"
        style={{ background: "var(--md-bg-secondary)", maxHeight: "70vh" }}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-3 border-b border-[var(--md-border)]">
          <h3 className="text-sm font-semibold md-text-accent">Browse</h3>
          <button
            onClick={onClose}
            className="px-2 py-0.5 text-sm rounded hover:bg-[var(--md-bg-hover)] transition-colors"
            title="Close"
          >
            x
          </button>
        </div>

        <FileBrowserPathBar
          value={editPath ?? (currentPath || "Loading...")}
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
          isBookmarked={isBookmarked}
          canBookmark={!!currentPath}
          onToggleBookmark={toggleCurrentBookmark}
        />

        <FileBrowserBookmarks onNavigate={loadDirectory} />

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
            Cancel
          </button>
          <button
            onClick={handleSelectCurrentDir}
            disabled={!currentPath}
            className="px-3 py-1.5 text-sm rounded bg-[var(--md-accent-blue)] text-white hover:opacity-90 transition-opacity disabled:opacity-40"
          >
            Select This Directory
          </button>
        </div>
      </div>
    </div>
  );
}
