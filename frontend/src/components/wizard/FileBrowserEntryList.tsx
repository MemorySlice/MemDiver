import { forwardRef, type MouseEvent } from "react";
import type { BrowseEntry } from "@/api/types";

interface FileBrowserEntryListProps {
  loading: boolean;
  error: string | null;
  parentPath: string | null;
  displayEntries: BrowseEntry[];
  filter: string;
  onNavigateParent: (path: string) => void;
  onEntryClick: (entry: BrowseEntry) => void;
}

export const ENTRY_ROW_ATTR = "data-entry-row";

export const preventMouseDownFocus = (e: MouseEvent) => e.preventDefault();

const ENTRY_CLASS =
  "w-full flex items-center gap-2 px-3 py-2 text-sm hover:bg-[var(--md-bg-hover)] transition-colors text-left";

function formatSize(bytes: number): string {
  if (bytes === 0) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export const FileBrowserEntryList = forwardRef<HTMLDivElement, FileBrowserEntryListProps>(
  function FileBrowserEntryList(
    { loading, error, parentPath, displayEntries, filter, onNavigateParent, onEntryClick },
    ref,
  ) {
    return (
      <div className="overflow-y-auto" style={{ maxHeight: "calc(70vh - 140px)" }}>
        {loading && <div className="p-4 text-sm md-text-muted text-center">Loading...</div>}

        {error && (
          <div className="p-4 text-sm text-center" style={{ color: "var(--md-accent-red)" }}>
            {error}
          </div>
        )}

        {!loading && !error && (
          <div ref={ref} className="divide-y divide-[var(--md-border)]">
            {parentPath && !filter && (
              <button
                data-entry-row
                onMouseDown={preventMouseDownFocus}
                onClick={() => onNavigateParent(parentPath)}
                className={ENTRY_CLASS}
              >
                <span className="text-[var(--md-accent-blue)]">..</span>
                <span className="md-text-muted text-xs">Parent directory</span>
              </button>
            )}

            {displayEntries.length === 0 && (
              <div className="p-4 text-sm md-text-muted text-center">
                {filter ? `No matches for "${filter}"` : "Empty directory"}
              </div>
            )}

            {displayEntries.map((entry) => (
              <button
                key={entry.path}
                data-entry-row
                onMouseDown={preventMouseDownFocus}
                onClick={() => onEntryClick(entry)}
                className={ENTRY_CLASS}
              >
                <span className={entry.is_dir ? "text-[var(--md-accent-blue)]" : "md-text-secondary"}>
                  {entry.is_dir ? "\u{1F4C1}" : "\u{1F4C4}"}
                </span>
                <span className="flex-1 truncate">{entry.name}</span>
                {!entry.is_dir && (
                  <span className="md-text-muted text-xs shrink-0">{formatSize(entry.size)}</span>
                )}
              </button>
            ))}
          </div>
        )}
      </div>
    );
  },
);
