import { useState } from "react";
import { useBrowserStore } from "@/stores/browser-store";
import { preventMouseDownFocus } from "./FileBrowserEntryList";

interface FileBrowserBookmarksProps {
  onNavigate: (path: string) => void;
}

export function FileBrowserBookmarks({ onNavigate }: FileBrowserBookmarksProps) {
  const bookmarks = useBrowserStore((s) => s.bookmarks);
  const removeBookmark = useBrowserStore((s) => s.removeBookmark);
  const [collapsed, setCollapsed] = useState(false);

  if (bookmarks.length === 0) return null;

  return (
    <div className="border-b border-[var(--md-border)]">
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        className="w-full flex items-center justify-between px-3 py-1.5 text-xs md-text-muted hover:bg-[var(--md-bg-hover)] transition-colors"
        title={collapsed ? "Expand bookmarks" : "Collapse bookmarks"}
      >
        <span className="flex items-center gap-1.5">
          <span className="text-[var(--md-accent-blue)]">{"\u2605"}</span>
          <span>Bookmarks ({bookmarks.length})</span>
        </span>
        <span>{collapsed ? "\u25B8" : "\u25BE"}</span>
      </button>

      {!collapsed && (
        <div className="overflow-y-auto" style={{ maxHeight: "140px" }}>
          {bookmarks.map((bm) => (
            <div
              key={bm.id}
              className="group flex items-center text-sm hover:bg-[var(--md-bg-hover)] transition-colors"
            >
              <button
                type="button"
                onMouseDown={preventMouseDownFocus}
                onClick={() => onNavigate(bm.path)}
                title={bm.path}
                className="flex-1 min-w-0 flex items-center gap-2 px-3 py-1.5 text-left"
              >
                <span className="text-[var(--md-accent-blue)] shrink-0">{"\u2605"}</span>
                <span className="shrink-0 truncate max-w-[140px]">{bm.label}</span>
                <span className="flex-1 truncate text-xs md-text-muted font-mono">{bm.path}</span>
              </button>
              <button
                type="button"
                onClick={() => removeBookmark(bm.id)}
                className="shrink-0 px-2 py-1.5 text-xs md-text-muted opacity-0 group-hover:opacity-100 focus:opacity-100 hover:text-[var(--md-accent-red)] transition-opacity"
                title="Remove bookmark"
              >
                {"\u2715"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
