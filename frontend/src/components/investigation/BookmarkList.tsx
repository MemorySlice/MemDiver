import { useState } from "react";
import type { Bookmark } from "@/stores/hex-store";

export type { Bookmark };

interface Props {
  bookmarks: Bookmark[];
  onAdd: (b: Bookmark) => void;
  onRemove: (offset: number) => void;
  onSelect: (offset: number) => void;
}

export function BookmarkList({ bookmarks, onAdd, onRemove, onSelect }: Props) {
  const [label, setLabel] = useState("");
  const [offset, setOffset] = useState("");

  const handleAdd = () => {
    const off = offset.startsWith("0x") ? parseInt(offset, 16) : parseInt(offset, 10);
    if (!isNaN(off) && label) {
      onAdd({ offset: off, length: 1, label });
      setLabel("");
      setOffset("");
    }
  };

  return (
    <div className="p-3 space-y-2 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">Bookmarks</h3>

      <div className="flex gap-1">
        <input value={offset} onChange={(e) => setOffset(e.target.value)} placeholder="0x offset"
          className="w-20 px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]" />
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label"
          onKeyDown={(e) => e.key === "Enter" && handleAdd()}
          className="flex-1 px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]" />
        <button onClick={handleAdd} aria-label="Add bookmark" className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">+</button>
      </div>

      {bookmarks.length === 0 ? (
        <p className="md-text-muted">No bookmarks yet.</p>
      ) : (
        <div className="space-y-1">
          {bookmarks.map((b) => (
            <div key={b.offset} className="flex items-center justify-between p-1.5 rounded hover:bg-[var(--md-bg-hover)]">
              <button onClick={() => onSelect(b.offset)} className="text-left flex-1 min-w-0 truncate" title={`0x${b.offset.toString(16)} — ${b.label}`} style={{ color: "var(--md-bookmark)" }}>
                <span className="font-mono">0x{b.offset.toString(16)}</span>
                <span className="ml-2 md-text-secondary">{b.label}</span>
              </button>
              <button onClick={() => onRemove(b.offset)} className="px-1 hover:text-[var(--md-accent-red)]">x</button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
