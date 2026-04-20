import { useState } from "react";

interface Props {
  currentOffset: number;
  fileSize: number;
  pageSize: number;
  onNavigate: (offset: number) => void;
  onGoToOffset: (offset: number) => void;
}

export function HexControls({ currentOffset, fileSize, pageSize, onNavigate, onGoToOffset }: Props) {
  const [offsetInput, setOffsetInput] = useState("");

  const handleGo = () => {
    const val = offsetInput.startsWith("0x")
      ? parseInt(offsetInput, 16)
      : parseInt(offsetInput, 10);
    if (!isNaN(val) && val >= 0 && val < fileSize) {
      onGoToOffset(val);
      setOffsetInput("");
    }
  };

  const prevPage = () => onNavigate(Math.max(0, currentOffset - pageSize));
  const nextPage = () => onNavigate(Math.min(fileSize - pageSize, currentOffset + pageSize));

  const currentPage = Math.floor(currentOffset / pageSize) + 1;
  const totalPages = Math.ceil(fileSize / pageSize);

  return (
    <div className="flex items-center gap-2 px-2 py-1.5 border-b border-[var(--md-border)] text-xs">
      <button onClick={prevPage} disabled={currentOffset === 0}
        className="px-2 py-0.5 rounded border border-[var(--md-border)] disabled:opacity-30 hover:bg-[var(--md-bg-hover)]">
        Prev
      </button>
      <span className="md-text-secondary">
        Page {currentPage}/{totalPages}
      </span>
      <button onClick={nextPage} disabled={currentOffset + pageSize >= fileSize}
        className="px-2 py-0.5 rounded border border-[var(--md-border)] disabled:opacity-30 hover:bg-[var(--md-bg-hover)]">
        Next
      </button>
      <span className="mx-1 md-text-muted">|</span>
      <input
        type="text"
        value={offsetInput}
        onChange={(e) => setOffsetInput(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && handleGo()}
        placeholder="0x offset"
        className="w-24 px-1.5 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]"
      />
      <button onClick={handleGo}
        className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
        Go
      </button>
    </div>
  );
}
