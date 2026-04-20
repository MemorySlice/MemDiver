import { useEffect, useMemo, useCallback } from "react";
import { useStringsStore } from "@/stores/strings-store";
import { useHexStore } from "@/stores/hex-store";

const MAX_VISIBLE = 200;

function hexOffset(offset: number): string {
  return `0x${offset.toString(16).toUpperCase().padStart(8, "0")}`;
}

function truncateValue(value: string, maxLen = 60): string {
  return value.length > maxLen ? value.slice(0, maxLen) + "\u2026" : value;
}

interface Props {
  dumpPath: string;
}

export function StringsPanel({ dumpPath }: Props) {
  const {
    loading, error, truncated, totalCount,
    filterText, setFilterText,
    encoding, setEncoding,
    minLength, setMinLength,
    highlightActive, setHighlightActive,
    fetchStrings, getFilteredStrings,
  } = useStringsStore();

  useEffect(() => {
    if (dumpPath) fetchStrings(dumpPath);
  }, [dumpPath, fetchStrings]);

  const strings = useStringsStore((s) => s.strings);
  const currentFilterText = useStringsStore((s) => s.filterText);
  const filtered = useMemo(() => getFilteredStrings(), [strings, currentFilterText]);

  const handleRowClick = useCallback((offset: number) => {
    useHexStore.getState().scrollToOffset(offset);
  }, []);

  const handleRefetch = useCallback(() => {
    useStringsStore.getState().clear();
    fetchStrings(dumpPath);
  }, [dumpPath, fetchStrings]);

  if (loading) {
    return <p className="p-3 text-sm md-text-muted animate-pulse">Extracting strings...</p>;
  }

  if (error) {
    return <p className="p-3 text-sm" style={{ color: "var(--md-accent-red)" }}>{error}</p>;
  }

  const overflow = filtered.length > MAX_VISIBLE;

  return (
    <div className="h-full flex flex-col text-xs">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-[var(--md-border)] flex-wrap">
        <select
          value={encoding}
          onChange={(e) => setEncoding(e.target.value as "ascii" | "utf-8")}
          className="px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)] text-xs"
        >
          <option value="ascii">ASCII</option>
          <option value="utf-8">UTF-8</option>
        </select>

        <label className="flex items-center gap-1 md-text-secondary">
          Min:
          <input
            type="number"
            value={minLength}
            onChange={(e) => setMinLength(Math.max(1, parseInt(e.target.value) || 4))}
            className="w-12 px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-center text-xs"
          />
        </label>

        <button
          onClick={handleRefetch}
          className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors"
        >
          Extract
        </button>

        <input
          type="text"
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          placeholder="Filter strings..."
          className="flex-1 min-w-[100px] px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-xs"
        />

        <label className="flex items-center gap-1 cursor-pointer md-text-secondary whitespace-nowrap">
          <input
            type="checkbox"
            checked={highlightActive}
            onChange={(e) => setHighlightActive(e.target.checked)}
            className="accent-[var(--md-accent-blue)]"
          />
          Highlight
        </label>

        <span className="md-text-muted whitespace-nowrap">
          {typeof totalCount === "string" ? totalCount : filtered.length} strings
          {truncated && " (truncated)"}
        </span>
      </div>

      {/* Results table */}
      {filtered.length === 0 ? (
        <p className="p-3 text-center md-text-muted">
          {useStringsStore.getState().strings.length === 0
            ? "No strings found."
            : "No strings match filter."}
        </p>
      ) : (
        <div className="flex-1 overflow-auto">
          <table className="w-full text-[11px]">
            <thead className="sticky top-0 bg-[var(--md-bg-secondary)]">
              <tr className="md-text-muted border-b border-[var(--md-border)]">
                <th className="text-left px-2 py-1">Offset</th>
                <th className="text-left px-2 py-1">Value</th>
                <th className="text-left px-2 py-1">Enc</th>
                <th className="text-left px-2 py-1">Len</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, MAX_VISIBLE).map((s, i) => (
                <tr
                  key={i}
                  onClick={() => handleRowClick(s.offset)}
                  className="cursor-pointer hover:bg-[var(--md-bg-hover)] transition-colors border-t border-[var(--md-border)]"
                >
                  <td className="px-2 py-0.5 font-mono whitespace-nowrap">
                    {hexOffset(s.offset)}
                  </td>
                  <td className="px-2 py-0.5 max-w-[300px] truncate" title={s.value}>
                    {truncateValue(s.value)}
                  </td>
                  <td className="px-2 py-0.5 md-text-muted">{s.encoding}</td>
                  <td className="px-2 py-0.5">{s.length}</td>
                </tr>
              ))}
              {overflow && (
                <tr>
                  <td colSpan={4} className="px-2 py-1 md-text-muted">
                    ...and {filtered.length - MAX_VISIBLE} more
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
