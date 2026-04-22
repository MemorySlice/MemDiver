import { useEffect, useMemo, useRef, useCallback, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useStringsStore } from "@/stores/strings-store";
import { useHexStore } from "@/stores/hex-store";

const ROW_HEIGHT = 22;
const OVERSCAN = 10;
const PREFETCH_MARGIN = 50;
const HIGHLIGHT_ALL_CONFIRM_THRESHOLD = 2000;

function hexOffset(offset: number): string {
  return `0x${offset.toString(16).toUpperCase().padStart(8, "0")}`;
}

function truncateValue(value: string, maxLen = 120): string {
  return value.length > maxLen ? value.slice(0, maxLen) + "…" : value;
}

interface Props {
  dumpPath: string;
}

export function StringsPanel({ dumpPath }: Props) {
  const rows = useStringsStore((s) => s.rows);
  const fetching = useStringsStore((s) => s.fetching);
  const done = useStringsStore((s) => s.done);
  const error = useStringsStore((s) => s.error);
  const truncated = useStringsStore((s) => s.truncated);
  const totalCount = useStringsStore((s) => s.totalCount);
  const filterText = useStringsStore((s) => s.filterText);
  const encoding = useStringsStore((s) => s.encoding);
  const minLength = useStringsStore((s) => s.minLength);
  const highlightActive = useStringsStore((s) => s.highlightActive);
  const highlightAllWarn = useStringsStore((s) => s.highlightAllWarn);

  const setFilterText = useStringsStore((s) => s.setFilterText);
  const setEncoding = useStringsStore((s) => s.setEncoding);
  const setMinLength = useStringsStore((s) => s.setMinLength);
  const setHighlightActive = useStringsStore((s) => s.setHighlightActive);
  const setHighlightAllWarn = useStringsStore((s) => s.setHighlightAllWarn);
  const setVisibleRange = useStringsStore((s) => s.setVisibleRange);
  const resetAndFetch = useStringsStore((s) => s.resetAndFetch);
  const fetchNextPage = useStringsStore((s) => s.fetchNextPage);
  const getFilteredStrings = useStringsStore((s) => s.getFilteredStrings);

  const [confirmOpen, setConfirmOpen] = useState(false);

  useEffect(() => {
    if (dumpPath) resetAndFetch(dumpPath);
  }, [dumpPath, resetAndFetch]);

  const filteredRows = useMemo(
    () => getFilteredStrings(),
    [rows, filterText, getFilteredStrings],
  );

  const parentRef = useRef<HTMLDivElement | null>(null);
  const rowVirtualizer = useVirtualizer({
    count: filteredRows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: OVERSCAN,
  });

  const virtualItems = rowVirtualizer.getVirtualItems();
  const firstVisibleIndex = virtualItems[0]?.index ?? -1;
  const lastVisibleIndex = virtualItems[virtualItems.length - 1]?.index ?? -1;

  useEffect(() => {
    if (firstVisibleIndex < 0) return;
    setVisibleRange(firstVisibleIndex, lastVisibleIndex);
    if (
      !done &&
      !fetching &&
      lastVisibleIndex >= filteredRows.length - PREFETCH_MARGIN
    ) {
      fetchNextPage();
    }
  }, [
    firstVisibleIndex,
    lastVisibleIndex,
    filteredRows.length,
    done,
    fetching,
    fetchNextPage,
    setVisibleRange,
  ]);

  const handleRowClick = useCallback((offset: number) => {
    useHexStore.getState().scrollToOffset(offset);
  }, []);

  const handleRefetch = useCallback(() => {
    resetAndFetch(dumpPath);
  }, [dumpPath, resetAndFetch]);

  const handleToggleHighlightAll = useCallback(() => {
    if (highlightAllWarn) {
      setHighlightAllWarn(false);
      return;
    }
    if (filteredRows.length > HIGHLIGHT_ALL_CONFIRM_THRESHOLD) {
      setConfirmOpen(true);
      return;
    }
    setHighlightAllWarn(true);
  }, [filteredRows.length, highlightAllWarn, setHighlightAllWarn]);

  const confirmHighlightAll = useCallback(() => {
    setHighlightAllWarn(true);
    setConfirmOpen(false);
  }, [setHighlightAllWarn]);

  const cancelHighlightAll = useCallback(() => {
    setConfirmOpen(false);
  }, []);

  if (error) {
    return (
      <p className="p-3 text-sm" style={{ color: "var(--md-accent-red)" }}>
        {error}
      </p>
    );
  }

  const showEmptyState = filteredRows.length === 0 && !fetching;

  return (
    <div className="h-full flex flex-col text-xs">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-[var(--md-border)] flex-wrap">
        <select
          value={encoding}
          onChange={(e) => {
            setEncoding(e.target.value as "ascii" | "utf-8");
            resetAndFetch(dumpPath);
          }}
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
            onChange={(e) => {
              setMinLength(Math.max(1, parseInt(e.target.value) || 4));
            }}
            onBlur={() => resetAndFetch(dumpPath)}
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

        <button
          onClick={handleToggleHighlightAll}
          disabled={!highlightActive || filteredRows.length === 0}
          className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
          title={
            highlightAllWarn
              ? "Restrict highlights to viewport"
              : `Highlight all ${filteredRows.length} matches`
          }
        >
          {highlightAllWarn ? "Viewport only" : `Highlight all ${filteredRows.length}`}
        </button>

        <span className="md-text-muted whitespace-nowrap">
          {typeof totalCount === "string" ? totalCount : filteredRows.length} strings
          {truncated && " (truncated)"}
          {fetching && (
            <span className="ml-2 animate-pulse" aria-label="loading">
              loading...
            </span>
          )}
          {done && rows.length > 0 && (
            <span className="ml-2 md-text-muted" aria-label="done">
              (done)
            </span>
          )}
        </span>
      </div>

      {/* Confirmation dialog for "Highlight all" above threshold */}
      {confirmOpen && (
        <div className="absolute inset-0 z-10 flex items-center justify-center bg-black/40">
          <div className="max-w-md p-4 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)] text-xs space-y-3">
            <p>
              Highlighting all {filteredRows.length} matches may slow the hex viewer.
              Continue?
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={cancelHighlightAll}
                className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={confirmHighlightAll}
                className="px-2 py-1 rounded border border-[var(--md-accent-blue)] bg-[var(--md-accent-blue)] text-white hover:opacity-90 transition-opacity"
              >
                Highlight all
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header row */}
      <div
        className="grid px-2 py-1 md-text-muted border-b border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[11px]"
        style={{ gridTemplateColumns: "10ch 1fr 6ch 4ch" }}
      >
        <span>Offset</span>
        <span>Value</span>
        <span>Len</span>
        <span>Enc</span>
      </div>

      {/* Virtualized body */}
      {showEmptyState ? (
        <p className="p-3 text-center md-text-muted">
          {rows.length === 0 ? "No strings found." : "No strings match filter."}
        </p>
      ) : (
        <div ref={parentRef} className="flex-1 overflow-auto">
          <div
            style={{
              height: `${rowVirtualizer.getTotalSize()}px`,
              width: "100%",
              position: "relative",
            }}
          >
            {virtualItems.map((virtualRow) => {
              const row = filteredRows[virtualRow.index];
              if (!row) return null;
              return (
                <div
                  key={virtualRow.key}
                  data-testid="strings-row"
                  data-index={virtualRow.index}
                  onClick={() => handleRowClick(row.offset)}
                  className="absolute left-0 top-0 w-full grid cursor-pointer hover:bg-[var(--md-bg-hover)] transition-colors border-t border-[var(--md-border)] text-[11px] items-center px-2"
                  style={{
                    height: `${virtualRow.size}px`,
                    transform: `translateY(${virtualRow.start}px)`,
                    gridTemplateColumns: "10ch 1fr 6ch 4ch",
                  }}
                >
                  <span className="font-mono whitespace-nowrap">
                    {hexOffset(row.offset)}
                  </span>
                  <span
                    className="truncate pr-2"
                    title={row.value}
                  >
                    {truncateValue(row.value)}
                  </span>
                  <span className="md-text-muted">{row.length}</span>
                  <span className="md-text-muted">{row.encoding}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
