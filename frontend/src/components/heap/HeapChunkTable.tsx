/**
 * The paged, filtered, virtualized chunk table of the heap panel.
 *
 * Pages are requested in the hex viewer's CURRENT view so every row's
 * `view_offset` is directly a hex offset: a row click selects the chunk (for
 * the inspector) and scrolls the hex viewer there.
 */

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useShallow } from "zustand/react/shallow";
import { useVirtualizer } from "@tanstack/react-virtual";

import { HEAP_CHUNK_STATES } from "@/api/heap";
import type { HeapChunk, HeapChunkState } from "@/api/types";
import {
  HEAP_DEFAULT_PAGE_SIZE,
  chunkPageKey,
  selectHeapDump,
  useHeapStore,
} from "@/stores/heap-store";
import { useHexStore } from "@/stores/hex-store";
import { confidencePercent, formatAddress } from "./heap-format";
import { jumpHexToViewOffset } from "./heap-navigation";

const ROW_HEIGHT = 22;
const GRID = "grid grid-cols-[9rem_6rem_5rem_7rem_minmax(4rem,1fr)_4rem] gap-2 px-2";

interface Props {
  dumpPath: string;
}

export function HeapChunkTable({ dumpPath }: Props) {
  const { t } = useTranslation("heap");
  const view = useHexStore((s) => s.viewMode);
  const { filters, chunkPages, chunksStatus, chunksError, selectedVa } = useHeapStore(
    useShallow((s) => {
      const e = selectHeapDump(dumpPath)(s);
      return {
        filters: e.filters,
        chunkPages: e.chunkPages,
        chunksStatus: e.chunksStatus,
        chunksError: e.chunksError,
        selectedVa: e.selectedChunk?.va ?? null,
      };
    }),
  );

  // A new filter set or view starts again at the first page.
  const [page, setPage] = useState(0);
  const queryKey = chunkPageKey(filters, view, 0, HEAP_DEFAULT_PAGE_SIZE);
  const [prevQueryKey, setPrevQueryKey] = useState(queryKey);
  if (prevQueryKey !== queryKey) {
    setPrevQueryKey(queryKey);
    setPage(0);
  }

  const pageKey = chunkPageKey(filters, view, page, HEAP_DEFAULT_PAGE_SIZE);
  const response = chunkPages[pageKey];
  const needsFetch = Boolean(dumpPath) && !response && chunksStatus !== "loading";
  const reset = chunksStatus === "idle";
  // A page/filter/view change that lands while ANOTHER page is in flight is
  // skipped below; re-running when that load settles fetches the page now on
  // screen (e.g. heap mode moving an .msl from its raw to its vas view while
  // the raw page loads).
  const inFlight = chunksStatus === "loading";
  const requestedKey = useRef<string | null>(null);
  useEffect(() => {
    // Re-runs on a new page/filter/view, when the store reset this dump
    // (allocator change), or when an earlier load settles. A failed page
    // waits for the retry button instead of refetching itself in a loop.
    if (!needsFetch) return;
    const status = selectHeapDump(dumpPath)(useHeapStore.getState()).chunksStatus;
    if (status === "loading") return;
    if (status === "error" && requestedKey.current === pageKey) return;
    requestedKey.current = pageKey;
    void useHeapStore.getState().loadChunkPage(dumpPath, { page, view, pageSize: HEAP_DEFAULT_PAGE_SIZE });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- needsFetch is deliberately read, not a trigger
  }, [dumpPath, pageKey, page, view, reset, inFlight]);

  const chunks = response?.chunks ?? [];
  const pages = Math.max(1, response?.pages ?? 1);

  const onSelect = (chunk: HeapChunk) => {
    useHeapStore.getState().selectChunk(dumpPath, chunk);
    jumpHexToViewOffset(chunk.view_offset);
  };

  return (
    <div className="h-full flex flex-col text-xs min-h-0" data-testid="heap-chunk-table">
      <ChunkFilters dumpPath={dumpPath} />
      {chunksError && !response && (
        <div role="alert" className="mx-2 my-1 p-2 rounded md-bg-error-subtle md-text-error flex gap-2">
          <span className="flex-1">{chunksError}</span>
          <button
            type="button"
            className="px-1.5 rounded border border-[var(--md-border)]"
            onClick={() =>
              void useHeapStore.getState().loadChunkPage(dumpPath, { page, view, pageSize: HEAP_DEFAULT_PAGE_SIZE })
            }
          >
            {t("overview.retry")}
          </button>
        </div>
      )}
      <div className={`${GRID} py-1 border-b border-[var(--md-border)] md-text-muted`} role="row">
        <span role="columnheader">{t("chunks.columns.va")}</span>
        <span role="columnheader">{t("chunks.columns.offset")}</span>
        <span role="columnheader" className="text-right">{t("chunks.columns.size")}</span>
        <span role="columnheader">{t("chunks.columns.state")}</span>
        <span role="columnheader">{t("chunks.columns.bin")}</span>
        <span role="columnheader" className="text-right">{t("chunks.columns.confidence")}</span>
      </div>
      {chunksStatus === "loading" && !response ? (
        <p role="status" className="p-2 md-text-muted">{t("chunks.loading")}</p>
      ) : response && chunks.length === 0 ? (
        <p className="p-2 md-text-muted">{t("chunks.empty")}</p>
      ) : (
        <ChunkRows chunks={chunks} selectedVa={selectedVa} onSelect={onSelect} />
      )}
      <div className="flex items-center gap-2 px-2 py-1 border-t border-[var(--md-border)]">
        <button
          type="button"
          disabled={page <= 0}
          onClick={() => setPage((p) => Math.max(0, p - 1))}
          aria-label={t("chunks.previousPage")}
          className="px-1.5 rounded border border-[var(--md-border)] disabled:opacity-50"
        >
          ‹
        </button>
        <span data-testid="heap-chunk-page">{t("chunks.pageOf", { page: page + 1, pages })}</span>
        <button
          type="button"
          disabled={page + 1 >= pages}
          onClick={() => setPage((p) => p + 1)}
          aria-label={t("chunks.nextPage")}
          className="px-1.5 rounded border border-[var(--md-border)] disabled:opacity-50"
        >
          ›
        </button>
        {response && (
          <span className="ml-auto md-text-muted">{t("chunks.total", { count: response.total })}</span>
        )}
      </div>
    </div>
  );
}

interface RowsProps {
  chunks: HeapChunk[];
  selectedVa: number | null;
  onSelect: (chunk: HeapChunk) => void;
}

function ChunkRows({ chunks, selectedVa, onSelect }: RowsProps) {
  const { t } = useTranslation("heap");
  const parentRef = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Virtual; rows read it fresh each render
  const virtualizer = useVirtualizer({
    count: chunks.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 10,
  });

  return (
    <div ref={parentRef} className="flex-1 overflow-auto min-h-0" role="rowgroup">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((item) => {
          const chunk = chunks[item.index];
          const selected = chunk.va === selectedVa;
          return (
            <button
              key={item.key}
              type="button"
              role="row"
              data-testid="heap-chunk-row"
              data-va={chunk.va}
              aria-selected={selected}
              title={t("chunks.jumpTo")}
              onClick={() => onSelect(chunk)}
              className={`${GRID} absolute left-0 w-full text-left items-center font-mono hover:bg-[var(--md-bg-hover)] ${
                selected ? "md-selected-surface" : ""
              }`}
              style={{ top: item.start, height: ROW_HEIGHT }}
            >
              <span>{formatAddress(chunk.va)}</span>
              <span>{formatAddress(chunk.view_offset)}</span>
              <span className="text-right">{chunk.size.toLocaleString()}</span>
              <span className="font-sans truncate" title={t(`states.${chunk.state}`)} data-heap-state={chunk.state}>
                {t(`states.${chunk.state}`)}
              </span>
              <span className="truncate">{chunk.bin ?? ""}</span>
              <span className="text-right">{confidencePercent(chunk.confidence)}%</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function parseSize(text: string): number | null {
  const v = text.trim();
  if (!v) return null;
  const n = /^0x/i.test(v) ? parseInt(v, 16) : parseInt(v, 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function ChunkFilters({ dumpPath }: { dumpPath: string }) {
  const { t } = useTranslation("heap");
  const filters = useHeapStore((s) => selectHeapDump(dumpPath)(s).filters);
  const [minDraft, setMinDraft] = useState(filters.minSize?.toString() ?? "");
  const [maxDraft, setMaxDraft] = useState(filters.maxSize?.toString() ?? "");

  // A reset (or another panel) replacing the filters refreshes the drafts.
  const [prevFilters, setPrevFilters] = useState(filters);
  if (prevFilters !== filters) {
    setPrevFilters(filters);
    setMinDraft(filters.minSize?.toString() ?? "");
    setMaxDraft(filters.maxSize?.toString() ?? "");
  }

  const apply = () =>
    useHeapStore.getState().setFilters(dumpPath, {
      minSize: parseSize(minDraft),
      maxSize: parseSize(maxDraft),
    });

  const input = "w-20 px-1 py-0.5 rounded border border-[var(--md-border)] bg-transparent";
  return (
    <form
      className="flex flex-wrap items-center gap-2 px-2 py-1 border-b border-[var(--md-border)]"
      aria-label={t("filters.title")}
      onSubmit={(e) => {
        e.preventDefault();
        apply();
      }}
    >
      <label className="flex items-center gap-1">
        <span className="md-text-muted">{t("filters.state")}</span>
        <select
          value={filters.state ?? ""}
          data-testid="heap-filter-state"
          onChange={(e) =>
            useHeapStore.getState().setFilters(dumpPath, {
              state: (e.target.value || null) as HeapChunkState | null,
            })
          }
          className="px-1 py-0.5 rounded border border-[var(--md-border)] bg-transparent"
        >
          <option value="">{t("filters.allStates")}</option>
          {HEAP_CHUNK_STATES.map((s) => (
            <option key={s} value={s}>{t(`states.${s}`)}</option>
          ))}
        </select>
      </label>
      <label className="flex items-center gap-1">
        <span className="md-text-muted">{t("filters.minSize")}</span>
        <input className={input} value={minDraft} inputMode="numeric" data-testid="heap-filter-min" onChange={(e) => setMinDraft(e.target.value)} />
      </label>
      <label className="flex items-center gap-1">
        <span className="md-text-muted">{t("filters.maxSize")}</span>
        <input className={input} value={maxDraft} inputMode="numeric" data-testid="heap-filter-max" onChange={(e) => setMaxDraft(e.target.value)} />
      </label>
      <button type="submit" className="px-1.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
        {t("filters.apply")}
      </button>
      <button
        type="button"
        onClick={() => useHeapStore.getState().resetFilters(dumpPath)}
        className="px-1.5 rounded md-text-secondary hover:bg-[var(--md-bg-hover)]"
      >
        {t("filters.reset")}
      </button>
    </form>
  );
}
