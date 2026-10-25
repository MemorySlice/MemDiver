import { useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useVirtualizer } from "@tanstack/react-virtual";

import type { ProcessRow } from "@/api/image";
import { filterAndSort, type ProcessSortKey } from "./process-sort";

const ROW_HEIGHT = 24;

const GRID = "grid grid-cols-[3rem_3rem_1fr_3rem_auto] gap-1 items-center px-1";

/** Virtualized pslist table with filter box, pid/name sorting and row actions. */
export function ProcessTable({ rows, onOpen, onExtract, busy, selectedPid = null, onSelect }: {
  rows: readonly ProcessRow[];
  onOpen: (row: ProcessRow) => void;
  onExtract: (row: ProcessRow) => void;
  busy: boolean;
  /** The pid selected across panels (D14), marked in the table. */
  selectedPid?: number | null;
  onSelect?: (row: ProcessRow) => void;
}) {
  const { t } = useTranslation("image");
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<ProcessSortKey>("pid");
  const [desc, setDesc] = useState(false);
  const shown = useMemo(
    () => filterAndSort(rows, filter, sortKey, desc), [rows, filter, sortKey, desc]);
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: shown.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 8,
  });

  const sortBy = (key: ProcessSortKey) => {
    if (key === sortKey) setDesc(!desc);
    else { setSortKey(key); setDesc(false); }
  };
  const arrow = (key: ProcessSortKey) => (key === sortKey ? (desc ? " ▾" : " ▴") : "");

  return (
    <div data-testid="process-table" className="space-y-1">
      <input type="text" value={filter} onChange={(e) => setFilter(e.target.value)}
        aria-label={t("processes.filter")} placeholder={t("processes.filter")}
        className="w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]" />
      <div className="text-xs md-text-muted">
        {t("processes.count", { shown: shown.length, total: rows.length })}
      </div>
      <div className={`${GRID} text-xs font-medium md-text-secondary`}>
        <button onClick={() => sortBy("pid")} data-testid="sort-pid" className="text-left">
          {t("processes.col.pid")}{arrow("pid")}</button>
        <span>{t("processes.col.ppid")}</span>
        <button onClick={() => sortBy("comm")} data-testid="sort-comm" className="text-left">
          {t("processes.col.comm")}{arrow("comm")}</button>
        <span>{t("processes.col.uid")}</span>
        <span>{t("processes.col.actions")}</span>
      </div>
      <div ref={scrollRef} className="overflow-auto max-h-64" data-testid="process-scroll">
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map((item) => {
            const row = shown[item.index];
            return (
              <div key={row.pid} data-testid="process-row"
                className={`${GRID} text-xs font-mono absolute left-0 w-full ${selectedPid === row.pid ? "bg-[var(--md-bg-selected)]" : "hover:bg-[var(--md-bg-hover)]"}`}
                style={{ top: item.start, height: ROW_HEIGHT }}>
                {onSelect ? (
                  <button type="button" onClick={() => onSelect(row)} data-testid="process-select"
                    aria-pressed={selectedPid === row.pid} title={t("processes.select")}
                    aria-label={`${t("processes.select")} ${row.pid}`}
                    className={`text-left ${selectedPid === row.pid ? "font-bold underline" : ""}`}>
                    {selectedPid === row.pid ? "● " : ""}{row.pid}</button>
                ) : <span>{row.pid}</span>}
                <span>{row.ppid}</span>
                <span className="truncate" title={row.comm}>{row.comm}</span>
                <span>{row.uid ?? ""}</span>
                <span className="flex gap-1 font-sans">
                  <button disabled={busy} onClick={() => onOpen(row)}
                    title={t("processes.openProcess")} aria-label={`${t("processes.openProcess")} ${row.pid}`}
                    className="underline md-text-accent disabled:opacity-40">
                    {t("processes.openProcess")}</button>
                  <button disabled={busy} onClick={() => onExtract(row)}
                    aria-label={`${t("processes.extract")} ${row.pid}`}
                    className="underline md-text-accent disabled:opacity-40">
                    {t("processes.extract")}</button>
                </span>
              </div>
            );
          })}
        </div>
      </div>
      {shown.length === 0 && <p className="text-xs md-text-muted">{t("processes.empty")}</p>}
    </div>
  );
}
