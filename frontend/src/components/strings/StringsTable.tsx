import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useVirtualizer } from "@tanstack/react-virtual";
import { wireIntHex, type WireInt } from "@/api/lossless-json";
import {
  cancelStringsJob, getStringsJobPayload, getStringsTable, isJobTicket, STRINGS_SYNC_MAX_BYTES,
  type StringsTable as Table, type StringsTableRow,
} from "@/api/strings";
import { readableFailure } from "@/api/client";
import { useTaskProgress } from "@/hooks/useTaskProgress";
import { useHexStore } from "@/stores/hex-store";
import {
  gotoOffset, highlightParts, searchRows, viewForHex,
} from "./strings-table-utils";

const ROW_HEIGHT = 24;
const OVERSCAN = 10;
const COLUMNS = "14ch 8ch 1fr 22ch";

const hexAddr = (addr: WireInt) => `0x${wireIntHex(addr, 8).slice(2).toUpperCase()}`;

interface Props {
  dumpPath: string;
}

/** Strings as a table: address + encoding + value + IOC badges; click a row to go to it. */
export function StringsTable({ dumpPath }: Props) {
  const { t } = useTranslation("misc");
  const viewMode = useHexStore((s) => s.viewMode);
  const availableViews = useHexStore((s) => s.availableViews);
  const fileSize = useHexStore((s) => s.fileSize);
  const vasSize = useHexStore((s) => s.vasSize);
  const view = viewForHex(viewMode, availableViews);
  const [table, setTable] = useState<Table | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ pct: number | null; msg: string | null }>({ pct: null, msg: null });
  const [query, setQuery] = useState("");
  const [onlyIocs, setOnlyIocs] = useState(false);
  const [hint, setHint] = useState<string | null>(null);
  // Bumped on every (dump, view) change and every new scan: a late answer of an older one is dropped.
  const requestId = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const taskRef = useRef<string | null>(null);

  // The server turns a scan over 64 MiB into a JOB, and a request cannot refuse that, so a
  // large dump is only scanned when the user asks for it.
  const scannedBytes = view === "raw" ? fileSize : (vasSize || fileSize);
  const needsExplicitScan = scannedBytes > STRINGS_SYNC_MAX_BYTES;

  const stopJob = useCallback(() => {
    const running = taskRef.current;
    taskRef.current = null;
    setTaskId(null);
    if (running) void cancelStringsJob(running).catch(() => undefined);
  }, []);

  const scan = useCallback(() => {
    requestId.current += 1;
    const mine = requestId.current;
    controller.current?.abort();
    stopJob();
    const abort = new AbortController();
    controller.current = abort;
    setTable(null);
    setError(null);
    setLoading(true);
    getStringsTable({ dump_path: dumpPath, view }, abort.signal)
      .then((res) => {
        if (mine !== requestId.current) return;
        if (isJobTicket(res)) {
          taskRef.current = res.task_id;
          setProgress({ pct: null, msg: null });
          setTaskId(res.task_id);
          return;
        }
        setTable(res);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (mine !== requestId.current) return;
        setError(readableFailure(e));
        setLoading(false);
      });
  }, [dumpPath, view, stopJob]);

  useEffect(() => {
    if (needsExplicitScan) {
      requestId.current += 1;
      controller.current?.abort();
      stopJob();
      setTable(null);
      setError(null);
      setLoading(false);
    } else {
      scan();
    }
    return () => { controller.current?.abort(); };
  }, [scan, needsExplicitScan, stopJob]);

  // Leaving the tab must not leave a job nobody follows.
  useEffect(() => stopJob, [stopJob]);

  useTaskProgress(taskId, {
    onProgress: (pct, msg) => { if (taskRef.current === taskId) setProgress({ pct, msg }); },
    onDone: () => {
      const mine = requestId.current;
      void getStringsJobPayload(taskId ?? "")
        .then((payload) => {
          if (mine !== requestId.current || taskRef.current !== taskId) return;
          taskRef.current = null;
          setTaskId(null);
          setLoading(false);
          if (payload) setTable(payload); else setError(t("strings.table.noPayload"));
        })
        .catch((e: unknown) => {
          if (mine !== requestId.current) return;
          setError(readableFailure(e));
          setLoading(false);
        });
    },
    onError: (message) => {
      if (taskRef.current !== taskId) return;
      taskRef.current = null;
      setTaskId(null);
      setLoading(false);
      setError(message);
    },
  });

  const cancel = useCallback(() => {
    requestId.current += 1;
    stopJob();
    setLoading(false);
  }, [stopJob]);

  const rows = useMemo(() => {
    const kept = onlyIocs ? (table?.rows ?? []).filter((r) => r.iocs.length > 0) : (table?.rows ?? []);
    return searchRows(kept, query);
  }, [table, query, onlyIocs]);

  const parentRef = useRef<HTMLDivElement | null>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: OVERSCAN,
  });

  const goto = useCallback((row: StringsTableRow) => {
    if (!table) return;
    const hex = useHexStore.getState();
    const result = gotoOffset(row, table.view, hex.viewMode, hex.vaSpanStart);
    setHint(result.ok ? null : result.hint);
    if (!result.ok) return;
    if (result.view && result.view !== hex.viewMode) hex.showView(result.view);
    hex.scrollToOffset(result.offset);
  }, [table]);

  if (error) {
    return <p role="alert" className="p-3 text-sm" style={{ color: "var(--md-accent-red)" }}>{error}</p>;
  }
  if (needsExplicitScan && !table && !loading) {
    return (
      <div className="p-3 text-sm space-y-2" data-testid="strings-table-scan-gate">
        <p role="status" className="md-text-muted">{t("strings.table.tooLarge")}</p>
        <button type="button" onClick={scan} data-testid="strings-table-scan"
          className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
          {t("strings.table.scan")}
        </button>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col text-xs" data-testid="strings-table">
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-[var(--md-border)] flex-wrap">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label={t("strings.table.searchLabel")}
          placeholder={t("strings.table.searchPlaceholder")}
          className="flex-1 min-w-[120px] px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-xs"
        />
        <label className="flex items-center gap-1 cursor-pointer md-text-secondary whitespace-nowrap">
          <input
            type="checkbox"
            checked={onlyIocs}
            onChange={(e) => setOnlyIocs(e.target.checked)}
            className="accent-[var(--md-accent-blue)]"
          />
          {t("strings.table.onlyIocs")}
        </label>
        <span className="md-text-muted whitespace-nowrap" role="status">
          {loading ? (progress.msg ?? t("strings.loading")) : t("strings.table.count", { shown: rows.length, total: table?.row_count ?? 0 })}
          {loading && taskId && progress.pct !== null && ` ${Math.round(progress.pct * 100)}%`}
          {table?.truncated && t("strings.table.truncated", { limit: table.limit })}
        </span>
        {taskId && (
          <button type="button" onClick={cancel} data-testid="strings-table-cancel"
            className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
            {t("strings.table.cancel")}
          </button>
        )}
      </div>
      {hint && <p role="status" className="px-2 py-1 md-text-warning">{t(hint)}</p>}
      <div
        className="grid px-2 py-1 md-text-muted border-b border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[11px]"
        style={{ gridTemplateColumns: COLUMNS }}
      >
        <span>{t("strings.table.colAddr")}</span>
        <span>{t("strings.colEnc")}</span>
        <span>{t("strings.colValue")}</span>
        <span>{t("strings.table.colIocs")}</span>
      </div>
      {rows.length === 0 && !loading ? (
        <p className="p-3 text-center md-text-muted">
          {table && table.rows.length > 0 ? t("strings.noStringsMatch") : t("strings.noStringsFound")}
        </p>
      ) : (
        <div ref={parentRef} className="flex-1 overflow-auto">
          <div style={{ height: `${virtualizer.getTotalSize()}px`, width: "100%", position: "relative" }}>
            {virtualizer.getVirtualItems().map((item) => {
              const row = rows[item.index];
              if (!row) return null;
              return (
                <div
                  key={item.key}
                  data-testid="strings-table-row"
                  role="button"
                  tabIndex={0}
                  title={row.region?.path ?? row.space}
                  onClick={() => goto(row)}
                  onKeyDown={(e) => { if (e.key === "Enter") goto(row); }}
                  className="absolute left-0 top-0 w-full grid cursor-pointer hover:bg-[var(--md-bg-hover)] border-t border-[var(--md-border)] text-[11px] items-center px-2"
                  style={{ height: `${item.size}px`, transform: `translateY(${item.start}px)`, gridTemplateColumns: COLUMNS }}
                >
                  <span className="font-mono whitespace-nowrap">{hexAddr(row.addr)}</span>
                  <span className="md-text-muted">{row.encoding}</span>
                  <span className="truncate pr-2" title={row.value}>
                    {highlightParts(row.value.slice(0, 200), query).map((p, i) => (
                      <Fragment key={i}>
                        {p.match ? <mark data-testid="strings-hit" className="bg-[var(--md-bg-selected)] text-inherit">{p.text}</mark> : p.text}
                      </Fragment>
                    ))}
                  </span>
                  <span className="flex gap-1 overflow-hidden">
                    {row.iocs.map((kind) => (
                      <span
                        key={kind}
                        data-testid="ioc-badge"
                        className="px-1 rounded border border-[var(--md-accent-cyan)] text-[var(--md-accent-cyan)] whitespace-nowrap"
                      >
                        {t(`strings.table.ioc.${kind}`, { defaultValue: kind })}
                      </span>
                    ))}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
