import { useRef } from "react";
import { useTranslation } from "react-i18next";
import { useVirtualizer } from "@tanstack/react-virtual";

import type { Vol3Column, Vol3RunResult } from "@/api/vol3";
import { formatAddress } from "./vol3-address";
import { SPACE_CHOICES, type ColumnOverrides } from "./vol3-columns";
import { matchRow, type HighlightRule } from "./highlight-rules";
import { RULE_MARKERS } from "./rule-markers";

const NO_RULES: readonly HighlightRule[] = [];

const ROW_HEIGHT = 24;
const COL_WIDTH = 150;
const INDENT_PX = 12;

function Cell({ column, value, reason }: {
  column: Vol3Column; value: unknown; reason: string | undefined;
}) {
  const { t } = useTranslation("vol3");
  if (value === null || value === undefined) {
    // An absent cell is NOT zero and NOT empty: the reason is the information.
    const why = reason ?? t("table.absentUnknown");
    return (
      <span data-testid="absent-cell" title={why} className="italic md-text-muted">
        {"∅ "}{why}
      </span>
    );
  }
  if (column.space || column.type === "hex") {
    const address = formatAddress(value);
    if (address) {
      return (
        <span className="flex items-center gap-1" data-testid="address-cell">
          <span title={address.approximate ? t("table.approximate") : undefined}>
            {address.approximate ? "≈" : ""}{address.text}
          </span>
          {column.space && (
            <span data-testid="space-badge"
              className="px-1 rounded border border-[var(--md-border)] text-[10px] md-text-secondary font-sans">
              {t(`table.spaceBadge.${column.space}`, { defaultValue: column.space })}
            </span>
          )}
          {column.space && column.object_type && (
            <span data-testid="object-type-badge"
              title={column.object_size ? t("table.objectSize", { count: column.object_size }) : undefined}
              className="px-1 rounded border border-[var(--md-border)] text-[10px] md-text-secondary font-sans">
              {column.object_type}
            </span>
          )}
        </span>
      );
    }
  }
  return <span title={String(value)} className="truncate">{String(value)}</span>;
}

function SpaceSelect({ column, override, onChange }: {
  column: Vol3Column;
  override: string | null | undefined;
  onChange: (space: string | null | undefined) => void;
}) {
  const { t } = useTranslation("vol3");
  const current = override === undefined ? (column.space ?? "auto") : (override ?? "none");
  const decode = (v: string) => (v === "auto" ? undefined : v === "none" ? null : v);
  return (
    <select value={current} onChange={(e) => onChange(decode(e.target.value))}
      aria-label={t("table.highlightAs", { column: column.name })} data-testid={`space-select-${column.name}`}
      className="w-full text-[10px] rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] font-normal">
      <option value="auto">{t("table.space.auto")}</option>
      {SPACE_CHOICES.map((s) => <option key={s} value={s}>{t(`table.space.${s}`)}</option>)}
      <option value="none">{t("table.space.none")}</option>
    </select>
  );
}

/** Virtualized plugin result grid: tree indent by depth, absent markers, space selectors. */
export function ResultsTable({
  result, overrides, onOverride, onRowClick, rules = NO_RULES, indices,
}: {
  result: Vol3RunResult;
  /** Highlight rules in force; the most severe one holding on a row styles it. */
  rules?: readonly HighlightRule[];
  /** Original row numbers to show (a filter); `onRowClick` still gets ORIGINAL numbers. */
  indices?: readonly number[];
  overrides: ColumnOverrides;
  onOverride: (column: string, space: string | null | undefined) => void;
  onRowClick: (row: number) => void;
}) {
  const { t } = useTranslation("vol3");
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: indices ? indices.length : result.rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 8,
  });
  const width = result.columns.length * COL_WIDTH;
  const cols = { gridTemplateColumns: `repeat(${result.columns.length}, ${COL_WIDTH}px)`, width };

  return (
    <div ref={scrollRef} className="overflow-auto max-h-96 border border-[var(--md-border)] rounded"
      data-testid="vol3-results-scroll">
      <div className="sticky top-0 z-10 bg-[var(--md-bg-secondary)] grid gap-1 px-1 py-1 text-xs font-medium"
        style={cols} data-testid="vol3-header">
        {result.columns.map((column) => (
          <div key={column.name} className="space-y-0.5 min-w-0">
            <div className="truncate md-text-secondary" title={column.name}>{column.name}</div>
            <SpaceSelect column={column} override={overrides[column.name]}
              onChange={(space) => onOverride(column.name, space)} />
          </div>
        ))}
      </div>
      <div style={{ height: virtualizer.getTotalSize(), position: "relative", width }}>
        {virtualizer.getVirtualItems().map((item) => {
          const original = indices ? indices[item.index] : item.index;
          const row = result.rows[original];
          const hit = matchRow(rules, result.plugin, result.columns, row);
          const marker = hit ? RULE_MARKERS[hit.style] : null;
          return (
            <div key={original} data-testid="vol3-row" role="button" tabIndex={0}
              aria-label={t("table.rowLabel", { n: original + 1 })}
              data-rule-style={hit?.style} data-rule-id={hit?.rule.id}
              onClick={() => onRowClick(original)}
              onKeyDown={(e) => { if (e.key === "Enter") onRowClick(original); }}
              className="grid gap-1 px-1 items-center text-xs font-mono absolute left-0 cursor-pointer hover:bg-[var(--md-bg-hover)]"
              style={{
                ...cols, top: item.start, height: ROW_HEIGHT,
                ...(marker ? { boxShadow: `inset 3px 0 0 var(${marker.token})` } : {}),
              }}>
              {result.columns.map((column, c) => {
                const flagged = hit && marker && hit.columns.some((n) => n.trim().toLowerCase() === column.name.trim().toLowerCase());
                return (
                  <div key={column.name} className="min-w-0 truncate"
                    data-rule-cell={flagged ? hit.style : undefined}
                    style={{
                      ...(c === 0 ? { paddingLeft: row.depth * INDENT_PX } : {}),
                      ...(flagged ? { background: `color-mix(in srgb, var(${marker.token}) 18%, transparent)` } : {}),
                    }}>
                    {flagged && (
                      <span aria-label={t(`rules.style.${hit.style}`)} title={t(`rules.style.${hit.style}`)}
                        data-testid="rule-marker" style={{ color: `var(${marker.token})` }}>{marker.glyph}{" "}</span>
                    )}
                    <Cell column={column} value={row.values[c]} reason={row.absent[column.name]} />
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>
      {(indices ? indices.length : result.rows.length) === 0 && <p className="p-2 text-xs md-text-muted">{t("table.empty")}</p>}
    </div>
  );
}
