import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  ISF_SECTIONS, setIsfDraft, type DraftRef, type IsfField, type IsfOrigin, type IsfSection, type IsfStruct,
} from "@/api/isf";
import { formatType, summarize, type EntryRef } from "./isf-format";
import type { EditFocus, OpKind } from "./OpForms";
import { ProvenanceBadge, ProvenanceDetail } from "./ProvenanceBadge";
import { PAGE_SIZE, sectionTag, useDraftData } from "./useDraftData";
import { buttonClass, errorStyle, iconButtonClass, inputClass } from "./ui";

interface Props {
  draftRef: DraftRef;
  draft: string;
  rev: number;
  section: IsfSection;
  query: string;
  selected: EntryRef | null;
  onSection: (s: IsfSection) => void;
  onQuery: (q: string) => void;
  onEdit: (focus: EditFocus) => void;
  onChanged: () => void;
}

const SEARCH_DEBOUNCE_MS = 300;

const EDIT_OP: Record<IsfSection, OpKind | null> =
  { symbols: "symbol", user_types: "struct", base_types: "base_type", enums: null };

/** Server-searched, offset-paged view of one draft section (one page rendered at a time). */
export function DraftTree(p: Props) {
  const { t } = useTranslation("isf");
  const [pageState, setPageState] = useState({ scope: "", offset: 0 });
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [typed, setTyped] = useState(p.query);
  // A page belongs to one section and one search; changing either returns to page one.
  const scope = `${p.section}\u0000${p.query}`;
  const offset = pageState.scope === scope ? pageState.offset : 0;
  const data = useDraftData(p.draftRef, p.draft, p.rev, p.section, offset, p.query);
  const setOffset = (next: number) => setPageState({ scope, offset: Math.max(0, next) });
  const { total } = data;
  const from = total === 0 ? 0 : data.offset + 1;
  const to = data.offset + data.rows.length;

  // The search box is applied once typing rests; an external query (an implicated chip) shows at once.
  const [seenQuery, setSeenQuery] = useState(p.query);
  if (seenQuery !== p.query) { setSeenQuery(p.query); setTyped(p.query); }
  useEffect(() => {
    if (typed === p.query) return;
    const timer = setTimeout(() => p.onQuery(typed), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [typed, p]);

  const remove = async (key: string[]) => {
    setActionError(null);
    try {
      await setIsfDraft(p.draftRef, p.draft, { op: "remove", args: { key },
        provenance: { source: "manual", tier: "manual", evidence: [], author: "human" } });
      setConfirm(null);
      p.onChanged();
    } catch (e) { setActionError(readableFailure(e)); }
  };
  const toggle = (name: string) => setExpanded((s) => {
    const next = new Set(s);
    if (next.has(name)) next.delete(name); else next.add(name);
    return next;
  });
  const removeButton = (keyParts: string[], id: string) => (
    confirm === id ? (
      <span className="inline-flex gap-1 shrink-0">
        <button type="button" className={buttonClass} data-testid="isf-remove-confirm"
          onClick={() => void remove(keyParts)}>{t("tree.removeConfirm")}</button>
        <button type="button" className={buttonClass} onClick={() => setConfirm(null)}>{t("tree.cancel")}</button>
      </span>
    ) : (
      <button type="button" className={iconButtonClass} data-testid="isf-remove"
        aria-label={t("tree.remove")} title={t("tree.remove")} onClick={() => setConfirm(id)}>{"\u2715"}</button>
    )
  );

  return (
    <section className="space-y-1" data-testid="isf-tree">
      <div role="tablist" className="flex flex-wrap gap-1" aria-label={t("tree.sections")}>
        {ISF_SECTIONS.map((s) => (
          <button key={s} type="button" role="tab" aria-selected={p.section === s} data-testid={`isf-section-${s}`}
            onClick={() => p.onSection(s)}
            className={`${buttonClass} ${p.section === s ? "bg-[var(--md-bg-hover)] md-text-accent" : ""}`}>
            {t(`tree.section.${s}`, { count: data.counts?.[s] ?? 0 })}
          </button>
        ))}
      </div>
      <input type="search" value={typed} className={inputClass} data-testid="isf-search"
        aria-label={t("tree.search")} placeholder={t("tree.searchPlaceholder")}
        onChange={(e) => setTyped(e.target.value)} />
      {data.loading && <p role="status" className="md-text-muted">{t("tree.loading")}</p>}
      {(data.error || actionError) && <p role="alert" data-testid="isf-tree-error" style={errorStyle}>{data.error ?? actionError}</p>}
      <div className="flex items-center gap-1" data-testid="isf-tree-pager">
        <span className="md-text-muted" data-testid="isf-tree-count">
          {total === 0 ? t("tree.none") : t("tree.range", { from, to, total })}</span>
        <button type="button" className={buttonClass} data-testid="isf-page-prev" disabled={data.offset === 0}
          onClick={() => setOffset(data.offset - PAGE_SIZE)}>{t("tree.prev")}</button>
        <button type="button" className={buttonClass} data-testid="isf-page-next" disabled={to >= total}
          onClick={() => setOffset(data.offset + PAGE_SIZE)}>{t("tree.next")}</button>
      </div>
      <ul className="space-y-0.5" data-testid="isf-tree-rows">
        {data.rows.map((row) => {
          const key = [sectionTag(p.section), row.name];
          const isSel = p.selected?.section === p.section && p.selected.name === row.name;
          const open = expanded.has(row.name) || (isSel && p.selected?.field !== undefined);
          const fields = p.section === "user_types" ? Object.entries((row.item as IsfStruct).fields ?? {}) : [];
          const provenance = row.origin?.provenance;
          const untypedCount = p.section === "user_types" ? (row.item as IsfStruct).untyped_fields ?? 0 : 0;
          const editOp = EDIT_OP[p.section];
          return (
            <li key={row.name} data-testid="isf-row" data-name={row.name} data-selected={isSel || undefined}
              className={`border rounded px-1 py-0.5 ${isSel ? "border-[var(--md-accent-blue)]" : "border-[var(--md-border)]"}`}>
              <div className="flex items-center gap-1 min-w-0">
                {fields.length > 0 && (
                  <button type="button" aria-expanded={open} className={`${buttonClass} shrink-0`}
                    aria-label={t("tree.toggle", { name: row.name })} onClick={() => toggle(row.name)}>{open ? "-" : "+"}</button>
                )}
                <span className="font-mono truncate min-w-0 flex-1" title={row.name} data-testid="isf-row-name">{row.name}</span>
                <span className="shrink-0"><ProvenanceBadge provenance={provenance} /></span>
                {editOp && (
                  <button type="button" className={iconButtonClass} data-testid="isf-edit-entry"
                    aria-label={t("tree.edit")} title={t("tree.edit")}
                    onClick={() => p.onEdit({ op: editOp, name: row.name, nonce: Date.now() })}>{"\u270E"}</button>
                )}
                {removeButton(key, row.name)}
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <span className="md-text-secondary font-mono truncate min-w-0" title={summarize(p.section, row.item)}>
                  {summarize(p.section, row.item)}</span>
                {untypedCount > 0 && (
                  <span data-testid="isf-untyped-count" className="md-text-muted shrink-0">{t("tree.untypedCount", { count: untypedCount })}</span>
                )}
              </div>
              {provenance && open && <ProvenanceDetail provenance={provenance} />}
              {open && fields.length > 0 && (
                <ul className="pl-3 space-y-0.5" data-testid="isf-fields">
                  {fields.map(([fname, field]) => (
                    <FieldRow key={fname} struct={row.name} name={fname} field={field}
                      selected={isSel && p.selected?.field === fname}
                      origin={data.fieldOrigins[`${row.name}.${fname}`] ?? null}
                      onEdit={() => p.onEdit({ op: "field", name: row.name, field: fname, nonce: Date.now() })}
                      remove={removeButton(["field", row.name, fname], `${row.name}.${fname}`)} />
                  ))}
                </ul>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function FieldRow({ struct, name, field, selected, origin, onEdit, remove }: {
  struct: string; name: string; field: IsfField; selected: boolean;
  origin: IsfOrigin | null;
  onEdit: () => void; remove: React.ReactNode;
}) {
  const { t } = useTranslation("isf");
  return (
    <li data-testid="isf-field-row" data-field={`${struct}.${name}`} data-selected={selected || undefined}
      className={`flex items-center gap-1 min-w-0 ${selected ? "outline outline-1 outline-[var(--md-accent-blue)]" : ""}`}>
      <span className="font-mono truncate min-w-0" title={name}>{name}</span>
      <span className="md-text-secondary font-mono truncate min-w-0 flex-1" title={`+${field.offset} ${formatType(field.type)}`}>
        +{field.offset} {formatType(field.type)}</span>
      <span className="shrink-0"><ProvenanceBadge provenance={origin?.provenance} /></span>
      {origin?.untyped && <span data-testid="isf-untyped" className="md-text-muted shrink-0">{t("tree.untyped")}</span>}
      <button type="button" className={iconButtonClass} aria-label={t("tree.edit")} title={t("tree.edit")}
        onClick={onEdit}>{"\u270E"}</button>
      {remove}
    </li>
  );
}
