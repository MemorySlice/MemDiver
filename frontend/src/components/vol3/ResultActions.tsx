import { useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import { annotateVol3Run, type Vol3RunResult } from "@/api/vol3";

const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";
const selectClass =
  "px-1 py-0.5 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";

/** "Highlight column" and "Save as annotations" for one result. */
export function ResultActions({ result, caseDir, onHighlight }: {
  result: Vol3RunResult;
  caseDir: string;
  onHighlight: (column: string) => void;
}) {
  const { t } = useTranslation("vol3");
  const addressColumns = result.columns.filter((c) => c.space);
  const labelColumns = result.columns.filter((c) => c.type === "str");
  const [column, setColumn] = useState(addressColumns[0]?.name ?? "");
  const [label, setLabel] = useState("");
  const [note, setNote] = useState<{ text: string; error: boolean } | null>(null);
  const tableName = typeof result.table?.name === "string" ? result.table.name : null;
  const canSave = Boolean(caseDir.trim() && result.run_id && tableName && column);

  const save = async () => {
    if (!canSave || !tableName || !result.run_id) return;
    try {
      const out = await annotateVol3Run({
        case_dir: caseDir.trim(), table: tableName, run_id: result.run_id, column,
        label_column: label || undefined,
      });
      setNote({ text: t("annotate.done", { n: Number(out.created ?? 0) }), error: false });
    } catch (err) {
      setNote({ text: readableFailure(err), error: true });
    }
  };

  if (addressColumns.length === 0) {
    return <p className="text-xs md-text-muted" data-testid="no-address-columns">{t("actions.noAddress")}</p>;
  }
  return (
    <div className="space-y-1" data-testid="result-actions">
      <div className="flex flex-wrap items-center gap-2">
        <select value={column} onChange={(e) => setColumn(e.target.value)} className={selectClass}
          aria-label={t("actions.column")} data-testid="action-column">
          {addressColumns.map((c) => <option key={c.name} value={c.name}>{c.name}</option>)}
        </select>
        <button type="button" className={buttonClass} disabled={!column}
          onClick={() => onHighlight(column)} data-testid="highlight-column">{t("actions.highlight")}</button>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <select value={label} onChange={(e) => setLabel(e.target.value)} className={selectClass}
          aria-label={t("annotate.labelColumn")} data-testid="annotate-label">
          <option value="">{t("annotate.noLabel")}</option>
          {labelColumns.map((c) => <option key={c.name} value={c.name}>{c.name}</option>)}
        </select>
        <button type="button" className={buttonClass} disabled={!canSave} onClick={() => void save()}
          data-testid="annotate-save">{t("annotate.save")}</button>
      </div>
      {!canSave && <p className="text-xs md-text-muted" data-testid="annotate-disabled-hint">{t("annotate.needCase")}</p>}
      {note && (
        <p role={note.error ? "alert" : "status"} data-testid="annotate-note" className="text-xs"
          style={note.error ? { color: "var(--md-accent-red)" } : undefined}>{note.text}</p>
      )}
    </div>
  );
}
