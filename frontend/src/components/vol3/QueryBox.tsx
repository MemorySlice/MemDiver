import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  listVol3SavedQueries, runVol3Query, type Vol3QueryResult, type Vol3SavedQuery,
} from "@/api/vol3";
import { formatAddress } from "./vol3-address";
import { queryHasAddresses } from "./vol3-highlights";

const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";
const MAX_SHOWN = 500;
const LIST_DEBOUNCE_MS = 300;

const showCell = (cell: unknown) => {
  if (cell === null || cell === undefined) return "∅";
  // Wire-exact uint64 arrive as decimal strings; show them as hex like the run table.
  return typeof cell === "string" && /^\d{16,}$/.test(cell) ? (formatAddress(cell)?.text ?? cell) : String(cell);
};

/** Read-only SQL over the case tables, with the built-in saved queries. */
export function QueryBox({ caseDir, onSendToHighlights, note }: {
  caseDir: string;
  /** Receives the rows; the panel owns the view context needed to place them. */
  onSendToHighlights: (result: Vol3QueryResult) => void;
  /** Outcome of the last send (placed / refused), shown under the table. */
  note: string | null;
}) {
  const { t } = useTranslation("vol3");
  const [saved, setSaved] = useState<Vol3SavedQuery[]>([]);
  const [sql, setSql] = useState("");
  // The saved query whose text is in the box; sent by name while the text is unchanged.
  const [picked, setPicked] = useState<{ name: string; sql: string } | null>(null);
  const [result, setResult] = useState<Vol3QueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const dir = caseDir.trim();

  useEffect(() => {
    if (!dir) { setSaved([]); return; }
    let cancelled = false;
    const timer = setTimeout(() => {
      listVol3SavedQueries(dir)
        .then((l) => { if (!cancelled) setSaved(l.saved_queries); })
        .catch(() => { if (!cancelled) setSaved([]); });
    }, LIST_DEBOUNCE_MS);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [dir]);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      // A saved query goes by NAME so the backend applies its own refusals
      // (truncated inputs); once the text is edited it is raw SQL.
      const unchanged = picked !== null && picked.sql === sql;
      setResult(await runVol3Query(dir, unchanged ? { saved: picked.name } : { sql }));
    } catch (err) {
      setResult(null);
      setError(readableFailure(err));
    } finally {
      setBusy(false);
    }
  };

  const shown = result ? result.rows.slice(0, MAX_SHOWN) : [];
  return (
    <div className="space-y-2" data-testid="query-box">
      {!dir && <p className="md-text-muted" data-testid="query-needs-case">{t("query.needCase")}</p>}
      <select aria-label={t("query.saved")} data-testid="query-saved" value=""
        onChange={(e) => {
          const q = saved.find((s) => s.name === e.target.value);
          if (q && typeof q.sql === "string") {
            setSql(q.sql);
            setPicked({ name: q.name, sql: q.sql });
          }
        }}
        className="w-full px-1 py-0.5 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]">
        <option value="">{t("query.savedPlaceholder")}</option>
        {saved.map((q) => <option key={q.name} value={q.name} title={q.description}>{q.name}</option>)}
      </select>
      <textarea value={sql} onChange={(e) => setSql(e.target.value)} rows={4} spellCheck={false}
        aria-label={t("query.sql")} placeholder={t("query.sqlPlaceholder")} data-testid="query-sql"
        className="w-full px-2 py-1 text-xs font-mono rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]" />
      <button type="button" className={buttonClass} disabled={!dir || !sql.trim() || busy}
        onClick={() => void run()} data-testid="query-run">{t("query.run")}</button>
      {error && <p role="alert" data-testid="query-error" style={{ color: "var(--md-accent-red)" }}>{error}</p>}
      {result && (
        <div className="space-y-1" data-testid="query-result">
          <p className="md-text-muted">{t("query.rows", { shown: shown.length, total: result.row_count })}</p>
          {(result.warnings ?? []).map((w, n) => (
            <p key={n} role="status" data-testid="query-warning" className="md-text-warning">
              {typeof w === "string" ? w : JSON.stringify(w)}
            </p>
          ))}
          {result.truncated && <p role="status" data-testid="query-truncated">{t("query.truncated")}</p>}
          <div className="overflow-auto max-h-80 border border-[var(--md-border)] rounded">
            <table className="text-xs font-mono">
              <thead className="sticky top-0 bg-[var(--md-bg-secondary)]">
                <tr>{result.columns.map((c) => <th key={c} className="px-2 text-left font-medium">{c}</th>)}</tr>
              </thead>
              <tbody>
                {shown.map((row, r) => (
                  <tr key={r} data-testid="query-row">
                    {row.map((cell, c) => <td key={c} className="px-2 whitespace-nowrap">{showCell(cell)}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {queryHasAddresses(result) && (
            <button type="button" className={buttonClass} data-testid="query-send"
              onClick={() => onSendToHighlights(result)}>{t("query.send")}</button>
          )}
          {note && <p role="status" data-testid="query-note" className="md-text-muted">{note}</p>}
        </div>
      )}
    </div>
  );
}
