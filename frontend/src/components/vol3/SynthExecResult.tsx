import { useTranslation } from "react-i18next";

import type { Vol3ExecResult } from "@/api/vol3";
import { cellText, execColumns, isProvenCell, isSecretColumn } from "./synth-utils";

const PROVEN_COLUMN = "Proven";

/**
 * Rows of a plugin run under stock `vol` (`POST /api/vol3/exec`). The `Proven`
 * column is the claim that matters, so it comes first and is counted; columns
 * carrying key material are masked.
 */
export function SynthExecResult({ result }: { result: Vol3ExecResult }) {
  const { t } = useTranslation("vol3");
  const all = execColumns(result.rows);
  const columns = all.includes(PROVEN_COLUMN) ? [PROVEN_COLUMN, ...all.filter((c) => c !== PROVEN_COLUMN)] : all;
  const proven = result.rows.filter((r) => isProvenCell(r[PROVEN_COLUMN])).length;
  return (
    <div className="space-y-1" data-testid="synth-exec-result">
      <p role="status" data-testid="synth-exec-summary"
        style={{ color: result.ok ? undefined : "var(--md-accent-red)" }}>
        {result.ok
          ? t("exec.summary", { rows: result.row_count, proven, elapsed: result.elapsed_s.toFixed(1) })
          : t("exec.failed", { code: result.returncode ?? "?" })}
        {result.truncated && ` ${t("exec.truncated")}`}
      </p>
      {result.framework && <p className="md-text-muted" data-testid="synth-exec-framework">{result.framework}</p>}
      {result.rows.length > 0 && (
        <div className="overflow-auto max-h-64">
          <table className="w-full text-left font-mono text-[10px]" data-testid="synth-exec-table">
            <caption className="sr-only">{t("exec.caption", { plugin: result.plugin })}</caption>
            <thead className="md-text-secondary">
              <tr>{columns.map((c) => (
                <th key={c} scope="col" className="px-1 py-0.5 font-normal whitespace-nowrap">
                  {c}{isSecretColumn(c) && <span className="md-text-muted"> ({t("exec.masked")})</span>}
                </th>
              ))}</tr>
            </thead>
            <tbody>
              {result.rows.map((row, i) => (
                <tr key={i} data-testid="synth-exec-row">
                  {columns.map((c) => (
                    <td key={c} className="px-1 py-0.5 whitespace-nowrap"
                      data-testid={c === PROVEN_COLUMN ? "synth-exec-proven" : undefined}
                      style={c === PROVEN_COLUMN && isProvenCell(row[c])
                        ? { color: "var(--md-accent-green)", fontWeight: 600 } : undefined}>
                      {cellText(c, row[c])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {!result.ok && result.stderr_tail && (
        <pre className="text-[10px] p-1 rounded border border-[var(--md-border)] overflow-auto max-h-32"
          data-testid="synth-exec-stderr">{result.stderr_tail}</pre>
      )}
    </div>
  );
}
