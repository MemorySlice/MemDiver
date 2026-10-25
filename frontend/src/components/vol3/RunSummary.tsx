import { useTranslation } from "react-i18next";

import type { Vol3RunResult } from "@/api/vol3";

/**
 * Honest run status: a truncated run says so and why, diagnostics are listed,
 * and the arguments the backend filled in (e.g. a process view's pid) are shown.
 */
export function RunSummary({ result }: { result: Vol3RunResult }) {
  const { t } = useTranslation("vol3");
  const defaults = Object.entries(result.defaults_applied ?? {});
  return (
    <div className="space-y-1 text-xs" data-testid="run-summary">
      <p className="md-text-secondary">
        {t("result.rows", { returned: result.rows_returned, total: result.row_count })}
        {" · "}{t("result.elapsed", { s: result.elapsed_s })}
      </p>
      {result.truncated && (
        <p role="alert" data-testid="truncated-banner" className="font-medium"
          style={{ color: "var(--md-accent-orange)" }}>
          {t("result.truncated", {
            reason: t(`result.stopReason.${result.stop_reason ?? "unknown"}`, {
              defaultValue: result.stop_reason ?? t("result.stopReason.unknown") }) })}
        </p>
      )}
      {result.rows_returned < result.row_count && (
        <p className="md-text-muted" data-testid="cap-note">
          {t("result.rowCap", { returned: result.rows_returned, total: result.row_count })}</p>
      )}
      {defaults.length > 0 && (
        <p className="md-text-muted" data-testid="defaults-applied">
          {t("result.defaultsApplied", {
            args: defaults.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ") })}
        </p>
      )}
      {result.diagnostics.length > 0 && (
        <ul data-testid="diagnostics" className="list-disc pl-4 md-text-muted">
          {result.diagnostics.map((d, i) => <li key={i}>{d}</li>)}
        </ul>
      )}
    </div>
  );
}
