import { useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import { validateIsfDraft, type DraftRef, type ValidateResult } from "@/api/isf";
import { buttonClass, errorStyle } from "./ui";

/** Validate the draft and show per-plugin readiness as cards. */
export function ValidateCards({ draftRef, draft, rev }: { draftRef: DraftRef; draft: string; rev: number }) {
  const { t } = useTranslation("isf");
  const [answer, setAnswer] = useState<{ rev: number; draft: string; result: ValidateResult } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // A readiness answer describes ONE version of ONE draft; an edit retires it.
  const result = answer && answer.rev === rev && answer.draft === draft ? answer.result : null;

  const run = async () => {
    setBusy(true); setError(null);
    try { setAnswer({ rev, draft, result: await validateIsfDraft(draftRef, draft) }); }
    catch (e) { setError(readableFailure(e)); }
    setBusy(false);
  };
  return (
    <section className="space-y-1" data-testid="isf-validate">
      <h4 className="font-semibold">{t("validate.title")}</h4>
      <button type="button" className={buttonClass} disabled={busy} data-testid="isf-validate-run"
        onClick={() => void run()}>{t("validate.run")}</button>
      {error && <p role="alert" data-testid="isf-validate-error" style={errorStyle}>{error}</p>}
      {result && (
        <>
          <p data-testid="isf-validate-summary">
            {result.is_valid ? t("validate.valid") : t("validate.invalid")}
            {" · "}{t("validate.counts", { errors: result.error_count, warnings: result.warning_count })}
            {result.truncated ? ` · ${t("validate.truncated")}` : ""}
          </p>
          <ul className="grid grid-cols-1 gap-1" data-testid="isf-readiness">
            {result.plugins.map((p) => (
              <li key={p.plugin} data-testid="isf-readiness-card" data-verdict={p.verdict}
                className="border border-[var(--md-border)] rounded px-1 py-0.5">
                <div className="flex justify-between gap-2">
                  <span className="font-mono">{p.plugin}</span>
                  <span className="font-medium">{p.verdict}</span>
                </div>
                <div className="md-text-secondary">
                  {t("validate.missing", { required: p.required_missing.length, optional: p.optional_missing })}
                  {p.upstream_defects > 0 ? ` · ${t("validate.defects", { count: p.upstream_defects })}` : ""}
                </div>
                {p.reason && <div className="md-text-muted">{p.reason}</div>}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
