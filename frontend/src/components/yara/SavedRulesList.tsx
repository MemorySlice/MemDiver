import { useState } from "react";
import { useTranslation } from "react-i18next";

import type { RuleScope, YaraRuleMeta } from "@/api/yara";

const buttonClass =
  "px-2 py-0.5 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

const keyOf = (r: Pick<YaraRuleMeta, "name" | "scope">) => `${r.scope}:${r.name}`;

/** The stored rules with their scope, version and health markers; Load and confirmed Delete. */
export function SavedRulesList({ rules, loadedKey, onLoad, onDelete }: {
  rules: YaraRuleMeta[];
  loadedKey: string | null;
  onLoad: (name: string, scope: RuleScope) => void;
  onDelete: (name: string, scope: RuleScope) => void;
}) {
  const { t } = useTranslation("yara");
  const [confirming, setConfirming] = useState<string | null>(null);

  if (rules.length === 0) {
    return <p className="md-text-muted" data-testid="yara-rules-none">{t("saved.none")}</p>;
  }
  return (
    <ul aria-label={t("saved.title")} className="space-y-1" data-testid="yara-rules">
      {rules.map((r) => {
        const key = keyOf(r);
        const scope = t(`saved.scope.${r.scope}`);
        return (
          <li key={key} data-testid="yara-rule-row" data-name={r.name} data-scope={r.scope}
            aria-current={loadedKey === key ? "true" : undefined}
            className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <span className="font-medium">{r.name}</span>
            <span className="md-text-secondary" data-testid="yara-rule-scope">{scope}</span>
            {r.version !== null && <span className="md-text-muted">{t("saved.version", { version: r.version })}</span>}
            {r.modified_externally && (
              <span data-testid="yara-rule-external" title={t("saved.externalHint")}
                style={{ color: "var(--md-accent-orange)" }}>{t("saved.external")}</span>
            )}
            {r.compiles === false && (
              <span data-testid="yara-rule-broken" style={{ color: "var(--md-accent-red)" }}>{t("saved.broken")}</span>
            )}
            {r.shadows && <span className="md-text-muted" data-testid="yara-rule-shadows">{t("saved.shadows")}</span>}
            {r.shadowed && <span className="md-text-muted" data-testid="yara-rule-shadowed">{t("saved.shadowed")}</span>}
            <span className="flex gap-1 ml-auto">
              <button type="button" className={buttonClass} disabled={r.shadowed}
                aria-label={t("saved.loadLabel", { name: r.name, scope })} data-testid="yara-rule-load"
                onClick={() => onLoad(r.name, r.scope)}>{t("saved.load")}</button>
              {confirming === key ? (
                <span role="group" aria-label={t("saved.confirmDelete", { name: r.name, scope })}
                  className="flex items-center gap-1" data-testid="yara-rule-confirm">
                  <span style={{ color: "var(--md-accent-red)" }}>{t("saved.confirmDelete", { name: r.name, scope })}</span>
                  <button type="button" className={buttonClass} data-testid="yara-rule-confirm-yes"
                    onClick={() => { setConfirming(null); onDelete(r.name, r.scope); }}>{t("saved.confirm")}</button>
                  <button type="button" className={buttonClass} data-testid="yara-rule-confirm-no"
                    onClick={() => setConfirming(null)}>{t("saved.cancel")}</button>
                </span>
              ) : (
                <button type="button" className={buttonClass} data-testid="yara-rule-delete"
                  aria-label={t("saved.deleteLabel", { name: r.name, scope })}
                  onClick={() => setConfirming(key)}>{t("saved.delete")}</button>
              )}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
