import { useTranslation } from "react-i18next";

import type { Vol3CheckOutcome } from "@/api/vol3";

/** The outcome of loading a plugin source: its identity, or exactly what broke. */
export function CheckResultView({ outcome }: { outcome: Vol3CheckOutcome }) {
  const { t } = useTranslation("vol3");
  if (!outcome.ok) {
    const { error } = outcome;
    return (
      <div role="alert" data-testid="check-error" className="space-y-0.5"
        style={{ color: "var(--md-accent-red)" }}>
        <p className="font-medium">
          {error.line !== null ? t("editor.check.failedAt", { type: error.type, line: error.line })
            : t("editor.check.failed", { type: error.type })}
        </p>
        <p>{error.message}</p>
        {error.text && <pre className="font-mono md-text-secondary whitespace-pre-wrap">{error.text}</pre>}
      </div>
    );
  }
  const open = outcome.unsatisfied ?? [];
  return (
    <div role="status" data-testid="check-ok" className="space-y-0.5">
      <p className="font-medium" style={{ color: "var(--md-accent-green)" }}>
        {t("editor.check.ok", { name: outcome.plugin.name, version: outcome.plugin.version || "-" })}
      </p>
      <p className="md-text-secondary" data-testid="check-requirements">
        {outcome.plugin.requirements.length === 0
          ? t("editor.check.noRequirements")
          : t("editor.check.requirements", {
            list: outcome.plugin.requirements.map((r) => r.name).join(", ") })}
      </p>
      {outcome.view_path !== undefined && (open.length === 0
        ? <p data-testid="check-satisfied" style={{ color: "var(--md-accent-green)" }}>{t("editor.check.viewSatisfied")}</p>
        : (
          <div data-testid="check-unsatisfied" style={{ color: "var(--md-accent-orange)" }}>
            <p className="font-medium">{t("editor.check.unsatisfied")}</p>
            <ul className="list-disc ml-4">
              {open.map((u) => (
                <li key={`${u.path ?? ""}${u.name}`}>
                  <span className="font-mono">{u.name}</span>
                  {u.optional ? ` (${t("args.optional")})` : ""}
                  {(u.reason || u.description) ? `: ${u.reason || u.description}` : ""}
                </li>
              ))}
            </ul>
          </div>
        ))}
    </div>
  );
}
