import { useTranslation } from "react-i18next";

export interface ImportWarningsProps {
  secretsOnlyInExcluded?: number;
  warnings?: string[];
}

/**
 * Warning callout for an import whose selection dropped something that
 * matters. Renders nothing when there is nothing to warn about.
 * `warnings` are server-produced sentences and are shown as given.
 */
export function ImportWarnings({ secretsOnlyInExcluded = 0, warnings = [] }: ImportWarningsProps) {
  const { t } = useTranslation("import");
  if (secretsOnlyInExcluded <= 0 && warnings.length === 0) return null;
  return (
    <div
      role="alert"
      data-testid="import-warnings"
      className="text-xs p-2 rounded border space-y-1"
      style={{ borderColor: "var(--md-accent-orange)", color: "var(--md-text-primary)" }}
    >
      <p className="font-semibold" style={{ color: "var(--md-accent-orange)" }}>
        {t("warnings.heading")}
      </p>
      {secretsOnlyInExcluded > 0 && (
        <p>{t("warnings.secretsOnlyInExcluded", { count: secretsOnlyInExcluded })}</p>
      )}
      {warnings.map((w, i) => (
        <p key={i}>{w}</p>
      ))}
    </div>
  );
}
