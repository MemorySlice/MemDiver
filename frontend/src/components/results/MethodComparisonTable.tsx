/**
 * Side-by-side method comparison table matching the CLI output format.
 */
import { useTranslation } from "react-i18next";

interface ToolResult {
  tool: string;
  format: string;
  precision?: number;
  false_positives?: number;
  recall?: number;
  decryption_verified?: boolean;
  plugin_saved?: string | null;
}

interface MethodComparisonTableProps {
  results: ToolResult[];
}

export function MethodComparisonTable({ results }: MethodComparisonTableProps) {
  const { t } = useTranslation("results");
  if (results.length === 0) {
    return (
      <div className="flex items-center justify-center h-24 md-text-muted text-sm">
        {t("comparison.empty")}
      </div>
    );
  }

  const metrics = [
    { key: 'format', label: t("comparison.format"), fmt: (v: unknown) => String(v) },
    { key: 'precision', label: t("comparison.precision"), fmt: (v: unknown) => typeof v === 'number' ? `${(v * 100).toFixed(2)}%` : t("comparison.na") },
    { key: 'false_positives', label: t("comparison.falsePositives"), fmt: (v: unknown) => typeof v === 'number' ? v.toLocaleString() : t("comparison.na") },
    { key: 'recall', label: t("comparison.recall"), fmt: (v: unknown) => typeof v === 'number' ? `${(v * 100).toFixed(1)}%` : t("comparison.na") },
    { key: 'decryption_verified', label: t("comparison.decryption"), fmt: (v: unknown) => v === true ? t("comparison.yes") : v === false ? t("comparison.no") : t("comparison.na") },
    { key: 'plugin_saved', label: t("comparison.plugin"), fmt: (v: unknown) => v ? t("comparison.saved") : '-' },
  ];

  return (
    <div className="p-4">
      <h3 className="text-sm font-semibold text-[var(--md-text-primary)] mb-3">
        {t("comparison.title")}
      </h3>
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="border-b border-[var(--md-border)]">
            <th className="text-left py-1.5 px-2 md-text-secondary font-medium">{t("comparison.metric")}</th>
            {results.map(r => (
              <th key={r.tool} className="text-center py-1.5 px-2 text-[var(--md-text-primary)] font-semibold">
                {r.tool}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {metrics.map(m => (
            <tr key={m.key} className="border-b border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
              <td className="py-1.5 px-2 md-text-secondary">{m.label}</td>
              {results.map(r => (
                <td key={r.tool} className="text-center py-1.5 px-2 text-[var(--md-text-primary)]">
                  {m.fmt((r as unknown as Record<string, unknown>)[m.key])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
