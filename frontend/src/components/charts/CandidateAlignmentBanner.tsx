import { memo } from "react";
import { useTranslation } from "react-i18next";
import type { AlignmentReport } from "@/api/candidates";

/**
 * How the N dumps were compared, and what that cost.
 *
 * The method is shown ALWAYS: an analyst reading a variance number has to know
 * whether byte 0 was compared to byte 0 (flat file offset) or to the same byte
 * of the same module (ASLR-invariant), because the two answer different
 * questions. The warnings are the loud half — non-empty exactly when the
 * comparison is questionable (the flat fallback ran on dumps of differing
 * size, or an aligned path kept too little to be representative). On an
 * equal-sized phase series the array is empty and the banner stays
 * informational rather than alarming, which is the whole point of it.
 */
export const CandidateAlignmentBanner = memo(function CandidateAlignmentBanner({
  report,
}: {
  report: AlignmentReport;
}) {
  const { t } = useTranslation("candidates");
  const hasWarnings = report.warnings.length > 0;

  return (
    <div
      data-testid="candidate-alignment-banner"
      role={hasWarnings ? "alert" : undefined}
      className={`px-2 py-1.5 rounded border text-[11px] ${
        hasWarnings
          ? "md-bg-warning-subtle md-border-warning"
          : "border-[var(--md-border)]"
      }`}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 md-text-muted">
        <span>
          <span className="font-medium">{t("alignmentBanner.label")}:</span>{" "}
          <span data-testid="candidate-alignment-method" className="font-mono">
            {t(`alignmentBanner.method.${report.method}`, {
              defaultValue: report.method,
            })}
          </span>
        </span>
        <span>
          {t("alignmentBanner.compared", {
            bytes: report.bytes_compared.toLocaleString(),
          })}
        </span>
        {report.bytes_discarded > 0 && (
          <span>
            {t("alignmentBanner.discarded", {
              bytes: report.bytes_discarded.toLocaleString(),
            })}
          </span>
        )}
        {report.sizes_differed && (
          <span>{t("alignmentBanner.sizesDiffered")}</span>
        )}
      </div>

      {hasWarnings && (
        <div data-testid="candidate-alignment-warnings" className="mt-1">
          <p className="font-medium md-text-warning">
            {t("alignmentBanner.warningsTitle")}
          </p>
          <ul className="mt-0.5 pl-4 list-disc space-y-0.5 md-text-warning">
            {report.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
});
