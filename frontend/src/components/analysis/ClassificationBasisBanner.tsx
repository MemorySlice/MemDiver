import { memo } from "react";
import { useTranslation } from "react-i18next";
import {
  CLASSIFICATION_BASIS_MIXED,
  classificationBasisDetails,
  findDiagnostic,
  type Diagnostic,
} from "@/api/diagnostics";

export interface ClassificationBasisBannerProps {
  /** Any diagnostics list; the banner picks out `classification_basis_mixed`. */
  diagnostics: readonly Diagnostic[] | null | undefined;
  /** Which view mounted it (`consensus`, `aligned-window`, `candidates`). */
  scope: string;
}

/**
 * "These dumps were not classified the same way."
 *
 * A region-filtered consensus/alignment over dumps classified by mapping names
 * (new imports, live captures) AND dumps classified by stored region type only
 * (legacy imports) may pair anonymous regions that are not the same region.
 * The numbers still render; this says why they may not correspond.
 *
 * Renders ONLY for `classification_basis_mixed`. Other codes are ignored here
 * on purpose: each code earns its own localized sentence, and the backend's
 * English `message` is never shown in its place.
 */
export const ClassificationBasisBanner = memo(function ClassificationBasisBanner({
  diagnostics,
  scope,
}: ClassificationBasisBannerProps) {
  const { t } = useTranslation("diagnostics");
  const diagnostic = findDiagnostic(diagnostics, CLASSIFICATION_BASIS_MIXED);
  if (!diagnostic) return null;

  const details = classificationBasisDetails(diagnostic);

  return (
    <div
      data-testid="classification-basis-warning"
      data-scope={scope}
      role="alert"
      className="px-2 py-1.5 rounded border text-[11px] md-bg-warning-subtle md-border-warning"
    >
      <p className="font-medium md-text-warning">{t("classificationBasisMixed.title")}</p>
      <p data-testid="classification-basis-body">
        {t("classificationBasisMixed.body", {
          named: details.named_dumps.length,
          stored: details.stored_type_dumps.length,
          total: details.total_dumps,
        })}
      </p>
      {details.stored_type_dumps.length > 0 && (
        <p className="md-text-muted font-mono" data-testid="classification-basis-stored">
          {t("classificationBasisMixed.storedDumps", {
            dumps: details.stored_type_dumps.join(", "),
          })}
        </p>
      )}
      <p className="md-text-muted" data-testid="classification-basis-hint">
        {t("classificationBasisMixed.hint")}
      </p>
    </div>
  );
});
