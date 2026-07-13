/**
 * Small badge showing decryption verification status.
 */
import { useTranslation } from "react-i18next";

interface VerificationBadgeProps {
  verified: boolean | null | undefined;
}

export function VerificationBadge({ verified }: VerificationBadgeProps) {
  const { t } = useTranslation("results");
  if (verified === true) {
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium md-bg-success-subtle md-text-success"
            title={t("verification.verifiedTitle")}>
        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
        </svg>
        {t("verification.verified")}
      </span>
    );
  }
  if (verified === false) {
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium md-bg-error-subtle md-text-error"
            title={t("verification.failedTitle")}>
        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
        </svg>
        {t("verification.failed")}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium bg-zinc-500/20 text-zinc-400"
          title={t("verification.notVerifiedTitle")}>
      ?
    </span>
  );
}
