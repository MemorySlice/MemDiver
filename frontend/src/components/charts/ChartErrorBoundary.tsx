/**
 * Chart-flavored `ErrorBoundary`.
 *
 * Every lazy-loaded chart dispatcher (EntropyChart, VarianceMap, VasChart,
 * SurvivorCurve) wraps its `<Suspense>` in one of these. On error it shows
 * a short i18n message plus a Retry button; clicking Retry calls the
 * caller-supplied `onRetry` (which the dispatcher uses to recreate its
 * `lazy()` import so a transient chunk-load failure gets a real second
 * attempt) and then clears the boundary's own error state.
 */
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { ErrorBoundary } from "@/components/ErrorBoundary";

interface ChartErrorBoundaryProps {
  children: ReactNode;
  /** Called when the user clicks Retry, before the error state clears. */
  onRetry: () => void;
}

export function ChartErrorBoundary({ children, onRetry }: ChartErrorBoundaryProps) {
  const { t } = useTranslation("charts");
  return (
    <ErrorBoundary
      onReset={onRetry}
      fallback={(retry) => (
        <div className="p-4 text-sm md-text-muted" role="alert">
          <p>{t("error.message")}</p>
          <button
            type="button"
            className="mt-2 px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
            onClick={retry}
          >
            {t("error.retry")}
          </button>
        </div>
      )}
    >
      {children}
    </ErrorBoundary>
  );
}
