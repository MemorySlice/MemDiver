import { useTranslation } from "react-i18next";

import type { ImageJobState } from "./useImageJob";
import { ImageError } from "./ImageError";

const cancelClass =
  "px-2 py-0.5 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

/**
 * Progress bar + error line of one image job (renders nothing while idle/done).
 * A job with a pakunoda stage has no honest completion fraction, so it shows an
 * indeterminate bar and "Stage: x · n s"; `onCancel` adds a Cancel button.
 */
export function JobStatus<T>({ state, label, testId, onCancel }: {
  state: ImageJobState<T>;
  label: string;
  testId: string;
  onCancel?: () => void;
}) {
  const { t } = useTranslation("image");
  if (state.status === "error" && state.error) return <ImageError message={state.error} implicated={state.implicated} />;
  if (state.status !== "running") return null;
  const pct = state.pct === null ? null : Math.round(state.pct * 100);
  const stage = state.stage ?? state.msg;
  const staged = state.stage !== null;
  const text = staged
    ? t("profile.stage", { stage, elapsed: (state.elapsedS ?? 0).toFixed(1) })
      + (state.totalElapsedS === null ? "" : t("profile.total", { total: state.totalElapsedS.toFixed(1) }))
    : `${state.msg ?? label}${pct !== null ? ` ${t("progress", { pct })}` : ""}`;
  return (
    <div data-testid={testId} role="status" className="text-xs md-text-secondary space-y-1">
      <div className="flex items-center gap-2">
        <span data-testid={`${testId}-text`}>{text}</span>
        {onCancel && (
          <button type="button" className={cancelClass} data-testid={`${testId}-cancel`}
            disabled={state.cancelling} onClick={onCancel}>{t("profile.cancel")}</button>
        )}
      </div>
      <div role="progressbar" aria-busy="true" aria-label={label}
        aria-valuemin={0} aria-valuemax={100} {...(!staged && pct !== null ? { "aria-valuenow": pct } : {})}
        className="h-1 rounded bg-[var(--md-border)] overflow-hidden relative">
        {staged || pct === null
          ? <div className="h-full w-1/3 bg-[var(--md-accent-blue)] animate-pulse" />
          : <div className="h-full bg-[var(--md-accent-blue)]" style={{ width: `${pct}%` }} />}
      </div>
    </div>
  );
}
