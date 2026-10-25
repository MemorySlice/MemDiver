import { useTranslation } from "react-i18next";

import type { ImageJobState } from "./useImageJob";
import { ImageError } from "./ImageError";

/** Progress bar + error line of one image job (renders nothing while idle/done). */
export function JobStatus<T>({ state, label, testId }: {
  state: ImageJobState<T>;
  label: string;
  testId: string;
}) {
  const { t } = useTranslation("image");
  if (state.status === "error" && state.error) return <ImageError message={state.error} />;
  if (state.status !== "running") return null;
  const pct = state.pct === null ? null : Math.round(state.pct * 100);
  return (
    <div data-testid={testId} role="status" className="text-xs md-text-secondary space-y-1">
      <div>{state.msg ?? label}{pct !== null && ` ${t("progress", { pct })}`}</div>
      <div className="h-1 rounded bg-[var(--md-border)] overflow-hidden">
        <div className="h-full bg-[var(--md-accent-blue)]"
          style={{ width: pct === null ? "30%" : `${pct}%` }} />
      </div>
    </div>
  );
}
