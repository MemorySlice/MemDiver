import { useId } from "react";
import { useTranslation } from "react-i18next";

import { HEAP_POLICIES, type HeapPolicy } from "@/api/types";

/** The backend default, shown while nothing has been chosen. */
const DEFAULT_HEAP_POLICY: HeapPolicy = "annotate";

interface Props {
  /** `undefined` = not chosen; the select shows the backend default. */
  value: HeapPolicy | undefined;
  onChange: (next: HeapPolicy) => void;
  disabled?: boolean;
  testId?: string;
  /** Classes for the `<select>`, so each form keeps its own input idiom. */
  selectClassName?: string;
}

/**
 * `Annotate │ Mask metadata │ Off` — what the candidate reduction does with
 * the consensus heap roles. Shared by the Consensus tab's candidate filters
 * and the pipeline's search-reduce thresholds, so both word it the same way.
 */
export function HeapPolicySelect({
  value,
  onChange,
  disabled = false,
  testId,
  selectClassName = "w-32 px-2 py-1 rounded border border-[var(--md-border)] md-bg-secondary",
}: Props) {
  const { t } = useTranslation("heap");
  const id = useId();
  const current = value ?? DEFAULT_HEAP_POLICY;

  return (
    <label htmlFor={id} className="flex flex-col gap-0.5" title={t("candidates.policy.hint")}>
      <span className="md-text-muted">{t("candidates.policy.label")}</span>
      <select
        id={id}
        data-testid={testId}
        value={current}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value as HeapPolicy)}
        className={selectClassName}
      >
        {HEAP_POLICIES.map((policy) => (
          <option key={policy} value={policy} title={t(`candidates.policy.${policy}Hint`)}>
            {t(`candidates.policy.${policy}`)}
          </option>
        ))}
      </select>
      <span className="text-[10px] md-text-muted max-w-[10rem]">
        {t(`candidates.policy.${current}Hint`)}
      </span>
    </label>
  );
}
