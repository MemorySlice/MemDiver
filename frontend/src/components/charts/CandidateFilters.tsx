import { memo, useId } from "react";
import { useTranslation } from "react-i18next";
import { BYTE_CLASSES, type ByteClassName, type CandidateFilterState } from "@/api/candidates";

/** Byte alignments worth offering: none, word, pointer, page. */
const ALIGNMENT_CHOICES = [1, 4, 8, 16, 4096];

interface Props {
  value: CandidateFilterState;
  onChange: (next: CandidateFilterState) => void;
  disabled?: boolean;
}

/** Parse a number input, treating an unparseable value as the fallback. */
function toNumber(raw: string, fallback: number): number {
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/**
 * The four filter controls of the candidate query.
 *
 * The class control is a checkbox group rather than a `<select multiple>`:
 * every option then carries its own label and its own checked state, which is
 * both what a screen reader needs and what makes "defaults to all
 * non-invariant" assertable in a test. State is owned by the parent
 * (component-local `useState`), never a store slice — these are the terms of
 * one query, not application state anything else reads.
 */
export const CandidateFilters = memo(function CandidateFilters({
  value,
  onChange,
  disabled = false,
}: Props) {
  const { t } = useTranslation("candidates");
  const ids = useId();

  const toggleClass = (name: ByteClassName) => {
    const next = value.classes.includes(name)
      ? value.classes.filter((c) => c !== name)
      : [...value.classes, name];
    onChange({ ...value, classes: next });
  };

  const numberField = (
    key: "minRegion" | "maxRegion" | "entropyThreshold",
    labelKey: string,
    id: string,
    extra: { step?: number; min?: number; max?: number; hint?: string },
  ) => (
    <label htmlFor={id} className="flex flex-col gap-0.5">
      <span className="md-text-muted">{t(labelKey)}</span>
      <input
        id={id}
        type="number"
        value={value[key]}
        disabled={disabled}
        step={extra.step}
        min={extra.min}
        max={extra.max}
        onChange={(e) => onChange({ ...value, [key]: toNumber(e.target.value, value[key]) })}
        className="w-24 px-2 py-1 rounded border border-[var(--md-border)] md-bg-secondary"
      />
      {extra.hint && <span className="text-[10px] md-text-muted">{extra.hint}</span>}
    </label>
  );

  return (
    <fieldset
      data-testid="candidate-filters"
      className="border border-[var(--md-border)] rounded px-2 py-1.5"
    >
      <legend className="px-1 text-[11px] md-text-muted">
        {t("filters.legend")}
      </legend>

      <div className="flex flex-wrap items-start gap-x-5 gap-y-2 text-[11px]">
        <fieldset className="border-0 p-0 m-0">
          <legend className="md-text-muted mb-0.5">{t("filters.classes")}</legend>
          <div
            data-testid="candidate-class-select"
            className="flex flex-wrap gap-x-3 gap-y-1"
          >
            {BYTE_CLASSES.map((name) => {
              const id = `${ids}-class-${name}`;
              return (
                <label key={name} htmlFor={id} className="flex items-center gap-1">
                  <input
                    id={id}
                    type="checkbox"
                    data-testid={`candidate-class-${name}`}
                    checked={value.classes.includes(name)}
                    disabled={disabled}
                    onChange={() => toggleClass(name)}
                  />
                  <span title={t(`legend.class.${name}`)}>{t(`class.${name}`)}</span>
                </label>
              );
            })}
          </div>
          <p className="mt-0.5 text-[10px] md-text-muted max-w-xs">
            {t("filters.classesHint")}
          </p>
        </fieldset>

        {numberField("minRegion", "filters.minLength", `${ids}-min`, { min: 1 })}
        {numberField("maxRegion", "filters.maxLength", `${ids}-max`, {
          min: 0,
          hint: t("filters.maxLengthAny"),
        })}
        {numberField("entropyThreshold", "filters.entropyThreshold", `${ids}-entropy`, {
          step: 0.1,
          min: 0,
          max: 8,
          hint: t("filters.entropyUnit"),
        })}

        <label htmlFor={`${ids}-alignment`} className="flex flex-col gap-0.5">
          <span className="md-text-muted">{t("filters.alignment")}</span>
          <select
            id={`${ids}-alignment`}
            data-testid="candidate-alignment-select"
            value={value.alignment}
            disabled={disabled}
            onChange={(e) =>
              onChange({ ...value, alignment: toNumber(e.target.value, value.alignment) })
            }
            className="w-24 px-2 py-1 rounded border border-[var(--md-border)] md-bg-secondary"
          >
            {ALIGNMENT_CHOICES.map((n) => (
              <option key={n} value={n}>
                {n} {t("filters.alignmentUnit")}
              </option>
            ))}
          </select>
        </label>
      </div>
    </fieldset>
  );
});
