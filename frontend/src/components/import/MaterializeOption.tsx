import { useId } from "react";
import { useTranslation } from "react-i18next";

export interface MaterializeOptionProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  /** Extra line under the explanation (e.g. "applies to .msl files only"). */
  hint?: string;
  disabled?: boolean;
}

/**
 * The opt-in "write a filtered copy" checkbox for `.msl` input, with the
 * trade-off spelled out: smaller file, but the copy loses the original's
 * integrity hash / byte identity. The default (unchecked) leaves the original
 * untouched and filters at analysis time.
 */
export function MaterializeOption({ checked, onChange, hint, disabled = false }: MaterializeOptionProps) {
  const { t } = useTranslation("import");
  const explanationId = useId();
  return (
    <label className="flex items-start gap-2 text-sm p-2 rounded border border-[var(--md-border)] cursor-pointer">
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        aria-describedby={explanationId}
        data-testid="region-materialize"
        className="mt-0.5 accent-[var(--md-accent-blue)]"
      />
      <span>
        <span className="font-medium">{t("materialize.label")}</span>
        <span id={explanationId} className="block text-xs md-text-secondary">
          {t("materialize.explanation")}
          {hint ? ` ${hint}` : ""}
        </span>
      </span>
    </label>
  );
}
