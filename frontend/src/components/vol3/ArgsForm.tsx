import { useTranslation } from "react-i18next";

import type { Vol3Requirement } from "@/api/vol3";
import type { ArgDraft, ArgErrors } from "./vol3-args";

const fieldClass =
  "w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";

function Field({ req, value, onChange }: {
  req: Vol3Requirement;
  value: string | boolean | undefined;
  onChange: (value: string | boolean) => void;
}) {
  const { t } = useTranslation("vol3");
  const id = `vol3-arg-${req.name}`;
  if (req.type === "boolean") {
    return <input id={id} type="checkbox" checked={value === true}
      onChange={(e) => onChange(e.target.checked)} />;
  }
  if (req.choices?.length) {
    return (
      <select id={id} value={String(value ?? "")} onChange={(e) => onChange(e.target.value)}
        className={fieldClass}>
        {req.optional && <option value="">{t("args.choiceNone")}</option>}
        {req.choices.map((choice) => <option key={choice} value={choice}>{choice}</option>)}
      </select>
    );
  }
  const placeholder = req.type === "array" ? t("args.listPlaceholder")
    : req.type === "integer" ? t("args.integerPlaceholder") : "";
  return <input id={id} type="text" value={String(value ?? "")} placeholder={placeholder}
    onChange={(e) => onChange(e.target.value)} className={`${fieldClass} font-mono`} />;
}

/** One labelled input per plugin requirement (integer / string / boolean / list / choice). */
export function ArgsForm({
  requirements, draft, errors, onChange, pidAutoFill, selectedPid = null, selectedPidArg = null,
}: {
  requirements: readonly Vol3Requirement[];
  draft: ArgDraft;
  errors: ArgErrors;
  onChange: (name: string, value: string | boolean) => void;
  /** Name of the pid-list argument the backend fills from a process view, if any. */
  pidAutoFill: string | null;
  /** The pid selected in another panel (D14); shown next to the pid argument it prefilled. */
  selectedPid?: number | null;
  selectedPidArg?: string | null;
}) {
  const { t } = useTranslation("vol3");
  if (requirements.length === 0) {
    return <p className="text-xs md-text-muted" data-testid="args-none">{t("args.none")}</p>;
  }
  return (
    <div className="space-y-2" data-testid="args-form">
      {requirements.map((req) => (
        <div key={req.name} className="space-y-0.5" data-testid={`arg-${req.name}`}>
          <label htmlFor={`vol3-arg-${req.name}`} className="flex items-baseline gap-1 text-xs md-text-secondary">
            <span className="font-mono">{req.name}</span>
            <span className="md-text-muted">
              {req.optional ? t("args.optional") : t("args.required")} · {req.type}
            </span>
          </label>
          <Field req={req} value={draft[req.name]} onChange={(v) => onChange(req.name, v)} />
          {req.description && <p className="text-xs md-text-muted">{req.description}</p>}
          {pidAutoFill === req.name && (
            <p className="text-xs md-text-muted" data-testid="pid-autofill-hint">{t("args.pidAuto")}</p>
          )}
          {selectedPid !== null && selectedPidArg === req.name && draft[req.name] === String(selectedPid) && (
            <p className="text-xs md-text-muted" data-testid="pid-selected-hint">
              {t("args.pidSelected", { pid: selectedPid })}</p>
          )}
          {errors[req.name] && (
            <p role="alert" className="text-xs" style={{ color: "var(--md-accent-red)" }}>
              {t(`args.error.${errors[req.name]}`)}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
