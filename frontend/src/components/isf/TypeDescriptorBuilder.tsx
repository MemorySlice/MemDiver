import { useTranslation } from "react-i18next";

import type { TypeDescriptor } from "@/api/isf";
import { defaultDescriptor } from "./type-descriptor";
import { inputClass } from "./ui";

const KINDS = ["base", "pointer", "array", "struct"] as const;
const MAX_DEPTH = 4;

/** Base / pointer / array / struct descriptor editor; pointers and arrays nest. */
export function TypeDescriptorBuilder({ value, onChange, testId, depth = 0 }: {
  value: TypeDescriptor;
  onChange: (next: TypeDescriptor) => void;
  testId: string;
  depth?: number;
}) {
  const { t } = useTranslation("isf");
  const nested = value.kind === "pointer" || value.kind === "array";
  return (
    <div className="space-y-1 pl-2 border-l border-[var(--md-border)]" data-testid={testId}>
      <select value={value.kind} className={inputClass} data-testid={`${testId}-kind`}
        aria-label={t("type.kind")} onChange={(e) => onChange(defaultDescriptor(e.target.value))}>
        {KINDS.filter((k) => depth < MAX_DEPTH || (k !== "pointer" && k !== "array"))
          .map((k) => <option key={k} value={k}>{t(`type.kinds.${k}`)}</option>)}
      </select>
      {!nested && (
        <input type="text" value={value.name ?? ""} className={inputClass} data-testid={`${testId}-name`}
          aria-label={t("type.name")} placeholder={t("type.name")}
          onChange={(e) => onChange({ kind: value.kind, name: e.target.value })} />
      )}
      {value.kind === "array" && (
        <input type="number" min={0} value={value.count ?? ""} className={inputClass} data-testid={`${testId}-count`}
          aria-label={t("type.count")} placeholder={t("type.count")}
          onChange={(e) => onChange({ ...value, count: e.target.value === "" ? undefined : Number(e.target.value) })} />
      )}
      {nested && value.subtype && (
        <TypeDescriptorBuilder value={value.subtype} testId={`${testId}-sub`} depth={depth + 1}
          onChange={(subtype) => onChange({ ...value, subtype })} />
      )}
    </div>
  );
}
