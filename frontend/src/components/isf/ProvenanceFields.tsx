import { useTranslation } from "react-i18next";

import { ISF_TIERS } from "@/api/isf";
import type { ProvenanceDraft } from "./provenance-draft";
import { inputClass } from "./ui";

export function ProvenanceFields({ value, onChange }: {
  value: ProvenanceDraft;
  onChange: (next: ProvenanceDraft) => void;
}) {
  const { t } = useTranslation("isf");
  return (
    <fieldset className="space-y-1 border-t border-[var(--md-border)] pt-1" data-testid="prov-fields">
      <legend className="md-text-secondary">{t("prov.legend")}</legend>
      <div className="flex gap-1">
        <input type="text" value={value.source} className={inputClass} data-testid="prov-source"
          aria-label={t("prov.source")} placeholder={t("prov.source")}
          onChange={(e) => onChange({ ...value, source: e.target.value })} />
        <select value={value.tier} className={inputClass} data-testid="prov-tier" aria-label={t("prov.tier")}
          onChange={(e) => onChange({ ...value, tier: e.target.value })}>
          {ISF_TIERS.map((tier) => <option key={tier} value={tier}>{t(`tier.${tier}`)}</option>)}
        </select>
      </div>
      <textarea value={value.evidence} rows={2} className={inputClass} data-testid="prov-evidence"
        aria-label={t("prov.evidence")} placeholder={t("prov.evidencePlaceholder")}
        onChange={(e) => onChange({ ...value, evidence: e.target.value })} />
      <p className="md-text-muted">{t("prov.author")}</p>
    </fieldset>
  );
}
