import { useTranslation } from "react-i18next";

import type { IsfProvenance } from "@/api/isf";

const TIER_COLOUR: Record<string, string> = {
  exact: "var(--md-accent-green)",
  ordinal: "var(--md-accent-cyan)",
  population: "var(--md-accent-blue)",
  code: "var(--md-accent-purple)",
  crc_certified: "var(--md-accent-green)",
  upstream_constant: "var(--md-accent-cyan)",
  bound: "var(--md-accent-yellow)",
  imported: "var(--md-accent-blue)",
  probe: "var(--md-accent-orange)",
  manual: "var(--md-text-secondary)",
};

/** Tier word (never colour alone) + source / evidence / author on hover. */
export function ProvenanceBadge({ provenance }: { provenance: IsfProvenance | null | undefined }) {
  const { t } = useTranslation("isf");
  if (!provenance) {
    return <span data-testid="provenance-badge" data-tier="unknown" className="md-text-muted">{t("provenance.unknown")}</span>;
  }
  const colour = TIER_COLOUR[provenance.tier] ?? "var(--md-text-secondary)";
  const title = [
    t("provenance.source", { source: provenance.source }),
    t("provenance.author", { author: provenance.author }),
    ...provenance.evidence.map((e) => t("provenance.evidenceLine", { evidence: e })),
  ].join("\n");
  return (
    <span data-testid="provenance-badge" data-tier={provenance.tier} title={title}
      className="inline-flex items-center px-1 rounded border text-[10px] font-medium"
      style={{ color: colour, borderColor: colour }}>
      {t(`tier.${provenance.tier}`, { defaultValue: provenance.tier })}
    </span>
  );
}

/** The expanded form: source, author and every evidence string as text. */
export function ProvenanceDetail({ provenance }: { provenance: IsfProvenance }) {
  const { t } = useTranslation("isf");
  return (
    <dl data-testid="provenance-detail" className="text-[11px] md-text-secondary space-y-0.5">
      <div>{t("provenance.source", { source: provenance.source })}</div>
      <div>{t("provenance.author", { author: provenance.author })}</div>
      {provenance.evidence.map((e) => <div key={e}>{t("provenance.evidenceLine", { evidence: e })}</div>)}
    </dl>
  );
}
