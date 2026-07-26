import { memo } from "react";
import { useTranslation } from "react-i18next";
import { useConsensusStore } from "@/stores/consensus-store";
import { EmptyState } from "@/components/common/EmptyState";
import { ConsensusIcon } from "@/components/common/Icons";

interface ConsensusChartProps {
  onNavigate?: (tab: "analysis") => void;
}

const CLASS_INFO: { key: string; labelKey: string; color: string; descKey: string }[] = [
  { key: "invariant", labelKey: "consensus.class.invariant.label", color: "var(--md-accent-green)", descKey: "consensus.class.invariant.desc" },
  { key: "structural", labelKey: "consensus.class.structural.label", color: "var(--md-accent-blue)", descKey: "consensus.class.structural.desc" },
  { key: "pointer", labelKey: "consensus.class.pointer.label", color: "var(--md-accent-cyan)", descKey: "consensus.class.pointer.desc" },
  { key: "key_candidate", labelKey: "consensus.class.keyCandidate.label", color: "var(--md-accent-red)", descKey: "consensus.class.keyCandidate.desc" },
];

export const ConsensusChart = memo(function ConsensusChart({ onNavigate }: ConsensusChartProps = {}) {
  const { t } = useTranslation("charts");
  const { available, size, numDumps, counts } = useConsensusStore();

  if (!available || !counts || size === 0) {
    return (
      <EmptyState
        icon={<ConsensusIcon />}
        title={t("consensus.empty.title")}
        description={t("consensus.empty.description")}
        primaryCta={onNavigate ? { label: t("consensus.empty.runAnalysis"), onClick: () => onNavigate("analysis") } : undefined}
        secondary={{ label: t("consensus.empty.aboutLink"), href: "/docs/visualizations/consensus.md" }}
        data-testid="consensus-empty"
      />
    );
  }

  return (
    <div className="p-3 text-xs space-y-3">
      <h3 className="text-sm font-semibold md-text-accent">{t("consensus.title")}</h3>
      <div className="flex gap-4 md-text-muted">
        <span>{t("consensus.totalBytes", { value: size.toLocaleString() })}</span>
        <span>{t("consensus.dumpsAnalyzed", { value: numDumps })}</span>
      </div>
      <div className="space-y-2">
        {CLASS_INFO.map(({ key, labelKey, color, descKey }) => {
          const count = counts[key] ?? 0;
          const pct = size > 0 ? (count / size) * 100 : 0;
          return (
            <div key={key} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-sm shrink-0"
                style={{ background: color }}
                title={t(descKey)}
              />
              <span className="min-w-[90px] font-medium">{t(labelKey)}</span>
              <div className="flex-1 h-4 rounded bg-[var(--md-bg-tertiary)] overflow-hidden">
                <div
                  className="h-full rounded transition-all"
                  style={{ background: color, width: `${pct}%` }}
                />
              </div>
              <span className="min-w-[100px] text-right md-text-muted">
                {count.toLocaleString()} ({pct.toFixed(1)}%)
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
});
