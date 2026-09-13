import { memo } from "react";
import { useShallow } from "zustand/react/shallow";
import { useTranslation } from "react-i18next";
import { useConsensusStore } from "@/stores/consensus-store";
import { EmptyState } from "@/components/common/EmptyState";
import { ConsensusIcon } from "@/components/common/Icons";
import { VARIANCE_META, type VarianceCategory } from "@/utils/variance-classes";

interface ConsensusChartProps {
  onNavigate?: (tab: "analysis") => void;
}

/**
 * The histogram bands.
 *
 * Both the colour AND the label now come from the shared `VARIANCE_META` map.
 * The palette was already shared -- this was the fifth private copy of it, and
 * the copies disagreed. The LABELS had the same problem one step later: this
 * file's `charts` namespace said "Key Candidate" and `candidates.json` said
 * "Key candidate", so the same backend class was two different words two panels
 * apart. Only the longer, chart-specific `desc` stays local, which is exactly
 * the split `VarianceMeta` already draws between `labelKey` and
 * `descriptionKey`.
 */
const CLASS_INFO: { key: VarianceCategory; color: string; descKey: string }[] = [
  { key: "invariant", color: VARIANCE_META.invariant.colorVar, descKey: "consensus.class.invariant.desc" },
  { key: "structural", color: VARIANCE_META.structural.colorVar, descKey: "consensus.class.structural.desc" },
  { key: "pointer", color: VARIANCE_META.pointer.colorVar, descKey: "consensus.class.pointer.desc" },
  { key: "key_candidate", color: VARIANCE_META.key_candidate.colorVar, descKey: "consensus.class.keyCandidate.desc" },
];

export const ConsensusChart = memo(function ConsensusChart({ onNavigate }: ConsensusChartProps = {}) {
  // Two namespaces: the band LABELS are the shared variance vocabulary, which
  // lives in `hex`; everything else on this chart is `charts`.
  const { t } = useTranslation(["charts", "hex"]);
  const { available, size, numDumps, counts } = useConsensusStore(
    useShallow((s) => ({
      available: s.available,
      size: s.size,
      numDumps: s.numDumps,
      counts: s.counts,
    })),
  );

  if (!available || !counts || size === 0) {
    return (
      <EmptyState
        icon={<ConsensusIcon />}
        title={t("consensus.empty.title")}
        description={t("consensus.empty.description")}
        primaryCta={onNavigate ? { label: t("consensus.empty.runAnalysis"), onClick: () => onNavigate("analysis") } : undefined}
        secondary={{ label: t("consensus.empty.aboutLink"), doc: "visualizations/consensus.md" }}
        data-testid="consensus-empty"
      />
    );
  }

  return (
    <div className="p-3 text-xs space-y-3" role="status" aria-live="polite">
      <h3 className="text-sm font-semibold md-text-accent">{t("consensus.title")}</h3>
      <div className="flex gap-4 md-text-muted">
        <span>{t("consensus.totalBytes", { value: size.toLocaleString() })}</span>
        <span>{t("consensus.dumpsAnalyzed", { value: numDumps })}</span>
      </div>
      <div className="space-y-2">
        {CLASS_INFO.map(({ key, color, descKey }) => {
          const count = counts[key] ?? 0;
          const pct = size > 0 ? (count / size) * 100 : 0;
          return (
            <div key={key} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-sm shrink-0"
                style={{ background: color }}
                title={t(descKey)}
              />
              <span className="min-w-[90px] font-medium">
                {t(`hex:${VARIANCE_META[key].labelKey}`)}
              </span>
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
